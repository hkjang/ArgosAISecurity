use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    plan: ServiceRecoveryPlan,
    report: ServiceRecoveryReport,
    report_path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "argos-report-verify-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let backup = root.join("backup.sqlite3");
        let connection = Connection::open(&backup).unwrap();
        connection.execute_batch("PRAGMA user_version=7;CREATE TABLE orders(id INTEGER PRIMARY KEY,secret TEXT);INSERT INTO orders VALUES(1,'PRIVATE-VERIFY-FIXTURE'),(2,'other');").unwrap();
        drop(connection);
        let plan = ServiceRecoveryPlan {
            service_id: "orders".into(),
            engine: DatabaseEngine::Sqlite,
            backup_path: backup,
            timeout_secs: 10,
            max_backup_bytes: 1024 * 1024,
            max_workspace_bytes: 4 * 1024 * 1024,
            declared_recovery_point_ms: None,
            incident_at_ms: None,
            expected_user_version: Some(7),
            tables: vec![TableExpectation {
                check_id: "orders-check".into(),
                table: "orders".into(),
                required_columns: vec!["id".into(), "secret".into()],
                min_rows: 2,
            }],
            postgresql: None,
        };
        let report = super::super::run(&plan, &root.join("drill")).unwrap();
        assert_eq!(report.status, "passed");
        let report_path = root.join("report.json");
        let fixture = Self {
            root,
            plan,
            report,
            report_path,
        };
        fixture.save(&fixture.report);
        fixture
    }
    fn save(&self, report: &ServiceRecoveryReport) {
        fs::write(&self.report_path, serde_json::to_vec(report).unwrap()).unwrap();
    }
    fn verify(&self) -> Result<ServiceReportVerification> {
        verify_report(&self.plan, &self.report_path, 3600)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn verifies_real_drill_and_keeps_both_inputs_unchanged() {
    let fixture = Fixture::new();
    let report_before = fs::read(&fixture.report_path).unwrap();
    let backup_before = fs::read(&fixture.plan.backup_path).unwrap();
    let result = fixture.verify().unwrap();
    assert_eq!(result.status, "consistent");
    assert!(!result.report_authenticated);
    assert_eq!(
        result.report_sha256,
        hex::encode(Sha256::digest(&report_before))
    );
    assert_eq!(
        result.backup_sha256,
        hex::encode(Sha256::digest(&backup_before))
    );
    assert_eq!(
        result.checked_ids,
        fixture.report.required_check_ids.clone().unwrap()
    );
    assert_eq!(fs::read(&fixture.report_path).unwrap(), report_before);
    assert_eq!(fs::read(&fixture.plan.backup_path).unwrap(), backup_before);
    assert!(!serde_json::to_string(&result)
        .unwrap()
        .contains("PRIVATE-VERIFY-FIXTURE"));
}

#[test]
fn identical_backup_relocation_and_semantic_order_do_not_invalidate() {
    let mut fixture = Fixture::new();
    let copied = fixture.root.join("relocated.sqlite3");
    fs::copy(&fixture.plan.backup_path, &copied).unwrap();
    fixture.plan.backup_path = copied;
    fixture.plan.tables[0].required_columns.reverse();
    fixture.plan.tables[0].required_columns.push("id".into());
    fixture.verify().unwrap();
    let mut plan = fixture.plan.clone();
    let mut second = plan.tables[0].clone();
    second.check_id = "second-check".into();
    plan.tables.push(second);
    let first = plan_binding(&plan).unwrap();
    plan.tables.reverse();
    let second = plan_binding(&plan).unwrap();
    assert_eq!(first.plan_sha256, second.plan_sha256);
    assert_eq!(first.expectations_sha256, second.expectations_sha256);
    let original = serde_json::json!({"b":{"z":1,"a":2},"a":true});
    let equivalent = serde_json::json!({"a":true,"b":{"a":2,"z":1}});
    assert_eq!(
        digest(b"canonical", &original).unwrap(),
        digest(b"canonical", &equivalent).unwrap()
    );
}

#[test]
fn changed_plan_limits_expectations_and_declared_context_are_rejected() {
    let fixture = Fixture::new();
    for mutator in [
        (|p: &mut ServiceRecoveryPlan| p.tables[0].min_rows = 1) as fn(&mut ServiceRecoveryPlan),
        |p| p.tables[0].required_columns.pop().map(|_| ()).unwrap(),
        |p| p.expected_user_version = Some(8),
        |p| p.timeout_secs += 1,
        |p| p.max_backup_bytes += 1,
        |p| p.max_workspace_bytes += 1,
        |p| p.service_id = "another-service".into(),
        |p| p.declared_recovery_point_ms = Some(1000),
    ] {
        let mut plan = fixture.plan.clone();
        mutator(&mut plan);
        assert_eq!(
            verify_report(&plan, &fixture.report_path, 3600)
                .unwrap_err()
                .code,
            "report_plan_mismatch"
        );
    }
    let mut report = fixture.report.clone();
    report.expectations_sha256 = Some("0".repeat(64));
    fixture.save(&report);
    assert_eq!(
        fixture.verify().unwrap_err().code,
        "report_expectations_mismatch"
    );
}

#[test]
fn rejects_changed_backup_content_and_size() {
    let fixture = Fixture::new();
    let original = fs::read(&fixture.plan.backup_path).unwrap();
    let mut changed = original.clone();
    *changed.last_mut().unwrap() ^= 1;
    fs::write(&fixture.plan.backup_path, &changed).unwrap();
    assert_eq!(fixture.verify().unwrap_err().code, "report_backup_mismatch");
    fs::write(&fixture.plan.backup_path, &original).unwrap();
    let mut report = fixture.report.clone();
    report.backup_bytes = report.backup_bytes.map(|value| value + 1);
    fixture.save(&report);
    assert_eq!(fixture.verify().unwrap_err().code, "report_backup_mismatch");
}

#[test]
fn rejects_legacy_failed_future_stale_and_invalid_age_reports() {
    let fixture = Fixture::new();
    let mut legacy = serde_json::to_value(&fixture.report).unwrap();
    legacy["format"] = serde_json::json!("argos-service-recovery-v1");
    for field in [
        "plan_hash_version",
        "plan_sha256",
        "expectations_sha256",
        "required_check_ids",
    ] {
        legacy.as_object_mut().unwrap().remove(field);
    }
    fs::write(&fixture.report_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
    assert_eq!(
        fixture.verify().unwrap_err().code,
        "legacy_or_unbound_report"
    );
    let mut report = fixture.report.clone();
    report.status = "failed".into();
    fixture.save(&report);
    assert_eq!(fixture.verify().unwrap_err().code, "report_not_successful");
    report = fixture.report.clone();
    report.failure_code = Some("timeout".into());
    fixture.save(&report);
    assert_eq!(fixture.verify().unwrap_err().code, "report_not_successful");
    report = fixture.report.clone();
    report.started_at_ms = 1000;
    report.finished_at_ms = 2000;
    assert!(verify_metadata(&fixture.plan, &report, 1, 3000).is_ok());
    assert_eq!(
        verify_metadata(&fixture.plan, &report, 1, 3001)
            .err()
            .unwrap()
            .code,
        "report_too_old"
    );
    assert_eq!(
        verify_metadata(&fixture.plan, &report, 1, 1999)
            .err()
            .unwrap()
            .code,
        "invalid_or_future_report_time"
    );
    report.started_at_ms = 2001;
    assert_eq!(
        verify_metadata(&fixture.plan, &report, 1, 3000)
            .err()
            .unwrap()
            .code,
        "invalid_or_future_report_time"
    );
    assert_eq!(
        verify_report(&fixture.plan, &fixture.report_path, 0)
            .unwrap_err()
            .code,
        "invalid_report_max_age"
    );
    assert_eq!(
        verify_report(&fixture.plan, &fixture.report_path, u64::MAX)
            .unwrap_err()
            .code,
        "invalid_report_max_age"
    );
}

#[test]
fn requires_exact_unique_successful_checks_and_observed_counts() {
    let fixture = Fixture::new();
    let verify_modified = |report: &ServiceRecoveryReport, expected: &str| {
        fixture.save(report);
        assert_eq!(fixture.verify().unwrap_err().code, expected);
    };
    let mut report = fixture.report.clone();
    report.checks.push(report.checks[0].clone());
    verify_modified(&report, "duplicate_report_check");
    report = fixture.report.clone();
    report.checks.pop();
    verify_modified(&report, "report_checks_mismatch");
    report = fixture.report.clone();
    report.checks[0].check_id = "unexpected".into();
    verify_modified(&report, "report_checks_mismatch");
    report = fixture.report.clone();
    report.checks[0].passed = false;
    verify_modified(&report, "report_check_not_successful");
    report = fixture.report.clone();
    report.checks[0].code = "not-ok".into();
    verify_modified(&report, "report_check_not_successful");
    report = fixture.report.clone();
    report.required_check_ids.as_mut().unwrap().pop();
    verify_modified(&report, "required_checks_mismatch");
    report = fixture.report.clone();
    report
        .checks
        .iter_mut()
        .find(|c| c.check_id == "orders-check")
        .unwrap()
        .observed_rows = None;
    verify_modified(&report, "report_row_count_missing");
    report = fixture.report.clone();
    report
        .checks
        .iter_mut()
        .find(|c| c.check_id == "orders-check")
        .unwrap()
        .observed_rows = Some(1);
    verify_modified(&report, "report_row_expectation_failed");
    report = fixture.report.clone();
    report.checks[0].observed_rows = Some(99);
    verify_modified(&report, "report_builtin_check_invalid");
    report = fixture.report.clone();
    report.rpo_ms = Some(0);
    verify_modified(&report, "unsupported_report_recovery_claim");
    report = fixture.report.clone();
    report.service_id = "forged-id".into();
    verify_modified(&report, "report_metadata_mismatch");
}

#[test]
fn rejects_postgresql_invalid_constraint_observation() {
    let fixture = Fixture::new();
    let mut plan = fixture.plan.clone();
    plan.engine = DatabaseEngine::Postgresql;
    plan.expected_user_version = None;
    plan.postgresql = Some(PostgresqlSettings {
        installation_root: "/".into(),
        major_version: 18,
    });
    let mut report = new_report(&plan);
    report.status = "passed".into();
    report.finished_at_ms = report.started_at_ms;
    report.checks = vec![
        ServiceCheckResult {
            check_id: "argos-constraints".into(),
            passed: true,
            code: "ok".into(),
            observed_rows: Some(0),
        },
        ServiceCheckResult {
            check_id: "argos-write-read-rollback".into(),
            passed: true,
            code: "ok".into(),
            observed_rows: None,
        },
        ServiceCheckResult {
            check_id: "orders-check".into(),
            passed: true,
            code: "ok".into(),
            observed_rows: Some(2),
        },
    ];
    assert!(verify_metadata(&plan, &report, 3600, now_ms()).is_ok());
    report.checks[0].observed_rows = Some(1);
    assert_eq!(
        verify_metadata(&plan, &report, 3600, now_ms())
            .err()
            .unwrap()
            .code,
        "report_constraint_count_invalid"
    );
}

#[test]
fn bounds_report_input_and_refuses_symlinks_fifos_and_live_sqlite() {
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    let fixture = Fixture::new();
    fs::write(&fixture.report_path, vec![b' '; MAX_REPORT_BYTES + 1]).unwrap();
    assert_eq!(
        fixture.verify().unwrap_err().code,
        "verification_input_size_limit"
    );
    fixture.save(&fixture.report);
    let link = fixture.root.join("report-link");
    symlink(&fixture.report_path, &link).unwrap();
    assert_eq!(
        verify_report(&fixture.plan, &link, 3600).unwrap_err().code,
        "verification_regular_file_required"
    );
    let fifo = fixture.root.join("fifo");
    let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert_eq!(
        verify_report(&fixture.plan, &fifo, 3600).unwrap_err().code,
        "verification_regular_file_required"
    );
    let mut plan = fixture.plan.clone();
    plan.backup_path = fixture.root.join("backup-link");
    symlink(&fixture.plan.backup_path, &plan.backup_path).unwrap();
    assert_eq!(
        verify_report(&plan, &fixture.report_path, 3600)
            .unwrap_err()
            .code,
        "verification_regular_file_required"
    );
    fs::write(
        fixture
            .plan
            .backup_path
            .with_file_name("backup.sqlite3-wal"),
        b"live",
    )
    .unwrap();
    assert_eq!(
        fixture.verify().unwrap_err().code,
        "offline_native_backup_required"
    );
}

#[test]
fn rejects_in_place_write_or_path_swap_during_full_file_read() {
    use std::io::{Seek, SeekFrom};
    let fixture = Fixture::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut changed = false;
    let different_byte = fs::read(&fixture.plan.backup_path)
        .unwrap()
        .last()
        .copied()
        .unwrap()
        ^ 0xff;
    let result = read_stable_file(
        &fixture.plan.backup_path,
        fixture.plan.max_backup_bytes,
        deadline,
        |_| {
            if !changed {
                let mut file = OpenOptions::new()
                    .write(true)
                    .open(&fixture.plan.backup_path)
                    .unwrap();
                file.seek(SeekFrom::End(-1)).unwrap();
                file.write_all(&[different_byte]).unwrap();
                file.sync_all().unwrap();
                changed = true;
            }
            Ok(())
        },
    );
    assert_eq!(result.unwrap_err().code, "verification_file_changed");
    let replacement = fixture.root.join("replacement");
    fs::copy(&fixture.plan.backup_path, &replacement).unwrap();
    let mut changed = false;
    let result = read_stable_file(
        &fixture.plan.backup_path,
        fixture.plan.max_backup_bytes,
        deadline,
        |_| {
            if !changed {
                fs::rename(&replacement, &fixture.plan.backup_path).unwrap();
                changed = true;
            }
            Ok(())
        },
    );
    assert_eq!(result.unwrap_err().code, "verification_file_changed");
}
