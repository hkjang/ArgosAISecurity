use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    plan: ServiceRecoveryPlan,
}
impl Fixture {
    fn new(sql: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "argos-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let source = Connection::open(root.join("original.sqlite3")).unwrap();
        source.execute_batch(sql).unwrap();
        let backup_path = root.join("native.sqlite3");
        let mut destination = Connection::open(&backup_path).unwrap();
        {
            let backup = Backup::new(&source, &mut destination).unwrap();
            backup
                .run_to_completion(64, Duration::from_millis(1), None)
                .unwrap();
        }
        drop(destination);
        drop(source);
        Self {
            root,
            plan: ServiceRecoveryPlan {
                service_id: "orders".into(),
                engine: DatabaseEngine::Sqlite,
                backup_path,
                timeout_secs: 10,
                max_backup_bytes: 1024 * 1024,
                max_workspace_bytes: 4 * 1024 * 1024,
                declared_recovery_point_ms: Some(1000),
                incident_at_ms: Some(2000),
                expected_user_version: Some(7),
                tables: vec![TableExpectation {
                    check_id: "orders-readable".into(),
                    table: "orders".into(),
                    required_columns: vec!["id".into(), "secret".into()],
                    min_rows: 2,
                }],
                postgresql: None,
            },
        }
    }
    fn ordinary() -> Self {
        Self::new("PRAGMA user_version=7; CREATE TABLE orders(id INTEGER PRIMARY KEY,secret TEXT); INSERT INTO orders VALUES(1,'PRIVATE-ROW-SECRET'),(2,'another-secret');")
    }
    fn run(&self, name: &str) -> ServiceRecoveryReport {
        run(&self.plan, &self.root.join(name)).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn native_restore_proves_structure_rows_and_rollback_without_claiming_rpo() {
    let fixture = Fixture::ordinary();
    let before = fs::read(&fixture.plan.backup_path).unwrap();
    let report = fixture.run("drill");
    assert_eq!(report.status, "passed");
    assert!(report
        .checks
        .iter()
        .any(|c| c.check_id == "argos-write-read-rollback" && c.passed));
    assert_eq!(report.rpo_ms, None);
    assert_eq!(report.service_rto_ms, None);
    assert_eq!(
        report.recovery_point_basis,
        "operator_declared_not_database_verified"
    );
    assert_eq!(fs::read(&fixture.plan.backup_path).unwrap(), before);
    let restored = Connection::open(fixture.root.join("drill/restored.sqlite3")).unwrap();
    assert_eq!(
        restored
            .query_row("SELECT count(*) FROM orders", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        restored
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='__argos_service_recovery_probe'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    let saved = fs::read_to_string(fixture.root.join("drill").join(REPORT_NAME)).unwrap();
    assert!(!saved.contains("PRIVATE-ROW-SECRET"));
    assert!(!saved.contains(&fixture.plan.backup_path.to_string_lossy().to_string()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(fixture.root.join("drill"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(fixture.root.join("drill/restored.sqlite3"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
#[test]
fn independent_expectations_fail_with_sanitized_codes() {
    let mut fixture = Fixture::ordinary();
    fixture.plan.tables[0].min_rows = 3;
    assert_eq!(
        fixture.run("rows").failure_code.as_deref(),
        Some("sqlite_row_expectation_failed")
    );
    fixture.plan.tables[0].min_rows = 2;
    fixture.plan.tables[0]
        .required_columns
        .push("missing".into());
    assert_eq!(
        fixture.run("columns").failure_code.as_deref(),
        Some("sqlite_expected_column_missing")
    );
    fixture.plan.tables[0].required_columns.clear();
    fixture.plan.tables[0].table = "missing".into();
    assert_eq!(
        fixture.run("table").failure_code.as_deref(),
        Some("sqlite_expected_table_missing")
    );
    fixture.plan.tables[0].table = "orders".into();
    fixture.plan.expected_user_version = Some(8);
    assert_eq!(
        fixture.run("version").failure_code.as_deref(),
        Some("sqlite_schema_version_mismatch")
    );
}
#[test]
fn missing_relational_integrity_fails_even_when_file_can_be_copied() {
    let mut fixture=Fixture::new("PRAGMA foreign_keys=OFF; CREATE TABLE parents(id INTEGER PRIMARY KEY); CREATE TABLE orders(id INTEGER PRIMARY KEY,secret TEXT,parent_id INTEGER REFERENCES parents(id)); INSERT INTO orders VALUES(1,'sensitive',99);");
    fixture.plan.expected_user_version = None;
    fixture.plan.tables[0].min_rows = 1;
    let report = fixture.run("drill");
    assert_eq!(
        report.failure_code.as_deref(),
        Some("sqlite_foreign_key_violation")
    );
    assert!(report
        .checks
        .iter()
        .any(|c| c.check_id == "argos-integrity" && c.passed));
}
#[test]
fn rejects_virtual_tables_and_views() {
    let mut fixture = Fixture::new(
        "CREATE VIRTUAL TABLE orders USING fts5(secret); INSERT INTO orders VALUES('sensitive');",
    );
    fixture.plan.expected_user_version = None;
    assert_eq!(
        fixture.run("virtual").failure_code.as_deref(),
        Some("sqlite_virtual_tables_not_supported")
    );
    let mut fixture = Fixture::new(
        "CREATE TABLE original(id,secret); CREATE VIEW orders AS SELECT * FROM original;",
    );
    fixture.plan.expected_user_version = None;
    assert_eq!(
        fixture.run("view").failure_code.as_deref(),
        Some("sqlite_expected_table_missing")
    );
}
#[test]
fn refuses_reuse_injection_future_points_and_unbounded_plans() {
    let mut fixture = Fixture::ordinary();
    fixture.run("existing");
    assert_eq!(
        run(&fixture.plan, &fixture.root.join("existing"))
            .unwrap_err()
            .code,
        "workspace_create_failed_or_already_exists"
    );
    fixture.plan.tables[0].table = "orders\"; DROP TABLE orders;--".into();
    assert_eq!(
        validate_plan(&fixture.plan).unwrap_err().code,
        "unsupported_table_identifier"
    );
    fixture.plan.tables[0].table = "orders".into();
    fixture.plan.timeout_secs = 301;
    assert_eq!(
        validate_plan(&fixture.plan).unwrap_err().code,
        "timeout_out_of_range"
    );
    fixture.plan.timeout_secs = 1;
    fixture.plan.declared_recovery_point_ms = Some(3000);
    assert_eq!(
        validate_plan(&fixture.plan).unwrap_err().code,
        "recovery_point_after_incident"
    );
    fixture.plan.declared_recovery_point_ms = Some(u64::MAX);
    assert_eq!(
        validate_plan(&fixture.plan).unwrap_err().code,
        "recovery_timestamp_out_of_range"
    );
}
#[test]
fn rejects_live_sidecars_wrong_artifact_and_oversize() {
    let mut fixture = Fixture::ordinary();
    fs::write(
        fixture
            .plan
            .backup_path
            .with_file_name("native.sqlite3-wal"),
        b"live",
    )
    .unwrap();
    assert_eq!(
        fixture.run("live").failure_code.as_deref(),
        Some("offline_native_backup_required")
    );
    fs::remove_file(
        fixture
            .plan
            .backup_path
            .with_file_name("native.sqlite3-wal"),
    )
    .unwrap();
    fixture.plan.max_backup_bytes = 512;
    assert_eq!(
        fixture.run("large").failure_code.as_deref(),
        Some("backup_size_limit")
    );
    fixture.plan.max_backup_bytes = 1024 * 1024;
    fs::write(
        &fixture.plan.backup_path,
        b"CREATE TABLE orders(id); SECRET-SQL",
    )
    .unwrap();
    let report = fixture.run("sql");
    assert_eq!(
        report.failure_code.as_deref(),
        Some("native_backup_header_required")
    );
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("SECRET-SQL"));
}
#[cfg(unix)]
#[test]
fn refuses_symlink_and_fifo_without_blocking() {
    let mut fixture = Fixture::ordinary();
    let symlink = fixture.root.join("link.sqlite3");
    std::os::unix::fs::symlink(&fixture.plan.backup_path, &symlink).unwrap();
    fixture.plan.backup_path = symlink;
    assert_eq!(
        fixture.run("link").failure_code.as_deref(),
        Some("backup_must_be_regular_file")
    );
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let fifo = fixture.root.join("fifo.sqlite3");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        fixture.plan.backup_path = fifo;
        assert_eq!(
            fixture.run("fifo").failure_code.as_deref(),
            Some("backup_must_be_regular_file")
        );
    }
}
#[test]
fn timeout_interrupts_sqlite_operation() {
    let connection = Connection::open_in_memory().unwrap();
    let deadline = Instant::now() + Duration::from_millis(20);
    configure(&connection, deadline).unwrap();
    let result=connection.query_row("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT sum(x) FROM n",[],|row|row.get::<_,i64>(0));
    assert!(result.is_err());
    assert_eq!(sqlite_error(deadline, "unexpected").code, "timeout");
}

#[test]
fn aggregate_workspace_budget_detects_many_small_files_and_symlinks() {
    let fixture = Fixture::ordinary();
    let work = fixture.root.join("budget");
    create_workspace(&work).unwrap();
    fs::write(work.join("first"), [0; 600]).unwrap();
    fs::write(work.join("second"), [0; 600]).unwrap();
    assert_eq!(
        workspace_budget(&work, 1000, Instant::now() + Duration::from_secs(1))
            .unwrap_err()
            .code,
        "workspace_size_limit"
    );
    #[cfg(unix)]
    {
        fs::remove_file(work.join("second")).unwrap();
        std::os::unix::fs::symlink("/tmp", work.join("escape")).unwrap();
        assert_eq!(
            workspace_budget(&work, 1000, Instant::now() + Duration::from_secs(1))
                .unwrap_err()
                .code,
            "workspace_symlink_not_allowed"
        );
    }
}
