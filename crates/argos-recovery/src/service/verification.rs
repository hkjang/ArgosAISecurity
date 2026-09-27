//! 무서명 복구 시험 보고서의 일관성·최신성 확인. 작성자 진위는 검증하지 않는다.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const PLAN_HASH_VERSION: u32 = 1;

pub(super) struct PlanBinding {
    pub plan_sha256: String,
    pub expectations_sha256: String,
    pub required_check_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceReportVerification {
    pub format: String,
    pub status: String,
    pub verified_at_ms: u64,
    pub report_finished_at_ms: u64,
    pub report_age_ms: u64,
    pub max_age_secs: u64,
    pub service_id: String,
    pub engine: DatabaseEngine,
    pub plan_sha256: String,
    pub expectations_sha256: String,
    pub backup_sha256: String,
    pub report_sha256: String,
    pub backup_bytes: u64,
    pub checked_ids: Vec<String>,
    pub report_authenticated: bool,
    pub limitations: Vec<String>,
}

fn canonical_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json(value)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonical_json).collect())
        }
        _ => value.clone(),
    }
}

fn digest(domain: &[u8], value: &serde_json::Value) -> Result<String> {
    let bytes = serde_json::to_vec(&canonical_json(value))
        .map_err(|_| failure("plan_hash_serialization_failed"))?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(bytes);
    Ok(hex::encode(hash.finalize()))
}

pub(super) fn plan_binding(plan: &ServiceRecoveryPlan) -> Result<PlanBinding> {
    // TOML 배치와 검사 실행 순서에 영향받지 않도록 의미가 같은 집합을 정규화한다.
    let mut normalized =
        serde_json::to_value(plan).map_err(|_| failure("plan_hash_serialization_failed"))?;
    let object = normalized
        .as_object_mut()
        .ok_or_else(|| failure("plan_hash_serialization_failed"))?;
    object.remove("backup_path"); // 백업 파일은 전체 내용 해시와 크기로 별도 결합한다.
    let mut tables = plan.tables.clone();
    tables.sort_by(|a, b| a.check_id.cmp(&b.check_id));
    for table in &mut tables {
        table.required_columns.sort();
        table.required_columns.dedup();
    }
    object.insert(
        "tables".into(),
        serde_json::to_value(&tables).map_err(|_| failure("plan_hash_serialization_failed"))?,
    );
    if let Some(settings) = &plan.postgresql {
        // '.'과 중복 구분자만 정리한다. 해시 계산 중 symlink나 설치 파일은 읽지 않는다.
        let normalized_root: PathBuf = settings.installation_root.components().collect();
        object
            .get_mut("postgresql")
            .and_then(|settings| settings.as_object_mut())
            .ok_or_else(|| failure("plan_hash_serialization_failed"))?
            .insert(
                "installation_root".into(),
                serde_json::to_value(normalized_root)
                    .map_err(|_| failure("plan_hash_serialization_failed"))?,
            );
    }
    let mut required_check_ids: Vec<String> = match plan.engine {
        DatabaseEngine::Sqlite => vec![
            "argos-integrity".into(),
            "argos-foreign-keys".into(),
            "argos-write-read-rollback".into(),
        ],
        DatabaseEngine::Postgresql => vec![
            "argos-constraints".into(),
            "argos-write-read-rollback".into(),
        ],
    };
    if plan.engine == DatabaseEngine::Sqlite && plan.expected_user_version.is_some() {
        required_check_ids.push("argos-user-version".into());
    }
    required_check_ids.extend(tables.iter().map(|table| table.check_id.clone()));
    required_check_ids.sort();
    let expectations = serde_json::json!({"engine":plan.engine,"expected_user_version":plan.expected_user_version,"tables":tables,"required_check_ids":required_check_ids});
    Ok(PlanBinding {
        plan_sha256: digest(b"argos-service-plan-v1", &normalized)?,
        expectations_sha256: digest(b"argos-service-expectations-v1", &expectations)?,
        required_check_ids,
    })
}

fn same_metadata(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    let same =
        a.is_file() && b.is_file() && a.len() == b.len() && a.modified().ok() == b.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same && a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        same
    }
}

fn read_stable_file(
    path: &Path,
    max_bytes: u64,
    deadline: Instant,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<(u64, String)> {
    // OpenOptions만으로 보장할 수 없는 플랫폼에서는 no-follow/non-blocking 지원을 거부한다.
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, max_bytes, deadline, &mut consume);
        return Err(failure("report_verification_requires_linux"));
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::{Seek, SeekFrom};
        use std::os::unix::fs::OpenOptionsExt;
        let before_path =
            fs::symlink_metadata(path).map_err(|_| failure("verification_file_unreadable"))?;
        if !before_path.is_file() || before_path.file_type().is_symlink() {
            return Err(failure("verification_regular_file_required"));
        }
        if before_path.len() > max_bytes {
            return Err(failure("verification_input_size_limit"));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| failure("verification_file_unreadable"))?;
        let before = file
            .metadata()
            .map_err(|_| failure("verification_metadata_failed"))?;
        if !same_metadata(&before_path, &before) {
            return Err(failure("verification_file_changed"));
        }
        let mut bytes = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        let mut first_hash = Sha256::new();
        loop {
            deadline_check(deadline)?;
            let remaining = max_bytes
                .saturating_sub(bytes)
                .saturating_add(1)
                .min(buffer.len() as u64) as usize;
            let read = file
                .read(&mut buffer[..remaining])
                .map_err(|_| failure("verification_read_failed"))?;
            deadline_check(deadline)?;
            if read == 0 {
                break;
            }
            bytes = bytes.saturating_add(read as u64);
            if bytes > max_bytes {
                return Err(failure("verification_input_size_limit"));
            }
            first_hash.update(&buffer[..read]);
            consume(&buffer[..read])?;
        }
        let after = file
            .metadata()
            .map_err(|_| failure("verification_metadata_failed"))?;
        let after_path =
            fs::symlink_metadata(path).map_err(|_| failure("verification_file_changed"))?;
        if bytes != before.len()
            || !same_metadata(&before, &after)
            || !same_metadata(&before, &after_path)
            || after_path.file_type().is_symlink()
        {
            return Err(failure("verification_file_changed"));
        }
        // 짧은 간격의 같은 크기 쓰기는 파일시스템 시각 해상도에 가려질 수 있다.
        // 같은 descriptor를 다시 전체 읽어 첫 소비 바이트와 내용 해시도 대조한다.
        file.seek(SeekFrom::Start(0))
            .map_err(|_| failure("verification_read_failed"))?;
        let mut second_hash = Sha256::new();
        let mut second_bytes = 0u64;
        loop {
            deadline_check(deadline)?;
            let remaining = max_bytes
                .saturating_sub(second_bytes)
                .saturating_add(1)
                .min(buffer.len() as u64) as usize;
            let read = file
                .read(&mut buffer[..remaining])
                .map_err(|_| failure("verification_read_failed"))?;
            deadline_check(deadline)?;
            if read == 0 {
                break;
            }
            second_bytes = second_bytes.saturating_add(read as u64);
            if second_bytes > max_bytes {
                return Err(failure("verification_input_size_limit"));
            }
            second_hash.update(&buffer[..read]);
        }
        let first_hash = first_hash.finalize();
        if second_bytes != bytes || first_hash != second_hash.finalize() {
            return Err(failure("verification_file_changed"));
        }
        let after = file
            .metadata()
            .map_err(|_| failure("verification_metadata_failed"))?;
        let after_path =
            fs::symlink_metadata(path).map_err(|_| failure("verification_file_changed"))?;
        if !same_metadata(&before, &after)
            || !same_metadata(&before, &after_path)
            || after_path.file_type().is_symlink()
        {
            return Err(failure("verification_file_changed"));
        }
        deadline_check(deadline)?;
        Ok((bytes, hex::encode(first_hash)))
    }
}

fn verify_checks(
    plan: &ServiceRecoveryPlan,
    report: &ServiceRecoveryReport,
    binding: &PlanBinding,
) -> Result<()> {
    if report.required_check_ids.as_ref() != Some(&binding.required_check_ids) {
        return Err(failure("required_checks_mismatch"));
    }
    let mut results = BTreeMap::new();
    for check in &report.checks {
        if results.insert(check.check_id.as_str(), check).is_some() {
            return Err(failure("duplicate_report_check"));
        }
        if !check.passed || check.code != "ok" {
            return Err(failure("report_check_not_successful"));
        }
    }
    let actual: BTreeSet<&str> = results.keys().copied().collect();
    let expected: BTreeSet<&str> = binding
        .required_check_ids
        .iter()
        .map(String::as_str)
        .collect();
    if actual != expected {
        return Err(failure("report_checks_mismatch"));
    }
    for table in &plan.tables {
        let count = results[table.check_id.as_str()]
            .observed_rows
            .ok_or_else(|| failure("report_row_count_missing"))?;
        if count < table.min_rows || count > i64::MAX as u64 {
            return Err(failure("report_row_expectation_failed"));
        }
    }
    for (id, result) in results {
        if id == "argos-constraints" {
            if result.observed_rows != Some(0) {
                return Err(failure("report_constraint_count_invalid"));
            }
        } else if id.starts_with("argos-") && result.observed_rows.is_some() {
            return Err(failure("report_builtin_check_invalid"));
        }
    }
    Ok(())
}

fn verify_metadata(
    plan: &ServiceRecoveryPlan,
    report: &ServiceRecoveryReport,
    max_age_secs: u64,
    now: u64,
) -> Result<PlanBinding> {
    let max_age_ms = max_age_secs
        .checked_mul(1000)
        .filter(|value| *value > 0)
        .ok_or_else(|| failure("invalid_report_max_age"))?;
    if report.format != "argos-service-recovery-v2"
        || report.plan_hash_version != Some(PLAN_HASH_VERSION)
        || report.plan_sha256.is_none()
        || report.expectations_sha256.is_none()
        || report.required_check_ids.is_none()
    {
        return Err(failure("legacy_or_unbound_report"));
    }
    if report.status != "passed" || report.failure_code.is_some() {
        return Err(failure("report_not_successful"));
    }
    if report.started_at_ms == 0
        || report.finished_at_ms < report.started_at_ms
        || report.started_at_ms > now
        || report.finished_at_ms > now
    {
        return Err(failure("invalid_or_future_report_time"));
    }
    if now - report.finished_at_ms > max_age_ms {
        return Err(failure("report_too_old"));
    }
    let binding = plan_binding(plan)?;
    if report.plan_sha256.as_deref() != Some(binding.plan_sha256.as_str()) {
        return Err(failure("report_plan_mismatch"));
    }
    if report.expectations_sha256.as_deref() != Some(binding.expectations_sha256.as_str()) {
        return Err(failure("report_expectations_mismatch"));
    }
    let basis = if plan.declared_recovery_point_ms.is_some() {
        "operator_declared_not_database_verified"
    } else {
        "unknown"
    };
    if report.service_id != plan.service_id
        || report.engine != plan.engine
        || report.declared_recovery_point_ms != plan.declared_recovery_point_ms
        || report.incident_at_ms != plan.incident_at_ms
        || report.recovery_point_basis != basis
    {
        return Err(failure("report_metadata_mismatch"));
    }
    if report.rpo_ms.is_some()
        || report.rpo_reason != "latest_source_commit_unknown"
        || report.service_rto_ms.is_some()
        || report.service_rto_reason != "application_startup_and_service_health_not_tested"
    {
        return Err(failure("unsupported_report_recovery_claim"));
    }
    verify_checks(plan, report, &binding)?;
    Ok(binding)
}

/// 보고서·백업 내용을 변경하지 않고 일관성과 최신성을 확인한다.
/// 성공해도 무서명 보고서의 작성자나 실제 실행 여부를 인증하지 않는다.
pub fn verify_report(
    plan: &ServiceRecoveryPlan,
    report_path: &Path,
    max_age_secs: u64,
) -> Result<ServiceReportVerification> {
    validate_plan(plan)?;
    if max_age_secs == 0 || max_age_secs.checked_mul(1000).is_none() {
        return Err(failure("invalid_report_max_age"));
    }
    let deadline = Instant::now() + Duration::from_secs(plan.timeout_secs);
    let mut report_bytes = Vec::new();
    read_stable_file(report_path, MAX_REPORT_BYTES as u64, deadline, |chunk| {
        report_bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    let report: ServiceRecoveryReport = serde_json::from_slice(&report_bytes)
        .map_err(|_| failure("invalid_service_report_json"))?;
    verify_metadata(plan, &report, max_age_secs, now_ms())?;
    require_offline_backup(plan)?;
    let (backup_bytes, backup_sha256) =
        read_stable_file(&plan.backup_path, plan.max_backup_bytes, deadline, |_| {
            Ok(())
        })?;
    require_offline_backup(plan)?;
    if report.backup_sha256.as_deref() != Some(backup_sha256.as_str())
        || report.backup_bytes != Some(backup_bytes)
    {
        return Err(failure("report_backup_mismatch"));
    }
    // 큰 백업을 읽는 동안 허용 기간을 넘길 수 있으므로 반환 직전에 다시 확인한다.
    let now = now_ms();
    let binding = verify_metadata(plan, &report, max_age_secs, now)?;
    Ok(ServiceReportVerification {format:"argos-service-report-verification-v1".into(),status:"consistent".into(),verified_at_ms:now,report_finished_at_ms:report.finished_at_ms,report_age_ms:now-report.finished_at_ms,max_age_secs,service_id:plan.service_id.clone(),engine:plan.engine,plan_sha256:binding.plan_sha256,expectations_sha256:binding.expectations_sha256,backup_sha256,report_sha256:hex::encode(Sha256::digest(&report_bytes)),backup_bytes,checked_ids:binding.required_check_ids,report_authenticated:false,limitations:vec!["무서명 보고서의 일관성과 최신성만 확인하며 작성자와 실제 실행 여부는 인증하지 않습니다.".into(),"복구 시험을 재실행하지 않으며 전체 서비스 복구·RPO·서비스 RTO를 보장하지 않습니다.".into()]})
}

fn require_offline_backup(plan: &ServiceRecoveryPlan) -> Result<()> {
    if plan.engine == DatabaseEngine::Sqlite {
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sidecar = plan.backup_path.as_os_str().to_owned();
            sidecar.push(suffix);
            if fs::symlink_metadata(PathBuf::from(sidecar)).is_ok() {
                return Err(failure("offline_native_backup_required"));
            }
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
