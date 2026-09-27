//! Isolated native database restore drills. This is separate from file-hash
//! recovery checks: it restores a database and verifies structure, references,
//! configured table expectations, and a rolled-back write/read transaction.
//! Only local backup artifacts and fixed validation operations are accepted.
use rusqlite::{
    backup::{Backup, StepResult},
    params, Connection, OpenFlags, OptionalExtension,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
mod postgres;
mod verification;
pub use verification::{verify_report, ServiceReportVerification};

const MAX_BACKUP_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_REPORT_BYTES: usize = 256 * 1024;
pub const REPORT_NAME: &str = "service-recovery.json";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseEngine {
    Sqlite,
    Postgresql,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRecoveryPlan {
    pub service_id: String,
    pub engine: DatabaseEngine,
    /// Offline native backup. Never interpreted as a connection string or SQL.
    pub backup_path: PathBuf,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_max_bytes")]
    pub max_backup_bytes: u64,
    #[serde(default = "default_workspace_bytes")]
    pub max_workspace_bytes: u64,
    /// Informational operator assertion, never inferred from file timestamps.
    #[serde(default)]
    pub declared_recovery_point_ms: Option<u64>,
    #[serde(default)]
    pub incident_at_ms: Option<u64>,
    #[serde(default)]
    pub expected_user_version: Option<i64>,
    #[serde(default)]
    pub tables: Vec<TableExpectation>,
    #[serde(default)]
    pub postgresql: Option<PostgresqlSettings>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresqlSettings {
    /// Trusted local package tree ("/" for a standard system installation).
    pub installation_root: PathBuf,
    pub major_version: u16,
}

fn default_timeout() -> u64 {
    30
}
fn default_max_bytes() -> u64 {
    128 * 1024 * 1024
}
fn default_workspace_bytes() -> u64 {
    512 * 1024 * 1024
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TableExpectation {
    pub check_id: String,
    pub table: String,
    #[serde(default)]
    pub required_columns: Vec<String>,
    #[serde(default = "default_min_rows")]
    pub min_rows: u64,
}
fn default_min_rows() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCheckResult {
    pub check_id: String,
    pub passed: bool,
    pub code: String,
    /// Counts only, never records or database error text.
    pub observed_rows: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecoveryReport {
    pub format: String,
    /// 구버전 파싱을 위한 선택 필드. 검증은 결합 정보 누락을 거부한다.
    #[serde(default)]
    pub plan_hash_version: Option<u32>,
    #[serde(default)]
    pub plan_sha256: Option<String>,
    #[serde(default)]
    pub expectations_sha256: Option<String>,
    #[serde(default)]
    pub required_check_ids: Option<Vec<String>>,
    pub service_id: String,
    pub engine: DatabaseEngine,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub status: String,
    pub failure_code: Option<String>,
    pub backup_sha256: Option<String>,
    pub backup_bytes: Option<u64>,
    pub restore_duration_ms: u64,
    pub validation_duration_ms: u64,
    pub total_duration_ms: u64,
    pub declared_recovery_point_ms: Option<u64>,
    pub recovery_point_basis: String,
    pub incident_at_ms: Option<u64>,
    pub rpo_ms: Option<u64>,
    pub rpo_reason: String,
    pub service_rto_ms: Option<u64>,
    pub service_rto_reason: String,
    pub checks: Vec<ServiceCheckResult>,
    pub limitations: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("서비스 복구 거부: {code}")]
pub struct ServiceRecoveryError {
    pub code: &'static str,
}
type Result<T> = std::result::Result<T, ServiceRecoveryError>;
fn failure(code: &'static str) -> ServiceRecoveryError {
    ServiceRecoveryError { code }
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as u64
}
fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u64::MAX as u128) as u64
}
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
fn identifier(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn safe_path(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some()
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        && path
            .to_str()
            .is_some_and(|value| !value.chars().any(char::is_control))
}

pub fn validate_plan(plan: &ServiceRecoveryPlan) -> Result<()> {
    if !id(&plan.service_id) {
        return Err(failure("invalid_service_id"));
    }
    if !safe_path(&plan.backup_path) {
        return Err(failure("backup_path_must_be_absolute_local_file"));
    }
    if !(1..=300).contains(&plan.timeout_secs) {
        return Err(failure("timeout_out_of_range"));
    }
    if !(512..=MAX_BACKUP_BYTES).contains(&plan.max_backup_bytes) {
        return Err(failure("backup_limit_out_of_range"));
    }
    if !(1024..=8 * 1024 * 1024 * 1024).contains(&plan.max_workspace_bytes)
        || plan.max_workspace_bytes < plan.max_backup_bytes
    {
        return Err(failure("workspace_limit_out_of_range"));
    }
    if plan.tables.is_empty() || plan.tables.len() > 32 {
        return Err(failure("one_to_32_table_expectations_required"));
    }
    let mut ids = std::collections::HashSet::new();
    for table in &plan.tables {
        if !id(&table.check_id)
            || !ids.insert(&table.check_id)
            || table.check_id.starts_with("argos-")
        {
            return Err(failure("invalid_or_duplicate_check_id"));
        }
        if !identifier(&table.table)
            || table.table.starts_with("sqlite_")
            || table.table.starts_with("__argos_")
        {
            return Err(failure("unsupported_table_identifier"));
        }
        if table.required_columns.len() > 128
            || table
                .required_columns
                .iter()
                .any(|column| !identifier(column))
        {
            return Err(failure("unsupported_column_identifier"));
        }
        if table.min_rows > i64::MAX as u64 {
            return Err(failure("row_expectation_out_of_range"));
        }
    }
    if plan
        .expected_user_version
        .is_some_and(|version| !(0..=i32::MAX as i64).contains(&version))
    {
        return Err(failure("user_version_out_of_range"));
    }
    if plan
        .declared_recovery_point_ms
        .into_iter()
        .chain(plan.incident_at_ms)
        .any(|value| value > i64::MAX as u64 || value > now_ms())
    {
        return Err(failure("recovery_timestamp_out_of_range"));
    }
    if plan
        .declared_recovery_point_ms
        .zip(plan.incident_at_ms)
        .is_some_and(|(point, incident)| point > incident)
    {
        return Err(failure("recovery_point_after_incident"));
    }
    match (&plan.engine, &plan.postgresql) {
        (DatabaseEngine::Sqlite, Some(_)) => return Err(failure("postgresql_settings_for_sqlite")),
        (DatabaseEngine::Postgresql, None) => return Err(failure("postgresql_settings_required")),
        (DatabaseEngine::Postgresql, Some(settings)) => {
            if (!safe_path(&settings.installation_root)
                && settings.installation_root != Path::new("/"))
                || !(14..=18).contains(&settings.major_version)
            {
                return Err(failure("invalid_postgresql_installation"));
            }
            if plan.expected_user_version.is_some() {
                return Err(failure("user_version_is_sqlite_only"));
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn new_report(plan: &ServiceRecoveryPlan) -> ServiceRecoveryReport {
    let binding = verification::plan_binding(plan).ok();
    ServiceRecoveryReport {
        format: "argos-service-recovery-v2".into(),
        plan_hash_version: binding.as_ref().map(|_| verification::PLAN_HASH_VERSION),
        plan_sha256: binding.as_ref().map(|binding| binding.plan_sha256.clone()),
        expectations_sha256: binding.as_ref().map(|binding| binding.expectations_sha256.clone()),
        required_check_ids: binding.map(|binding| binding.required_check_ids),
        service_id: plan.service_id.clone(), engine: plan.engine,
        started_at_ms: now_ms(), finished_at_ms: 0, status: "failed".into(), failure_code: None,
        backup_sha256: None, backup_bytes: None, restore_duration_ms: 0, validation_duration_ms: 0, total_duration_ms: 0,
        declared_recovery_point_ms: plan.declared_recovery_point_ms,
        recovery_point_basis: if plan.declared_recovery_point_ms.is_some() { "operator_declared_not_database_verified" } else { "unknown" }.into(),
        incident_at_ms: plan.incident_at_ms, rpo_ms: None, rpo_reason: "latest_source_commit_unknown".into(),
        service_rto_ms: None, service_rto_reason: "application_startup_and_service_health_not_tested".into(),
        checks: Vec::new(), limitations: vec![
            "Database restore and fixed checks do not prove complete application recovery or business consistency.".into(),
            "No production database is contacted. Backup timestamps do not establish RPO.".into(),
            "Source and workspace parent directories must be controlled by the operator.".into(),
        ],
    }
}

/// Run directly with bounded SQLite work. CLI supervision additionally enforces a
/// process deadline (including blocked filesystem I/O). The destination must not exist.
pub fn run(plan: &ServiceRecoveryPlan, directory: &Path) -> Result<ServiceRecoveryReport> {
    validate_plan(plan)?;
    create_workspace(directory)?;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(plan.timeout_secs);
    let mut report = new_report(plan);
    let result = match plan.engine {
        DatabaseEngine::Sqlite => run_sqlite(plan, directory, deadline, &mut report),
        DatabaseEngine::Postgresql => {
            #[cfg(target_os = "linux")]
            {
                postgres::run(plan, directory, deadline, &mut report)
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(failure("postgresql_requires_linux_bubblewrap"))
            }
        }
    };
    let result =
        result.and_then(|()| workspace_budget(directory, plan.max_workspace_bytes, deadline));
    report.total_duration_ms = elapsed_ms(start);
    if result.is_err() && report.restore_duration_ms == 0 && report.validation_duration_ms == 0 {
        report.restore_duration_ms = report.total_duration_ms;
    }
    report.finished_at_ms = now_ms();
    match result {
        Ok(()) => report.status = "passed".into(),
        Err(error) => report.failure_code = Some(error.code.into()),
    }
    write_report(directory, &report)?;
    Ok(report)
}

fn create_workspace(directory: &Path) -> Result<()> {
    if !safe_path(directory) {
        return Err(failure("workspace_must_be_new_absolute_directory"));
    }
    let parent = directory
        .parent()
        .ok_or_else(|| failure("workspace_parent_missing"))?;
    if !parent.is_dir() {
        return Err(failure("workspace_parent_missing"));
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(directory)
        .map_err(|_| failure("workspace_create_failed_or_already_exists"))
}

fn new_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| failure("workspace_file_create_failed"))
}

pub fn write_report(directory: &Path, report: &ServiceRecoveryReport) -> Result<()> {
    let data =
        serde_json::to_vec_pretty(report).map_err(|_| failure("report_serialization_failed"))?;
    if data.len() > MAX_REPORT_BYTES {
        return Err(failure("report_output_limit"));
    }
    let mut output = new_file(&directory.join(REPORT_NAME))?;
    output
        .write_all(&data)
        .and_then(|_| output.sync_all())
        .map_err(|_| failure("report_write_failed"))
}

fn deadline_check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(failure("timeout"))
    } else {
        Ok(())
    }
}

fn staged_filename(engine: DatabaseEngine) -> &'static str {
    match engine {
        DatabaseEngine::Sqlite => "input.sqlite3",
        DatabaseEngine::Postgresql => "input.dump",
    }
}

fn stage_backup(
    plan: &ServiceRecoveryPlan,
    directory: &Path,
    deadline: Instant,
) -> Result<(String, u64)> {
    let metadata =
        fs::symlink_metadata(&plan.backup_path).map_err(|_| failure("backup_unreadable"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(failure("backup_must_be_regular_file"));
    }
    if metadata.len() > plan.max_backup_bytes {
        return Err(failure("backup_size_limit"));
    }
    for suffix in if plan.engine == DatabaseEngine::Sqlite {
        &["-wal", "-shm", "-journal"][..]
    } else {
        &[][..]
    } {
        let mut sidecar = plan.backup_path.as_os_str().to_owned();
        sidecar.push(suffix);
        if fs::symlink_metadata(PathBuf::from(sidecar)).is_ok() {
            return Err(failure("offline_native_backup_required"));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut input = options
        .open(&plan.backup_path)
        .map_err(|_| failure("backup_unreadable"))?;
    let before = input
        .metadata()
        .map_err(|_| failure("backup_metadata_failed"))?;
    if !before.is_file() || before.len() > plan.max_backup_bytes {
        return Err(failure("backup_must_be_bounded_regular_file"));
    }
    let mut output = new_file(&directory.join(staged_filename(plan.engine)))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        deadline_check(deadline)?;
        let read = input
            .read(&mut buffer)
            .map_err(|_| failure("backup_read_failed"))?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        if bytes > plan.max_backup_bytes {
            return Err(failure("backup_size_limit"));
        }
        let header = match plan.engine {
            DatabaseEngine::Sqlite => b"SQLite format 3\0".as_slice(),
            DatabaseEngine::Postgresql => b"PGDMP".as_slice(),
        };
        if bytes == read as u64 && !buffer[..read].starts_with(header) {
            return Err(failure("native_backup_header_required"));
        }
        output
            .write_all(&buffer[..read])
            .map_err(|_| failure("backup_stage_write_failed"))?;
        hasher.update(&buffer[..read]);
    }
    output
        .sync_all()
        .map_err(|_| failure("backup_stage_sync_failed"))?;
    let after = input
        .metadata()
        .map_err(|_| failure("backup_metadata_failed"))?;
    let changed = before.len() != after.len() || before.modified().ok() != after.modified().ok();
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt;
        changed || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec()
    };
    if plan.engine == DatabaseEngine::Sqlite {
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sidecar = plan.backup_path.as_os_str().to_owned();
            sidecar.push(suffix);
            if fs::symlink_metadata(PathBuf::from(sidecar)).is_ok() {
                return Err(failure("offline_native_backup_required"));
            }
        }
    }
    if changed || bytes != before.len() || bytes == 0 {
        return Err(failure("backup_changed_or_empty"));
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn configure(connection: &Connection, deadline: Instant) -> Result<()> {
    connection
        .busy_timeout(Duration::from_millis(20))
        .map_err(|_| failure("sqlite_setup_failed"))?;
    connection
        .execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA foreign_keys=ON;",
        )
        .map_err(|_| failure("sqlite_setup_failed"))?;
    connection.progress_handler(1000, Some(move || Instant::now() >= deadline));
    Ok(())
}

fn sqlite_error(deadline: Instant, code: &'static str) -> ServiceRecoveryError {
    if Instant::now() >= deadline {
        failure("timeout")
    } else {
        failure(code)
    }
}

fn check_result(
    report: &mut ServiceRecoveryReport,
    check_id: &str,
    passed: bool,
    code: &str,
    observed_rows: Option<u64>,
) {
    report.checks.push(ServiceCheckResult {
        check_id: check_id.into(),
        passed,
        code: code.into(),
        observed_rows,
    });
}

fn run_sqlite(
    plan: &ServiceRecoveryPlan,
    directory: &Path,
    deadline: Instant,
    report: &mut ServiceRecoveryReport,
) -> Result<()> {
    let restore_start = Instant::now();
    let (hash, bytes) = stage_backup(plan, directory, deadline)?;
    report.backup_sha256 = Some(hash);
    report.backup_bytes = Some(bytes);
    let source = Connection::open_with_flags(
        directory.join("input.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| failure("sqlite_source_open_failed"))?;
    configure(&source, deadline)?;
    let pages: u64 = source
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|_| failure("sqlite_page_budget_failed"))?;
    let page_size: u64 = source
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|_| failure("sqlite_page_budget_failed"))?;
    if pages
        .checked_mul(page_size)
        .is_none_or(|size| size > plan.max_backup_bytes)
    {
        return Err(failure("sqlite_restore_size_limit"));
    }
    let destination = directory.join("restored.sqlite3");
    new_file(&destination)?;
    let mut restored = Connection::open_with_flags(
        &destination,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| failure("sqlite_restore_open_failed"))?;
    configure(&restored, deadline)?;
    {
        let backup = Backup::new(&source, &mut restored)
            .map_err(|_| failure("sqlite_restore_init_failed"))?;
        loop {
            deadline_check(deadline)?;
            match backup
                .step(64)
                .map_err(|_| sqlite_error(deadline, "sqlite_restore_failed"))?
            {
                StepResult::Done => break,
                StepResult::More => {
                    workspace_budget(directory, plan.max_workspace_bytes, deadline)?;
                }
                StepResult::Busy | StepResult::Locked => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                _ => return Err(failure("sqlite_restore_failed")),
            }
        }
    }
    report.restore_duration_ms = elapsed_ms(restore_start);
    let validation_start = Instant::now();
    let validation = validate_sqlite(&mut restored, plan, deadline, report);
    report.validation_duration_ms = elapsed_ms(validation_start);
    validation?;
    File::open(&destination)
        .and_then(|file| file.sync_all())
        .map_err(|_| failure("restored_database_sync_failed"))?;
    Ok(())
}

fn validate_sqlite(
    connection: &mut Connection,
    plan: &ServiceRecoveryPlan,
    deadline: Instant,
    report: &mut ServiceRecoveryReport,
) -> Result<()> {
    deadline_check(deadline)?;
    // Reject virtual tables before inspecting application data. No extension
    // loading, attachment, user-supplied SQL, or server connection is supported.
    let virtual_tables: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_list WHERE schema='main' AND type='virtual'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| sqlite_error(deadline, "sqlite_schema_inspection_failed"))?;
    if virtual_tables != 0 {
        return Err(failure("sqlite_virtual_tables_not_supported"));
    }
    let integrity: String = connection
        .query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))
        .map_err(|_| sqlite_error(deadline, "sqlite_integrity_check_failed"))?;
    let okay = integrity == "ok";
    check_result(
        report,
        "argos-integrity",
        okay,
        if okay { "ok" } else { "integrity_violation" },
        None,
    );
    if !okay {
        return Err(failure("sqlite_integrity_violation"));
    }
    let violation = connection
        .prepare("PRAGMA foreign_key_check")
        .and_then(|mut statement| statement.query([])?.next().map(|row| row.is_some()))
        .map_err(|_| sqlite_error(deadline, "sqlite_foreign_key_check_failed"))?;
    check_result(
        report,
        "argos-foreign-keys",
        !violation,
        if violation {
            "foreign_key_violation"
        } else {
            "ok"
        },
        None,
    );
    if violation {
        return Err(failure("sqlite_foreign_key_violation"));
    }
    if let Some(expected) = plan.expected_user_version {
        let actual: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|_| sqlite_error(deadline, "sqlite_user_version_check_failed"))?;
        check_result(
            report,
            "argos-user-version",
            actual == expected,
            if actual == expected {
                "ok"
            } else {
                "schema_version_mismatch"
            },
            None,
        );
        if actual != expected {
            return Err(failure("sqlite_schema_version_mismatch"));
        }
    }
    for table in &plan.tables {
        deadline_check(deadline)?;
        let kind: Option<String> = connection
            .query_row(
                "SELECT type FROM pragma_table_list WHERE schema='main' AND name=?1",
                params![table.table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| sqlite_error(deadline, "sqlite_table_inspection_failed"))?;
        if kind.as_deref() != Some("table") {
            check_result(
                report,
                &table.check_id,
                false,
                "ordinary_table_missing",
                None,
            );
            return Err(failure("sqlite_expected_table_missing"));
        }
        for column in &table.required_columns {
            let present: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_xinfo(?1) WHERE name=?2)",
                    params![table.table, column],
                    |row| row.get(0),
                )
                .map_err(|_| sqlite_error(deadline, "sqlite_column_inspection_failed"))?;
            if !present {
                check_result(
                    report,
                    &table.check_id,
                    false,
                    "required_column_missing",
                    None,
                );
                return Err(failure("sqlite_expected_column_missing"));
            }
        }
        // Identifiers are validated ASCII names and quoted; no SQL input accepted.
        let query = format!("SELECT COUNT(*) FROM \"{}\"", table.table);
        let count: i64 = connection
            .query_row(&query, [], |row| row.get(0))
            .map_err(|_| sqlite_error(deadline, "sqlite_row_count_failed"))?;
        let okay = count >= 0 && count as u64 >= table.min_rows;
        check_result(
            report,
            &table.check_id,
            okay,
            if okay { "ok" } else { "insufficient_rows" },
            u64::try_from(count).ok(),
        );
        if !okay {
            return Err(failure("sqlite_row_expectation_failed"));
        }
    }
    deadline_check(deadline)?;
    let transaction = connection
        .transaction()
        .map_err(|_| sqlite_error(deadline, "sqlite_write_probe_failed"))?;
    transaction.execute_batch("CREATE TABLE __argos_service_recovery_probe(value INTEGER NOT NULL); INSERT INTO __argos_service_recovery_probe VALUES(73021);")
        .map_err(|_| sqlite_error(deadline, "sqlite_write_probe_failed"))?;
    let value: i64 = transaction
        .query_row(
            "SELECT value FROM __argos_service_recovery_probe",
            [],
            |row| row.get(0),
        )
        .map_err(|_| sqlite_error(deadline, "sqlite_write_probe_failed"))?;
    transaction
        .rollback()
        .map_err(|_| sqlite_error(deadline, "sqlite_write_probe_rollback_failed"))?;
    if value != 73021 {
        return Err(failure("sqlite_write_probe_mismatch"));
    }
    check_result(report, "argos-write-read-rollback", true, "ok", None);
    Ok(())
}

#[cfg(test)]
mod tests;

// Monitoring complements per-file process limits. A dedicated filesystem quota
// is still required for a hard aggregate storage reservation under hostile load.
fn workspace_budget(directory: &Path, limit: u64, deadline: Instant) -> Result<()> {
    let mut pending = vec![directory.to_path_buf()];
    let mut entries = 0usize;
    let mut bytes = 0u64;
    while let Some(path) = pending.pop() {
        deadline_check(deadline)?;
        for entry in
            fs::read_dir(path).map_err(|_| failure("workspace_budget_inspection_failed"))?
        {
            let entry = entry.map_err(|_| failure("workspace_budget_inspection_failed"))?;
            entries += 1;
            if entries > 50000 {
                return Err(failure("workspace_entry_limit"));
            }
            if entries % 128 == 0 {
                deadline_check(deadline)?;
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| failure("workspace_budget_inspection_failed"))?;
            if metadata.file_type().is_symlink() {
                return Err(failure("workspace_symlink_not_allowed"));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes.saturating_add(metadata.len());
                if bytes > limit {
                    return Err(failure("workspace_size_limit"));
                }
            }
        }
    }
    Ok(())
}
