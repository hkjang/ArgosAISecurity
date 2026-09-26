//! Signed activation is a transaction: trust checks, high-watermark, exact bytes,
//! effective settings, and the acceptance audit have one durable commit.
use crate::{verify_bytes, Policy};
use argos_common::config::{PolicyFileConfig, SensorKind};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_AUDIT_ROWS: i64 = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum ActivationError {
    #[error("정책 활성화 거부: {code}")]
    Rejected { code: &'static str },
    #[error("정책 상태 저장소 오류: {0}")]
    State(#[from] rusqlite::Error),
    #[error("정책 상태 파일 오류: {0}")]
    Io(#[from] std::io::Error),
    #[error("정책 상태 경로는 현재 계정 소유의 일반 파일/전용 디렉터리여야 합니다 (파일 0600, 디렉터리 0700)")]
    UnsafeStatePath,
}

fn reject(code: &'static str) -> ActivationError {
    ActivationError::Rejected { code }
}

#[derive(Debug)]
pub struct ActivatedPolicy {
    pub policy: Policy,
    pub sha256: String,
    /// accepted / restarted / rollback_accepted
    pub outcome: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PolicyStatus {
    pub policy_id: String,
    pub version: u64,
    pub sha256: String,
    pub key_id: String,
    pub accepted_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct PolicyAudit {
    pub id: i64,
    pub timestamp_ms: u64,
    pub outcome: String,
    pub reason: String,
    pub version: Option<u64>,
    pub policy_id: Option<String>,
    pub sha256: Option<String>,
    pub key_id: Option<String>,
    pub approval_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PolicyStateSnapshot {
    pub active: Option<PolicyStatus>,
    pub audit: Vec<PolicyAudit>,
    pub audit_limit: usize,
    pub audit_retention_rows: i64,
}

pub fn policy_state_path(config: &PolicyFileConfig, event_db_path: &Path) -> PathBuf {
    if !config.state_path.as_os_str().is_empty() {
        return config.state_path.clone();
    }
    let mut directory = event_db_path.as_os_str().to_owned();
    directory.push(".policy-state");
    PathBuf::from(directory).join("state.sqlite3")
}

/// Activate from one bounded read. An invalid configured policy never returns a
/// fallback policy. Opening or auditing failure also fails closed.
pub fn activate_file(
    config: &PolicyFileConfig,
    event_db_path: &Path,
    sensor: SensorKind,
) -> Result<ActivatedPolicy, ActivationError> {
    activate_at(config, event_db_path, sensor, argos_common::now_ms)
}

fn activate_at(
    config: &PolicyFileConfig,
    event_db_path: &Path,
    sensor: SensorKind,
    clock: impl Fn() -> u64,
) -> Result<ActivatedPolicy, ActivationError> {
    let mut connection = open_state(&policy_state_path(config, event_db_path))?;
    let verified = read_verify(config, sensor);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now = clock();
    // Untrusted policy content, parse errors and arbitrary path contents never
    // enter the audit or error messages. Only verified, validated identifiers do.
    let (policy, bytes, hash, settings, warnings) = match verified {
        Ok(value) => value,
        Err(code) => {
            audit(&transaction, now, "rejected", code, None, None)?;
            transaction.commit()?;
            return Err(reject(code));
        }
    };
    let outcome = match check_acceptance(&transaction, config, &policy, &hash, &settings, now) {
        Ok(outcome) => outcome,
        Err(code) => {
            audit(
                &transaction,
                now,
                "rejected",
                code,
                Some(&policy),
                Some(&hash),
            )?;
            transaction.commit()?;
            return Err(reject(code));
        }
    };
    if outcome != "restarted" {
        transaction.execute(
            "INSERT INTO accepted_policies (version, policy_id, sha256, key_id, accepted_at_ms, expires_at_ms, policy_bytes, settings_json, approval_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![policy.version, policy.policy_id, hash, policy.key_id, now, policy.expires_at_ms, bytes, settings, policy.rollback.as_ref().map(|r| &r.approval_id)],
        )?;
        transaction.execute(
            "INSERT INTO active_policy (singleton, version) VALUES (1, ?1) ON CONFLICT(singleton) DO UPDATE SET version=excluded.version",
            [policy.version],
        )?;
    }
    audit(
        &transaction,
        now,
        outcome,
        "validated",
        Some(&policy),
        Some(&hash),
    )?;
    transaction.commit()?;
    Ok(ActivatedPolicy {
        policy,
        sha256: hash,
        outcome: outcome.to_string(),
        warnings,
    })
}

type Verified = (Policy, Vec<u8>, String, String, Vec<String>);

fn read_verify(config: &PolicyFileConfig, sensor: SensorKind) -> Result<Verified, &'static str> {
    if !valid_id(&config.policy_id)
        || !valid_id(&config.host_id)
        || config.groups.len() > 128
        || config.groups.iter().any(|g| !valid_id(g))
    {
        return Err("invalid_local_identity");
    }
    if config.trusted_keys.is_empty()
        || config.trusted_keys.len() > 64
        || config.trusted_keys.keys().any(|id| !valid_id(id))
    {
        return Err("invalid_local_trusted_keys");
    }
    let mut unique_keys = std::collections::HashSet::new();
    for key in config.trusted_keys.values() {
        let parsed = crate::parse_verifying_key(key).map_err(|_| "invalid_local_trusted_keys")?;
        if !unique_keys.insert(parsed.to_bytes()) {
            return Err("duplicate_local_trusted_key");
        }
    }
    let bytes = read_bounded(&config.path, MAX_POLICY_BYTES).map_err(|_| "policy_read_failed")?;
    let signature_bytes = read_bounded(&crate::sig_path_for(&config.path), 256)
        .map_err(|_| "signature_read_failed")?;
    let signature = std::str::from_utf8(&signature_bytes).map_err(|_| "invalid_signature")?;
    // Pick a key only from the local trust map; do not use unverified key IDs as
    // paths or accept public keys supplied inside the policy.
    let signing_id = config
        .trusted_keys
        .iter()
        .find_map(|(id, key)| verify_bytes(&bytes, signature, key).is_ok().then_some(id))
        .ok_or("invalid_signature")?;
    let policy: Policy =
        toml::from_str(std::str::from_utf8(&bytes).map_err(|_| "invalid_policy_format")?)
            .map_err(|_| "invalid_policy_format")?;
    if !valid_id(&policy.policy_id)
        || !valid_id(&policy.key_id)
        || policy.target_hosts.len() > 128
        || policy.target_groups.len() > 128
        || policy
            .target_hosts
            .iter()
            .chain(&policy.target_groups)
            .any(|id| !valid_id(id))
    {
        return Err("invalid_policy_metadata");
    }
    if policy.key_id != *signing_id {
        return Err("key_id_mismatch");
    }
    if policy.version == 0 || policy.version > i64::MAX as u64 {
        return Err("invalid_version");
    }
    if let Some(rollback) = &policy.rollback {
        if rollback.source_version == 0
            || rollback.source_version >= policy.version
            || rollback.source_sha256.len() != 64
            || !rollback
                .source_sha256
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            || !valid_id(&rollback.approval_id)
            || rollback.reason.trim().is_empty()
            || rollback.reason.len() > 512
            || rollback.reason.chars().any(char::is_control)
        {
            return Err("invalid_rollback_approval");
        }
    }
    let warnings =
        argos_detect::validate_configuration(&policy.detection, &policy.response, sensor)
            .map_err(|_| "invalid_detection_response_configuration")?;
    let settings = serde_json::to_string(&(&policy.detection, &policy.response))
        .map_err(|_| "invalid_detection_response_configuration")?;
    let hash = hex::encode(Sha256::digest(&bytes));
    Ok((policy, bytes, hash, settings, warnings))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:@".contains(&c))
}

fn read_bounded(path: &Path, maximum: u64) -> std::io::Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "policy must be a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "policy size limit",
        ));
    }
    Ok(bytes)
}

fn check_acceptance(
    transaction: &rusqlite::Transaction<'_>,
    config: &PolicyFileConfig,
    policy: &Policy,
    hash: &str,
    settings: &str,
    now: u64,
) -> Result<&'static str, &'static str> {
    check_metadata(config, policy, now)?;
    let active: Option<(u64, String, String)> = transaction.query_row(
        "SELECT p.version,p.sha256,p.policy_id FROM active_policy a JOIN accepted_policies p ON p.version=a.version WHERE a.singleton=1",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).optional().map_err(|_| "state_query_failed")?;
    if let Some((version, active_hash, active_id)) = &active {
        if active_id != &policy.policy_id {
            return Err("policy_series_change");
        }
        if policy.version < *version {
            return Err("version_downgrade");
        }
        if policy.version == *version {
            return if hash == active_hash {
                Ok("restarted")
            } else {
                Err("version_reuse")
            };
        }
    }
    if let Some(rollback) = &policy.rollback {
        if active
            .as_ref()
            .is_none_or(|(version, _, _)| rollback.source_version >= *version)
        {
            return Err("rollback_source_not_older");
        }
        let source: Option<(String,String)> = transaction.query_row(
            "SELECT sha256,settings_json FROM accepted_policies WHERE version=?1 AND policy_id=?2",
            params![rollback.source_version,policy.policy_id], |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(|_| "state_query_failed")?;
        let Some((source_hash, source_settings)) = source else {
            return Err("rollback_source_unknown");
        };
        if source_hash != rollback.source_sha256 {
            return Err("rollback_source_hash_mismatch");
        }
        if source_settings != settings {
            return Err("rollback_settings_mismatch");
        }
        let used: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accepted_policies WHERE approval_id=?1)",
                [&rollback.approval_id],
                |r| r.get(0),
            )
            .map_err(|_| "state_query_failed")?;
        if used {
            return Err("rollback_approval_reused");
        }
        return Ok("rollback_accepted");
    }
    Ok("accepted")
}

fn check_metadata(
    config: &PolicyFileConfig,
    policy: &Policy,
    now: u64,
) -> Result<(), &'static str> {
    if policy.policy_id != config.policy_id {
        return Err("policy_id_mismatch");
    }
    if policy.issued_at_ms == 0
        || policy.issued_at_ms > policy.not_before_ms
        || policy.not_before_ms >= policy.expires_at_ms
        || policy.expires_at_ms > i64::MAX as u64
    {
        return Err("invalid_validity_interval");
    }
    if now < policy.not_before_ms {
        return Err("not_yet_valid");
    }
    if now >= policy.expires_at_ms {
        return Err("expired");
    }
    // If both scopes are present, both must match: listing a group must not
    // silently widen a policy explicitly restricted to particular hosts.
    if policy.target_hosts.is_empty() && policy.target_groups.is_empty() {
        return Err("missing_target");
    }
    if !policy.target_hosts.is_empty() && !policy.target_hosts.contains(&config.host_id) {
        return Err("host_target_mismatch");
    }
    if !policy.target_groups.is_empty()
        && !policy
            .target_groups
            .iter()
            .any(|group| config.groups.contains(group))
    {
        return Err("group_target_mismatch");
    }
    Ok(())
}

fn audit(
    transaction: &rusqlite::Transaction<'_>,
    now: u64,
    outcome: &str,
    reason: &str,
    policy: Option<&Policy>,
    hash: Option<&str>,
) -> Result<(), ActivationError> {
    transaction.execute(
        "INSERT INTO policy_audit(timestamp_ms,outcome,reason,version,policy_id,sha256,key_id,approval_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![now,outcome,reason,policy.map(|p|p.version),policy.map(|p|&p.policy_id),hash,policy.map(|p|&p.key_id),policy.and_then(|p|p.rollback.as_ref().map(|r|&r.approval_id))],
    )?;
    transaction.execute(
        "DELETE FROM policy_audit WHERE id <= (SELECT MAX(id)-?1 FROM policy_audit)",
        [MAX_AUDIT_ROWS],
    )?;
    Ok(())
}

fn protect_state_path(path: &Path) -> Result<(), ActivationError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(ActivationError::UnsafeStatePath)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(parent)?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(ActivationError::UnsafeStatePath);
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(ActivationError::UnsafeStatePath);
        }
        // Make creation of a new state directory durable as well as SQLite's
        // commit. Losing the directory after power loss would reset replay state.
        for directory in parent.canonicalize()?.ancestors() {
            std::fs::File::open(directory)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
        // Filesystem ACL protection needs a platform-specific implementation.
        return Err(ActivationError::UnsafeStatePath);
    }
    Ok(())
}

fn open_state(path: &Path) -> Result<Connection, ActivationError> {
    protect_state_path(path)?;
    let connection = Connection::open(path)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS accepted_policies (
            version INTEGER PRIMARY KEY CHECK(version>0), policy_id TEXT NOT NULL,
            sha256 TEXT NOT NULL, key_id TEXT NOT NULL, accepted_at_ms INTEGER NOT NULL,
            expires_at_ms INTEGER NOT NULL, policy_bytes BLOB NOT NULL, settings_json TEXT NOT NULL,
            approval_id TEXT UNIQUE);
        CREATE TABLE IF NOT EXISTS active_policy (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL REFERENCES accepted_policies(version));
        CREATE TABLE IF NOT EXISTS policy_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_ms INTEGER NOT NULL, outcome TEXT NOT NULL,
            reason TEXT NOT NULL, version INTEGER, policy_id TEXT, sha256 TEXT, key_id TEXT, approval_id TEXT);")?;
    Ok(connection)
}

/// Read-only inspection; this never creates a database, accepts a candidate or
/// changes the version high-watermark. Audit messages contain bounded codes.
pub fn read_state(path: &Path, audit_limit: usize) -> Result<PolicyStateSnapshot, ActivationError> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let active = connection.query_row(
        "SELECT p.policy_id,p.version,p.sha256,p.key_id,p.accepted_at_ms,p.expires_at_ms FROM active_policy a JOIN accepted_policies p ON p.version=a.version WHERE a.singleton=1",
        [], |r| Ok(PolicyStatus {policy_id:r.get(0)?,version:r.get(1)?,sha256:r.get(2)?,key_id:r.get(3)?,accepted_at_ms:r.get(4)?,expires_at_ms:r.get(5)?}),
    ).optional()?;
    let limit = audit_limit.min(1000);
    let mut statement = connection.prepare("SELECT id,timestamp_ms,outcome,reason,version,policy_id,sha256,key_id,approval_id FROM policy_audit ORDER BY id DESC LIMIT ?1")?;
    let audit = statement
        .query_map([limit as i64], |r| {
            Ok(PolicyAudit {
                id: r.get(0)?,
                timestamp_ms: r.get(1)?,
                outcome: r.get(2)?,
                reason: r.get(3)?,
                version: r.get(4)?,
                policy_id: r.get(5)?,
                sha256: r.get(6)?,
                key_id: r.get(7)?,
                approval_id: r.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PolicyStateSnapshot {
        active,
        audit,
        audit_limit: limit,
        audit_retention_rows: MAX_AUDIT_ROWS,
    })
}

/// Return the exact accepted baseline, independent of a possibly replaced
/// candidate file. Hash and saved effective settings must still match. This is
/// historical state inspection, not an authorization to reactivate expired data.
pub fn load_active_policy(path: &Path) -> Result<Policy, ActivationError> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let (bytes, hash, settings): (Vec<u8>, String, String) = connection.query_row(
        "SELECT p.policy_bytes,p.sha256,p.settings_json FROM active_policy a JOIN accepted_policies p ON p.version=a.version WHERE a.singleton=1",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if hex::encode(Sha256::digest(&bytes)) != hash {
        return Err(reject("state_hash_mismatch"));
    }
    let policy: Policy =
        toml::from_str(std::str::from_utf8(&bytes).map_err(|_| reject("invalid_saved_policy"))?)
            .map_err(|_| reject("invalid_saved_policy"))?;
    let actual = serde_json::to_string(&(&policy.detection, &policy.response))
        .map_err(|_| reject("invalid_saved_policy"))?;
    if actual != settings {
        return Err(reject("state_settings_mismatch"));
    }
    Ok(policy)
}

/// Signature + local trust/target/time/config validation only. This read-only
/// preview does NOT check or advance the persistent anti-replay state.
pub fn load_trusted(
    config: &PolicyFileConfig,
    sensor: SensorKind,
) -> Result<Policy, ActivationError> {
    let (policy, _, _, _, _) = read_verify(config, sensor).map_err(reject)?;
    check_metadata(config, &policy, argos_common::now_ms()).map_err(reject)?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{gen_keypair, sign_file, RollbackApproval};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture {
        dir: PathBuf,
        config: PolicyFileConfig,
        secret: String,
        db: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "argos-trust-{}-{}-{}",
                std::process::id(),
                argos_common::now_ms(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let (secret, public) = gen_keypair();
            let config = PolicyFileConfig {
                path: dir.join("policy.toml"),
                policy_id: "production".into(),
                host_id: "host-1".into(),
                groups: vec!["web".into()],
                trusted_keys: [("signer-1".into(), public)].into(),
                ..Default::default()
            };
            Self {
                db: dir.join("events.db"),
                dir,
                config,
                secret,
            }
        }
        fn policy(&self, version: u64) -> Policy {
            Policy {
                version,
                policy_id: "production".into(),
                key_id: "signer-1".into(),
                issued_at_ms: 1,
                not_before_ms: 100,
                expires_at_ms: 10_000,
                target_hosts: vec!["host-1".into()],
                target_groups: vec!["web".into()],
                ..Default::default()
            }
        }
        fn write(&self, policy: &Policy) {
            std::fs::write(&self.config.path, toml::to_string(policy).unwrap()).unwrap();
            sign_file(&self.config.path, &self.secret).unwrap();
        }
        fn activate(&self, now: u64) -> Result<ActivatedPolicy, ActivationError> {
            activate_at(&self.config, &self.db, SensorKind::Fanotify, || now)
        }
        fn state(&self) -> PathBuf {
            policy_state_path(&self.config, &self.db)
        }
        fn rejection(&self, now: u64, code: &str) {
            let error = self.activate(now).unwrap_err();
            assert!(
                matches!(&error,ActivationError::Rejected {code:actual} if *actual == code),
                "{error}"
            );
            assert_eq!(read_state(&self.state(), 1).unwrap().audit[0].reason, code);
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn restart_preserves_high_watermark_and_original_active_bytes() {
        let f = Fixture::new();
        let p = f.policy(7);
        f.write(&p);
        let first = f.activate(500).unwrap();
        assert_eq!(first.outcome, "accepted");
        assert_eq!(f.activate(600).unwrap().outcome, "restarted");
        let mut changed = f.policy(7);
        changed.response.block_score = 99.0;
        f.write(&changed);
        f.rejection(700, "version_reuse");
        f.write(&f.policy(6));
        f.rejection(800, "version_downgrade");
        let saved = load_active_policy(&f.state()).unwrap();
        assert_eq!(saved.version, 7);
        assert_eq!(saved.response.block_score, p.response.block_score);
        let snapshot = read_state(&f.state(), 10).unwrap();
        assert_eq!(snapshot.active.unwrap().sha256, first.sha256);
        assert_eq!(snapshot.audit.len(), 4);
        assert_eq!(snapshot.audit[0].outcome, "rejected");
    }

    #[test]
    fn expiry_not_before_and_target_scope_are_checked_even_for_restart() {
        let f = Fixture::new();
        f.write(&f.policy(1));
        f.rejection(99, "not_yet_valid");
        f.activate(100).unwrap();
        f.rejection(10_000, "expired");
        let mut config = f.config.clone();
        config.host_id = "host-2".into();
        let error = activate_at(&config, &f.db, SensorKind::Notify, || 200).unwrap_err();
        assert!(matches!(
            error,
            ActivationError::Rejected {
                code: "host_target_mismatch"
            }
        ));
        config = f.config.clone();
        config.groups = vec!["database".into()];
        assert!(matches!(
            activate_at(&config, &f.db, SensorKind::Notify, || 200),
            Err(ActivationError::Rejected {
                code: "group_target_mismatch"
            })
        ));
        config = f.config.clone();
        config.policy_id = "other".into();
        assert!(matches!(
            activate_at(&config, &f.db, SensorKind::Notify, || 200),
            Err(ActivationError::Rejected {
                code: "policy_id_mismatch"
            })
        ));
    }

    #[test]
    fn key_id_is_bound_to_locally_trusted_public_key() {
        let mut f = Fixture::new();
        let mut p = f.policy(1);
        p.key_id = "forged-key-id".into();
        f.write(&p);
        f.rejection(500, "key_id_mismatch");
        p.key_id = "signer-1".into();
        f.write(&p);
        let (other_secret, other_public) = gen_keypair();
        sign_file(&f.config.path, &other_secret).unwrap();
        f.rejection(500, "invalid_signature");
        f.config
            .trusted_keys
            .insert("signer-2".into(), other_public);
        p.key_id = "signer-2".into();
        f.write(&p);
        sign_file(&f.config.path, &other_secret).unwrap();
        assert_eq!(f.activate(500).unwrap().policy.key_id, "signer-2");
    }

    #[test]
    fn invalid_configuration_does_not_consume_a_version() {
        let f = Fixture::new();
        let mut p = f.policy(1);
        p.detection.window_secs = 0;
        f.write(&p);
        f.rejection(500, "invalid_detection_response_configuration");
        assert!(read_state(&f.state(), 10).unwrap().active.is_none());
        p.detection.window_secs = 10;
        f.write(&p);
        assert_eq!(f.activate(500).unwrap().outcome, "accepted");
    }

    #[test]
    fn rollback_requires_new_version_approved_known_exact_source_and_new_approval() {
        let f = Fixture::new();
        let p1 = f.policy(1);
        f.write(&p1);
        let source = f.activate(500).unwrap();
        let mut p2 = f.policy(2);
        p2.response.block_score = 90.0;
        f.write(&p2);
        f.activate(500).unwrap();
        let mut p3 = f.policy(3);
        p3.rollback = Some(RollbackApproval {
            source_version: 1,
            source_sha256: source.sha256.clone(),
            approval_id: "CHG-42".into(),
            reason: "Restore approved configuration after regression".into(),
        });
        p3.response.block_score = 95.0;
        f.write(&p3);
        f.rejection(500, "rollback_settings_mismatch");
        p3.response = p1.response;
        p3.rollback.as_mut().unwrap().source_sha256 = "0".repeat(64);
        f.write(&p3);
        f.rejection(500, "rollback_source_hash_mismatch");
        p3.rollback.as_mut().unwrap().source_sha256 = source.sha256;
        f.write(&p3);
        assert_eq!(f.activate(500).unwrap().outcome, "rollback_accepted");
        assert_eq!(f.activate(500).unwrap().outcome, "restarted");
        p3.version = 4;
        f.write(&p3);
        f.rejection(500, "rollback_approval_reused");
        f.write(&p2);
        f.rejection(500, "version_downgrade");
        let state = read_state(&f.state(), 10).unwrap();
        assert_eq!(state.active.unwrap().version, 3);
        assert!(state.audit.iter().any(
            |a| a.outcome == "rollback_accepted" && a.approval_id.as_deref() == Some("CHG-42")
        ));
    }

    #[test]
    fn acceptance_and_audit_roll_back_together_on_storage_failure() {
        let f = Fixture::new();
        f.write(&f.policy(1));
        let connection = open_state(&f.state()).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON policy_audit BEGIN SELECT RAISE(ABORT,'test disk/audit failure'); END;").unwrap();
        assert!(f.activate(500).is_err());
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM accepted_policies", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        assert!(read_state(&f.state(), 10).unwrap().active.is_none());
        connection
            .execute_batch("DROP TRIGGER fail_audit;")
            .unwrap();
        f.activate(500).unwrap();
    }

    #[test]
    fn concurrent_different_contents_for_same_version_accept_only_one() {
        let f = Fixture::new();
        f.write(&f.policy(1));
        let other_path = f.dir.join("other.toml");
        let mut p = f.policy(1);
        p.response.block_score = 99.0;
        std::fs::write(&other_path, toml::to_string(&p).unwrap()).unwrap();
        sign_file(&other_path, &f.secret).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let threads: Vec<_> = [
            f.config.clone(),
            PolicyFileConfig {
                path: other_path,
                ..f.config.clone()
            },
        ]
        .into_iter()
        .map(|config| {
            let db = f.db.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                activate_at(&config, &db, SensorKind::Fanotify, || 500)
            })
        })
        .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "{results:?}"
        );
        assert!(results.iter().any(|r| matches!(
            r,
            Err(ActivationError::Rejected {
                code: "version_reuse"
            })
        )));
        let snapshot = read_state(&f.state(), 10).unwrap();
        assert_eq!(snapshot.audit.len(), 2);
        assert_eq!(snapshot.active.unwrap().version, 1);
    }

    #[test]
    fn concurrent_versions_never_lower_the_high_watermark() {
        let f = Fixture::new();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (1..=8)
            .map(|version| {
                let path = f.dir.join(format!("{version}.toml"));
                std::fs::write(&path, toml::to_string(&f.policy(version)).unwrap()).unwrap();
                sign_file(&path, &f.secret).unwrap();
                let config = PolicyFileConfig {
                    path,
                    ..f.config.clone()
                };
                let db = f.db.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    activate_at(&config, &db, SensorKind::Fanotify, || 500)
                })
            })
            .collect();
        for thread in threads {
            match thread.join().unwrap() {
                Ok(_)
                | Err(ActivationError::Rejected {
                    code: "version_downgrade",
                }) => {}
                other => panic!("{other:?}"),
            }
        }
        let snapshot = read_state(&f.state(), 20).unwrap();
        assert_eq!(snapshot.active.unwrap().version, 8);
        assert_eq!(snapshot.audit.len(), 8);
    }

    #[test]
    fn rejection_audit_does_not_leak_untrusted_file_contents() {
        let f = Fixture::new();
        let secret = "private-token-must-not-leak";
        std::fs::write(&f.config.path, format!("this is invalid toml {secret}")).unwrap();
        sign_file(&f.config.path, &f.secret).unwrap();
        f.rejection(500, "invalid_policy_format");
        let json = serde_json::to_string(&read_state(&f.state(), 10).unwrap()).unwrap();
        assert!(!json.contains(secret));
        let path = f.dir.join("absent/state.sqlite3");
        assert!(read_state(&path, 5).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn legacy_metadata_cannot_activate_and_signing_still_works() {
        let f = Fixture::new();
        std::fs::write(
            &f.config.path,
            "version = 7\n[detection]\nwindow_secs = 10\n",
        )
        .unwrap();
        sign_file(&f.config.path, &f.secret).unwrap();
        assert_eq!(
            crate::load_verified(&f.config.path, &f.config.trusted_keys["signer-1"])
                .unwrap()
                .version,
            7
        );
        f.rejection(500, "invalid_policy_metadata");
        let mut config = f.config.clone();
        config.pubkey = config.trusted_keys["signer-1"].clone();
        config.trusted_keys.clear();
        assert!(matches!(
            activate_at(&config, &f.db, SensorKind::Fanotify, || 500),
            Err(ActivationError::Rejected {
                code: "invalid_local_trusted_keys"
            })
        ));
    }

    #[test]
    fn trusted_preview_does_not_create_or_advance_state() {
        let f = Fixture::new();
        let mut policy = f.policy(5);
        policy.expires_at_ms = i64::MAX as u64;
        f.write(&policy);
        assert_eq!(
            load_trusted(&f.config, SensorKind::Fanotify)
                .unwrap()
                .version,
            5
        );
        assert!(!f.state().exists());
        f.activate(500).unwrap();
        policy.version = 4;
        f.write(&policy);
        // This API deliberately validates trust, not replay acceptance.
        assert_eq!(
            load_trusted(&f.config, SensorKind::Fanotify)
                .unwrap()
                .version,
            4
        );
        assert_eq!(
            read_state(&f.state(), 10).unwrap().active.unwrap().version,
            5
        );
        f.rejection(500, "version_downgrade");
    }

    #[test]
    fn audit_history_is_bounded_without_pruning_accepted_sources() {
        let f = Fixture::new();
        f.write(&f.policy(1));
        f.activate(500).unwrap();
        let connection = Connection::open(f.state()).unwrap();
        connection.execute_batch("WITH RECURSIVE counter(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM counter WHERE n<10010) INSERT INTO policy_audit(timestamp_ms,outcome,reason) SELECT 500,'rejected','test' FROM counter;").unwrap();
        f.activate(600).unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM policy_audit", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, MAX_AUDIT_ROWS);
        assert_eq!(load_active_policy(&f.state()).unwrap().version, 1);
        assert_eq!(read_state(&f.state(), 10_000).unwrap().audit.len(), 1000);
    }

    #[cfg(unix)]
    #[test]
    fn policy_symlinks_directories_and_fifos_are_rejected_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let f = Fixture::new();
        let target = f.dir.join("real-policy");
        std::fs::write(&target, "version = 1").unwrap();
        std::os::unix::fs::symlink(&target, &f.config.path).unwrap();
        f.rejection(500, "policy_read_failed");
        std::fs::remove_file(&f.config.path).unwrap();
        std::fs::create_dir(&f.config.path).unwrap();
        f.rejection(500, "policy_read_failed");
        std::fs::remove_dir(&f.config.path).unwrap();
        let path = std::ffi::CString::new(f.config.path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        f.rejection(500, "policy_read_failed");
    }

    #[cfg(unix)]
    #[test]
    fn state_directory_and_database_are_private_and_symlinks_are_rejected() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let f = Fixture::new();
        f.write(&f.policy(1));
        f.activate(500).unwrap();
        assert_eq!(std::fs::metadata(f.state()).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(f.state().parent().unwrap())
                .unwrap()
                .mode()
                & 0o777,
            0o700
        );
        std::fs::set_permissions(f.state(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            f.activate(500),
            Err(ActivationError::UnsafeStatePath)
        ));
        std::fs::set_permissions(f.state(), std::fs::Permissions::from_mode(0o600)).unwrap();
        let renamed = f.state().with_extension("real");
        std::fs::rename(f.state(), &renamed).unwrap();
        std::os::unix::fs::symlink(&renamed, f.state()).unwrap();
        assert!(matches!(
            f.activate(500),
            Err(ActivationError::UnsafeStatePath)
        ));
    }
}
