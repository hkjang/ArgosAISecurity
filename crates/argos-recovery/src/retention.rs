//! Incident retention is independent of recovery trust. Local access to the backup
//! database is the authorization boundary: approver labels record an operator's
//! approval, not an authenticated remote RBAC decision. Append-only SQL history
//! prevents ordinary API mutation; it is not tamper-proof against the host owner.
use super::{BackupStore, RecoveryError};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::path::{Component, Path};

#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionPin {
    pub id: i64,
    pub incident_id: String,
    pub version_id: i64,
    pub path: String,
    pub hash: String,
    pub actor: String,
    pub reason: String,
    pub pinned_at_ms: u64,
    pub released_at_ms: Option<u64>,
    pub release_approval_id: Option<String>,
    pub released_by: Option<String>,
    pub release_reason: Option<String>,
}

/// The caller must obtain a separate approval. The named approver must differ
/// from each original pin actor, and an approval ID can authorize only one call.
#[derive(Debug, Clone)]
pub struct ReleaseApproval {
    pub approval_id: String,
    pub approver: String,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionAuditEntry {
    pub id: i64,
    pub pin_id: i64,
    pub incident_id: String,
    pub version_id: i64,
    pub path: String,
    pub hash: String,
    pub action: String,
    pub actor: String,
    pub reason: String,
    pub timestamp_ms: u64,
    pub approval_id: Option<String>,
}

const PIN_COLUMNS: &str = "id, incident_id, version_id, path, hash, actor, reason, pinned_at_ms,
    released_at_ms, release_approval_id, released_by, release_reason";

pub(super) fn migrate(conn: &Connection) -> Result<(), RecoveryError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS retention_pins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            version_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            hash TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            pinned_at_ms INTEGER NOT NULL,
            released_at_ms INTEGER,
            release_approval_id TEXT,
            released_by TEXT,
            release_reason TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS retention_active_reference
            ON retention_pins(incident_id, version_id) WHERE released_at_ms IS NULL;
        CREATE INDEX IF NOT EXISTS retention_versions ON retention_pins(version_id, released_at_ms);
        CREATE TABLE IF NOT EXISTS retention_approvals (
            approval_id TEXT PRIMARY KEY,
            approver TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS retention_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pin_id INTEGER NOT NULL,
            incident_id TEXT NOT NULL,
            version_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            hash TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('pinned', 'released')),
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp_ms INTEGER NOT NULL,
            approval_id TEXT
        );
        CREATE INDEX IF NOT EXISTS retention_audit_incident ON retention_audit(incident_id, id);
        CREATE TRIGGER IF NOT EXISTS retention_prevent_pinned_delete
            BEFORE DELETE ON versions WHEN EXISTS (
                SELECT 1 FROM retention_pins WHERE version_id = OLD.id AND released_at_ms IS NULL
            ) BEGIN SELECT RAISE(ABORT, 'active incident retention'); END;
        CREATE TRIGGER IF NOT EXISTS retention_audit_no_update BEFORE UPDATE ON retention_audit
            BEGIN SELECT RAISE(ABORT, 'retention audit is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS retention_audit_no_delete BEFORE DELETE ON retention_audit
            BEGIN SELECT RAISE(ABORT, 'retention audit is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS retention_approvals_no_update BEFORE UPDATE ON retention_approvals
            BEGIN SELECT RAISE(ABORT, 'retention approvals are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS retention_approvals_no_delete BEFORE DELETE ON retention_approvals
            BEGIN SELECT RAISE(ABORT, 'retention approvals are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS retention_pins_no_delete BEFORE DELETE ON retention_pins
            BEGIN SELECT RAISE(ABORT, 'retention history cannot be deleted'); END;
        CREATE TRIGGER IF NOT EXISTS retention_pins_immutable BEFORE UPDATE ON retention_pins
            WHEN OLD.released_at_ms IS NOT NULL OR NEW.id != OLD.id OR NEW.incident_id != OLD.incident_id
            OR NEW.version_id != OLD.version_id OR NEW.path != OLD.path OR NEW.hash != OLD.hash
            OR NEW.actor != OLD.actor OR NEW.reason != OLD.reason OR NEW.pinned_at_ms != OLD.pinned_at_ms
            BEGIN SELECT RAISE(ABORT, 'retention pin history is immutable'); END;",
    )?;
    Ok(())
}

impl BackupStore {
    /// Preserve an explicit version as evidence. This does not mark it known-good.
    /// Repeating an active incident/version pair returns the original pin unchanged.
    pub fn pin_version(
        &self,
        path: &Path,
        version_id: i64,
        incident_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<RetentionPin, RecoveryError> {
        validate_request(path, incident_id, actor, reason)?;
        if version_id <= 0 {
            return Err(RecoveryError::InvalidRetention(
                "version_id must be positive".into(),
            ));
        }
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let version = self.version(path, version_id)?;
        let pin = self.pin_in_transaction(&version, incident_id, actor.trim(), reason.trim())?;
        transaction.commit()?;
        Ok(pin)
    }

    /// Atomically preserve all known-good versions of this exact path strictly
    /// before the incident. No matching version is an error, not successful coverage.
    pub fn pin_known_good_before(
        &self,
        path: &Path,
        before_ms: u64,
        incident_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<Vec<RetentionPin>, RecoveryError> {
        validate_request(path, incident_id, actor, reason)?;
        if before_ms > i64::MAX as u64 {
            return Err(RecoveryError::InvalidRetention(
                "incident timestamp exceeds database range".into(),
            ));
        }
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let versions: Vec<_> = self
            .versions(path)?
            .into_iter()
            .filter(|version| version.known_good && version.timestamp_ms < before_ms)
            .collect();
        if versions.is_empty() {
            return Err(RecoveryError::NoTrustedVersion(path.display().to_string()));
        }
        let pins = versions
            .iter()
            .map(|version| {
                self.pin_in_transaction(version, incident_id, actor.trim(), reason.trim())
            })
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit()?;
        Ok(pins)
    }

    fn pin_in_transaction(
        &self,
        version: &super::BackupVersion,
        incident_id: &str,
        actor: &str,
        reason: &str,
    ) -> Result<RetentionPin, RecoveryError> {
        let existing = self.conn.query_row(
            &format!("SELECT {PIN_COLUMNS} FROM retention_pins WHERE incident_id = ?1 AND version_id = ?2 AND released_at_ms IS NULL"),
            params![incident_id, version.id], map_pin,
        ).optional()?;
        if let Some(pin) = existing {
            return Ok(pin);
        }
        let timestamp = now_ms();
        self.conn.execute(
            "INSERT INTO retention_pins(incident_id, version_id, path, hash, actor, reason, pinned_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![incident_id, version.id, version.path, version.hash, actor, reason, timestamp],
        )?;
        let pin = self.get_pin(self.conn.last_insert_rowid())?;
        self.append_retention_audit(&pin, "pinned", actor, reason, timestamp, None)?;
        Ok(pin)
    }

    /// List current incident references; include released references when requested.
    pub fn retention_pins(
        &self,
        incident_id: Option<&str>,
        include_released: bool,
    ) -> Result<Vec<RetentionPin>, RecoveryError> {
        if let Some(id) = incident_id {
            validate_id(id)?;
        }
        let mut statement = self.conn.prepare(&format!(
            "SELECT {PIN_COLUMNS} FROM retention_pins WHERE (?1 IS NULL OR incident_id = ?1)
             AND (?2 OR released_at_ms IS NULL) ORDER BY id"
        ))?;
        let pins = statement
            .query_map(params![incident_id, include_released], map_pin)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(pins)
    }

    /// Append-only pin/release history, including the original path/hash after prune.
    pub fn retention_audit(
        &self,
        incident_id: Option<&str>,
    ) -> Result<Vec<RetentionAuditEntry>, RecoveryError> {
        if let Some(id) = incident_id {
            validate_id(id)?;
        }
        let mut statement = self.conn.prepare(
            "SELECT id, pin_id, incident_id, version_id, path, hash, action, actor, reason,
                    timestamp_ms, approval_id FROM retention_audit
             WHERE (?1 IS NULL OR incident_id = ?1) ORDER BY id",
        )?;
        let rows = statement
            .query_map(params![incident_id], |row| {
                Ok(RetentionAuditEntry {
                    id: row.get(0)?,
                    pin_id: row.get(1)?,
                    incident_id: row.get(2)?,
                    version_id: row.get(3)?,
                    path: row.get(4)?,
                    hash: row.get(5)?,
                    action: row.get(6)?,
                    actor: row.get(7)?,
                    reason: row.get(8)?,
                    timestamp_ms: row.get(9)?,
                    approval_id: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Release only this reference. Other incidents continue to preserve the version.
    pub fn release_pin(
        &self,
        pin_id: i64,
        approval: &ReleaseApproval,
    ) -> Result<RetentionPin, RecoveryError> {
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let pin = self.get_pin(pin_id)?;
        if pin.released_at_ms.is_some() {
            return Err(RecoveryError::InvalidReleaseApproval(
                "reference has already been released".into(),
            ));
        }
        self.record_approval(std::slice::from_ref(&pin), approval)?;
        let result = self.release_in_transaction(&pin, approval)?;
        transaction.commit()?;
        Ok(result)
    }

    /// Release every active reference for an incident as one approved transaction.
    pub fn release_incident(
        &self,
        incident_id: &str,
        approval: &ReleaseApproval,
    ) -> Result<Vec<RetentionPin>, RecoveryError> {
        validate_id(incident_id)?;
        let transaction = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let pins = self.retention_pins(Some(incident_id), false)?;
        if pins.is_empty() {
            return Err(RecoveryError::NotFound(format!(
                "active retention for incident {incident_id}"
            )));
        }
        self.record_approval(&pins, approval)?;
        let results = pins
            .iter()
            .map(|pin| self.release_in_transaction(pin, approval))
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit()?;
        Ok(results)
    }

    fn record_approval(
        &self,
        pins: &[RetentionPin],
        approval: &ReleaseApproval,
    ) -> Result<(), RecoveryError> {
        let validate = || -> Result<(), RecoveryError> {
            validate_id(&approval.approval_id)?;
            validate_text(&approval.approver, "approver", 256)?;
            validate_text(&approval.reason, "approval reason", 4096)?;
            if pins.iter().any(|pin| pin.actor == approval.approver.trim()) {
                return Err(RecoveryError::InvalidReleaseApproval(
                    "approver must differ from the original pin actor".into(),
                ));
            }
            let used: bool = self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM retention_approvals WHERE approval_id = ?1)",
                params![approval.approval_id],
                |row| row.get(0),
            )?;
            if used {
                return Err(RecoveryError::InvalidReleaseApproval(
                    "approval ID was already used".into(),
                ));
            }
            Ok(())
        };
        validate().map_err(|error| match error {
            RecoveryError::InvalidRetention(message) => {
                RecoveryError::InvalidReleaseApproval(message)
            }
            error => error,
        })?;
        self.conn.execute("INSERT INTO retention_approvals(approval_id, approver, reason, timestamp_ms) VALUES (?1, ?2, ?3, ?4)",
            params![approval.approval_id, approval.approver.trim(), approval.reason.trim(), now_ms()])?;
        Ok(())
    }

    fn release_in_transaction(
        &self,
        pin: &RetentionPin,
        approval: &ReleaseApproval,
    ) -> Result<RetentionPin, RecoveryError> {
        let timestamp = now_ms();
        self.conn.execute(
            "UPDATE retention_pins SET released_at_ms = ?1, release_approval_id = ?2,
            released_by = ?3, release_reason = ?4 WHERE id = ?5 AND released_at_ms IS NULL",
            params![
                timestamp,
                approval.approval_id,
                approval.approver.trim(),
                approval.reason.trim(),
                pin.id
            ],
        )?;
        self.append_retention_audit(
            pin,
            "released",
            approval.approver.trim(),
            approval.reason.trim(),
            timestamp,
            Some(&approval.approval_id),
        )?;
        self.get_pin(pin.id)
    }

    fn append_retention_audit(
        &self,
        pin: &RetentionPin,
        action: &str,
        actor: &str,
        reason: &str,
        timestamp: i64,
        approval_id: Option<&str>,
    ) -> Result<(), RecoveryError> {
        self.conn.execute("INSERT INTO retention_audit(pin_id, incident_id, version_id, path, hash, action, actor, reason, timestamp_ms, approval_id)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![pin.id, pin.incident_id, pin.version_id, pin.path, pin.hash, action, actor, reason, timestamp, approval_id])?;
        Ok(())
    }

    fn get_pin(&self, id: i64) -> Result<RetentionPin, RecoveryError> {
        self.conn
            .query_row(
                &format!("SELECT {PIN_COLUMNS} FROM retention_pins WHERE id = ?1"),
                params![id],
                map_pin,
            )
            .optional()?
            .ok_or_else(|| RecoveryError::NotFound(format!("retention reference {id}")))
    }
}

fn map_pin(row: &rusqlite::Row<'_>) -> rusqlite::Result<RetentionPin> {
    Ok(RetentionPin {
        id: row.get(0)?,
        incident_id: row.get(1)?,
        version_id: row.get(2)?,
        path: row.get(3)?,
        hash: row.get(4)?,
        actor: row.get(5)?,
        reason: row.get(6)?,
        pinned_at_ms: row.get(7)?,
        released_at_ms: row.get(8)?,
        release_approval_id: row.get(9)?,
        released_by: row.get(10)?,
        release_reason: row.get(11)?,
    })
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn validate_id(value: &str) -> Result<(), RecoveryError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':'))
    {
        return Err(RecoveryError::InvalidRetention(
            "IDs must be 1..128 ASCII letters, digits, '-', '_' or ':'; paths are not IDs".into(),
        ));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str, max: usize) -> Result<(), RecoveryError> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(RecoveryError::InvalidRetention(format!(
            "{field} must be nonempty, at most {max} bytes, without control characters"
        )));
    }
    Ok(())
}

fn validate_request(
    path: &Path,
    incident_id: &str,
    actor: &str,
    reason: &str,
) -> Result<(), RecoveryError> {
    validate_id(incident_id)?;
    validate_text(actor, "actor", 256)?;
    validate_text(reason, "reason", 4096)?;
    if path.to_str().is_none_or(str::is_empty)
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || path
            .to_str()
            .is_some_and(|value| value.chars().any(char::is_control))
    {
        return Err(RecoveryError::InvalidRetention(
            "path must name a UTF-8 file without '..' or control characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn fixture(tag: &str) -> (PathBuf, BackupStore, PathBuf, i64) {
        let dir = std::env::temp_dir().join(format!("argos-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let path = dir.join("document.txt");
        fs::write(&path, "original").unwrap();
        store.backup(&path, 1000, 7).unwrap();
        let id = store.versions(&path).unwrap()[0].id;
        (dir, store, path, id)
    }

    fn approval(id: &str) -> ReleaseApproval {
        ReleaseApproval {
            approval_id: id.into(),
            approver: "reviewer".into(),
            reason: "case closed after recovery verification".into(),
        }
    }

    #[test]
    fn independent_incidents_survive_trust_revocation_prune_zero_and_reopen() {
        let (dir, store, path, id) = fixture("retention-incidents");
        store.mark_known_good(&path, id, "verified").unwrap();
        let first = store
            .pin_known_good_before(&path, 2000, "INC-1", "sensor", "suspected encryption")
            .unwrap();
        let second = store
            .pin_version(&path, id, "INC-2", "analyst", "related investigation")
            .unwrap();
        store
            .revoke_known_good(&path, id, "content now suspect")
            .unwrap();
        assert_eq!(store.prune(0).unwrap(), 0);
        assert!(!store.versions(&path).unwrap()[0].known_good);
        drop(store);
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        assert_eq!(store.retention_pins(None, false).unwrap().len(), 2);
        assert_eq!(store.retention_audit(None).unwrap().len(), 2);
        store
            .release_pin(first[0].id, &approval("APPROVAL-1"))
            .unwrap();
        assert_eq!(store.prune(0).unwrap(), 0);
        assert_eq!(store.retention_pins(None, false).unwrap()[0].id, second.id);
        store
            .release_incident("INC-2", &approval("APPROVAL-2"))
            .unwrap();
        assert_eq!(store.prune(0).unwrap(), 1);
        assert!(store.versions(&path).unwrap().is_empty());
        let audit = store.retention_audit(None).unwrap();
        assert_eq!(audit.len(), 4);
        assert_eq!(audit[3].approval_id.as_deref(), Some("APPROVAL-2"));
        assert_eq!(audit[0].path, path.to_str().unwrap());
        assert_eq!(audit[0].hash, audit[3].hash);
        assert_eq!(store.retention_pins(None, true).unwrap().len(), 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pinning_untrusted_evidence_does_not_authorize_restore() {
        let (dir, store, path, id) = fixture("retention-untrusted");
        store
            .pin_version(&path, id, "INC-3", "analyst", "evidence")
            .unwrap();
        assert_eq!(store.prune(0).unwrap(), 0);
        fs::write(&path, "current suspect file").unwrap();
        assert!(matches!(
            store.restore(&path, None),
            Err(RecoveryError::NoTrustedVersion(_))
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), "current suspect file");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn only_known_good_versions_strictly_before_incident_are_selected() {
        let (dir, store, path, first) = fixture("retention-cutoff");
        store
            .mark_known_good(&path, first, "verified first")
            .unwrap();
        fs::write(&path, "second").unwrap();
        store.backup(&path, 2000, 7).unwrap();
        let second = store.versions(&path).unwrap()[0].id;
        store
            .mark_known_good(&path, second, "verified second")
            .unwrap();
        fs::write(&path, "unreviewed").unwrap();
        store.backup(&path, 2500, 7).unwrap();
        fs::write(&path, "at incident").unwrap();
        store.backup(&path, 3000, 7).unwrap();
        let newest = store.versions(&path).unwrap()[0].id;
        store
            .mark_known_good(&path, newest, "verified newest")
            .unwrap();
        let pins = store
            .pin_known_good_before(&path, 3000, "INC-4", "sensor", "detection")
            .unwrap();
        assert_eq!(
            pins.iter().map(|pin| pin.version_id).collect::<Vec<_>>(),
            vec![second, first]
        );
        assert!(matches!(
            store.pin_known_good_before(&path, 1000, "INC-5", "sensor", "detection"),
            Err(RecoveryError::NoTrustedVersion(_))
        ));
        let repeated = store
            .pin_version(&path, first, "INC-4", "other", "repeat")
            .unwrap();
        assert_eq!(repeated.actor, "sensor");
        assert_eq!(store.retention_audit(None).unwrap().len(), 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn approval_is_required_distinct_and_not_reusable() {
        let (dir, store, path, id) = fixture("retention-approval");
        let pin = store
            .pin_version(&path, id, "INC-6", "analyst", "evidence")
            .unwrap();
        for invalid in [
            ReleaseApproval {
                approval_id: "".into(),
                ..approval("unused")
            },
            ReleaseApproval {
                approver: "".into(),
                ..approval("unused")
            },
            ReleaseApproval {
                reason: "  ".into(),
                ..approval("unused")
            },
            ReleaseApproval {
                approver: "analyst".into(),
                ..approval("unused")
            },
        ] {
            assert!(matches!(
                store.release_pin(pin.id, &invalid),
                Err(RecoveryError::InvalidReleaseApproval(_))
            ));
        }
        assert_eq!(store.retention_audit(None).unwrap().len(), 1);
        store.release_pin(pin.id, &approval("APPROVAL-6")).unwrap();
        let repinned = store
            .pin_version(&path, id, "INC-6", "analyst", "new investigation")
            .unwrap();
        assert_ne!(pin.id, repinned.id);
        assert!(store
            .release_pin(repinned.id, &approval("APPROVAL-6"))
            .is_err());
        assert_eq!(store.retention_pins(None, false).unwrap().len(), 1);
        assert!(store.release_pin(pin.id, &approval("APPROVAL-7")).is_err());
        assert!(store
            .release_incident("missing", &approval("APPROVAL-8"))
            .is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn incident_release_is_atomic_when_an_approver_is_a_pin_actor() {
        let (dir, store, path, first) = fixture("retention-atomic");
        store
            .pin_version(&path, first, "INC-7", "analyst", "evidence")
            .unwrap();
        fs::write(&path, "second").unwrap();
        store.backup(&path, 2000, 7).unwrap();
        let second = store.versions(&path).unwrap()[0].id;
        store
            .pin_version(&path, second, "INC-7", "reviewer", "evidence")
            .unwrap();
        assert!(store
            .release_incident("INC-7", &approval("APPROVAL-9"))
            .is_err());
        assert_eq!(store.retention_pins(None, false).unwrap().len(), 2);
        assert_eq!(store.retention_audit(None).unwrap().len(), 2);
        let released = store
            .release_incident(
                "INC-7",
                &ReleaseApproval {
                    approver: "second-reviewer".into(),
                    ..approval("APPROVAL-9")
                },
            )
            .unwrap();
        assert_eq!(released.len(), 2);
        assert_eq!(store.retention_audit(None).unwrap().len(), 4);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn history_is_append_only_and_records_survive_version_deletion() {
        let (dir, store, path, id) = fixture("retention-audit");
        let pin = store
            .pin_version(&path, id, "INC-8", "analyst", "evidence")
            .unwrap();
        assert!(store
            .conn
            .execute("DELETE FROM versions WHERE id = ?1", params![id])
            .is_err());
        assert!(store
            .conn
            .execute("DELETE FROM retention_audit", [])
            .is_err());
        assert!(store
            .conn
            .execute("UPDATE retention_audit SET reason = 'changed'", [])
            .is_err());
        assert!(store
            .conn
            .execute("UPDATE retention_pins SET actor = 'changed'", [])
            .is_err());
        store.release_pin(pin.id, &approval("APPROVAL-10")).unwrap();
        assert!(store
            .conn
            .execute("UPDATE retention_pins SET released_by = 'changed'", [])
            .is_err());
        assert!(store
            .conn
            .execute("DELETE FROM retention_approvals", [])
            .is_err());
        assert_eq!(store.prune(0).unwrap(), 1);
        assert_eq!(store.retention_audit(None).unwrap().len(), 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_versions_and_invalid_ids_cannot_silently_create_pins() {
        let (dir, store, path, id) = fixture("retention-validation");
        for invalid in ["", "../INC", "a/b", "a\\b", "has space", "line\nfeed"] {
            assert!(store
                .pin_version(&path, id, invalid, "analyst", "evidence")
                .is_err());
        }
        assert!(store
            .pin_version(&path, id, "INC-9", "", "evidence")
            .is_err());
        assert!(store
            .pin_version(&path, id, "INC-9", "analyst", "")
            .is_err());
        assert!(store
            .pin_version(&path, -1, "INC-9", "analyst", "evidence")
            .is_err());
        assert!(store
            .pin_version(&path, id + 999, "INC-9", "analyst", "evidence")
            .is_err());
        assert!(store
            .pin_version(&dir.join("other"), id, "INC-9", "analyst", "evidence")
            .is_err());
        assert!(store
            .pin_version(Path::new(""), id, "INC-9", "analyst", "evidence")
            .is_err());
        assert!(store
            .pin_version(Path::new("../file"), id, "INC-9", "analyst", "evidence")
            .is_err());
        assert!(store.retention_pins(None, false).unwrap().is_empty());
        assert!(store.retention_audit(None).unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_pin_and_prune_are_serialized_without_dangling_pins() {
        let (dir, store, path, id) = fixture("retention-concurrent");
        let other = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let pin_barrier = barrier.clone();
        let pin_path = path.clone();
        let pinning = std::thread::spawn(move || {
            pin_barrier.wait();
            other.pin_version(&pin_path, id, "INC-race", "analyst", "evidence")
        });
        barrier.wait();
        let removed = store.prune(0).unwrap();
        match pinning.join().unwrap() {
            Ok(_) => {
                assert_eq!(removed, 0);
                assert_eq!(store.versions(&path).unwrap().len(), 1);
                assert_eq!(store.retention_pins(None, false).unwrap().len(), 1);
            }
            Err(RecoveryError::NotFound(_)) => {
                assert_eq!(removed, 1);
                assert!(store.retention_pins(None, false).unwrap().is_empty());
            }
            Err(error) => panic!("unexpected pin result: {error}"),
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
