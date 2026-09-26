//! Argos Recovery: 내용 백업과 검증된 정상 복구 지점 (요건서 10장).
//!
//! 설계:
//! - 내용 주소 저장(content-addressed): 파일 내용의 SHA-256을 키로
//!   `<backup_dir>/objects/<해시 앞2자리>/<해시>` 에 저장. 같은 내용은 한 번만 저장된다.
//! - 버전 메타데이터(경로, 해시, 크기, 시각, 원인 pid)는 SQLite 인덱스에 기록.
//! - 해시 무결성과 운영자의 정상본 판정은 별도 상태다. 자동 백업은 미검토로 저장한다.
//! - 복구는 명시적으로 정상 판정된 버전만 선택하며, 미검토 버전은 별도 경로에서 미리 본다.
//! - 사고별 보존 고정은 정상본 판정과 독립적이다. 모든 사고 참조를 승인 해제해야 정리가 가능하다.
//! - 승인자 기록은 로컬 운영자의 승인 이력이다. 접근 권한은 저장소 파일 권한으로 통제하며,
//!   원격 사용자 인증이나 호스트 관리자에 대한 변조 방지 저장소를 제공하지 않는다.

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

mod retention;
pub use retention::{ReleaseApproval, RetentionAuditEntry, RetentionPin};

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("IO 오류 ({path}): {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("인덱스 DB 오류: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("백업본이 없습니다: {0}")]
    NotFound(String),
    #[error("선택 범위에 정상 판정된 복구 지점이 없습니다: {0}; 미리보기 후 정상본을 지정하세요")]
    NoTrustedVersion(String),
    #[error("정상본 판정 또는 취소에는 근거가 필요합니다")]
    MissingTrustNote,
    #[error("잘못된 백업 메타데이터: {0}")]
    InvalidMetadata(String),
    #[error("미리보기 경로는 원본 및 백업 저장소와 분리된 새 경로여야 합니다: {0}")]
    UnsafePreview(String),
    #[error("복구 대상은 일반 파일 또는 존재하지 않는 경로여야 합니다: {0}")]
    UnsafeRestoreTarget(String),
    #[error("무결성 검증 실패: 기대 해시 {expected}, 실제 {actual}")]
    IntegrityMismatch { expected: String, actual: String },
    #[error("파일이 백업 크기 제한({limit} bytes)을 초과합니다: {size} bytes")]
    TooLarge { size: u64, limit: u64 },
    #[error("잘못된 사고 보존 요청: {0}")]
    InvalidRetention(String),
    #[error("사고 보존 해제 승인 거부: {0}")]
    InvalidReleaseApproval(String),
}

fn io_err(path: &Path, source: std::io::Error) -> RecoveryError {
    RecoveryError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// 한 파일 버전의 메타데이터.
#[derive(Debug, Clone)]
pub struct BackupVersion {
    pub id: i64,
    pub path: String,
    pub hash: String,
    pub size: u64,
    pub timestamp_ms: u64,
    pub pid: u32,
    /// 해시 일치 여부와 무관한, 운영자가 명시적으로 기록한 정상본 판정.
    pub known_good: bool,
    pub trust_note: Option<String>,
}

/// 실제 백업 시도와 복구 시험으로 확인된 경로별 상태. 아직 관측하지 않은 파일은 포함하지 않는다.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecoveryPathReadiness {
    pub path: String,
    pub version_count: u64,
    pub known_good_versions: u64,
    pub latest_backup_ms: Option<u64>,
    pub latest_known_good_ms: Option<u64>,
    pub oversized_skips: u64,
    pub last_restore_test_ms: Option<u64>,
    pub last_restore_test_ok: Option<bool>,
    pub last_restore_test_error: Option<String>,
}

pub struct BackupStore {
    dir: PathBuf,
    conn: Connection,
    /// 이 크기를 넘는 파일은 백업하지 않는다 (저장소 증가 리스크 대응).
    pub max_file_bytes: u64,
}

impl BackupStore {
    pub fn open(dir: &Path, max_file_bytes: u64) -> Result<Self, RecoveryError> {
        fs::create_dir_all(dir.join("objects")).map_err(|e| io_err(dir, e))?;
        let mut conn = Connection::open(dir.join("index.db"))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // 동시에 CLI와 에이전트가 열어도 메타데이터 마이그레이션이 중복되지 않는다.
        let migration = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        migration.execute_batch(
            "CREATE TABLE IF NOT EXISTS versions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                path         TEXT NOT NULL,
                hash         TEXT NOT NULL,
                size         INTEGER NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                pid          INTEGER NOT NULL,
                known_good   INTEGER NOT NULL DEFAULT 0,
                trust_note   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_versions_path ON versions(path, timestamp_ms);
            CREATE TABLE IF NOT EXISTS recovery_status (
                path TEXT PRIMARY KEY,
                oversized_skips INTEGER NOT NULL DEFAULT 0,
                last_restore_test_ms INTEGER,
                last_restore_test_ok INTEGER,
                last_restore_test_error TEXT
            );",
        )?;
        let columns: Vec<String> = {
            let mut stmt = migration.prepare("PRAGMA table_info(versions)")?;
            let rows = stmt.query_map([], |row| row.get(1))?;
            rows.collect::<Result<_, _>>()?
        };
        // 이전 DB의 정상 여부는 추론하지 않는다. 모든 기존 버전은 미검토 상태로 보존.
        if !columns.iter().any(|c| c == "known_good") {
            migration.execute_batch(
                "ALTER TABLE versions ADD COLUMN known_good INTEGER NOT NULL DEFAULT 0;",
            )?;
        }
        if !columns.iter().any(|c| c == "trust_note") {
            migration.execute_batch("ALTER TABLE versions ADD COLUMN trust_note TEXT;")?;
        }
        retention::migrate(&migration)?;
        migration.commit()?;
        Ok(Self {
            dir: dir.to_path_buf(),
            conn,
            max_file_bytes,
        })
    }

    fn object_path(&self, hash: &str) -> PathBuf {
        self.dir.join("objects").join(&hash[..2]).join(hash)
    }

    /// 파일의 현재 내용을 백업한다. 직전 버전과 해시가 같으면 건너뛴다.
    /// 반환값: 새 버전이 기록되면 Some(hash), 중복·스킵이면 None.
    pub fn backup(
        &self,
        path: &Path,
        timestamp_ms: u64,
        pid: u32,
    ) -> Result<Option<String>, RecoveryError> {
        let meta = fs::metadata(path).map_err(|e| io_err(path, e))?;
        if !meta.is_file() {
            return Ok(None);
        }
        if meta.len() > self.max_file_bytes {
            self.record_oversized_skip(path)?;
            return Err(RecoveryError::TooLarge {
                size: meta.len(),
                limit: self.max_file_bytes,
            });
        }

        // stat 이후 파일이 커져도 읽기 예산을 넘지 않는다.
        let mut data = Vec::new();
        fs::File::open(path)
            .and_then(|f| {
                f.take(self.max_file_bytes.saturating_add(1))
                    .read_to_end(&mut data)
            })
            .map_err(|e| io_err(path, e))?;
        if data.len() as u64 > self.max_file_bytes {
            self.record_oversized_skip(path)?;
            return Err(RecoveryError::TooLarge {
                size: data.len() as u64,
                limit: self.max_file_bytes,
            });
        }
        let hash = hex::encode(Sha256::digest(&data));
        let path_str = path.to_string_lossy().into_owned();

        // 객체 저장과 인덱스 기록 사이에 보존 정리가 객체를 삭제하지 않도록 직렬화한다.
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.conn,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        // 직전 버전과 동일 내용이면 기록하지 않는다.
        let last: Option<String> = self
            .conn
            .query_row(
                "SELECT hash FROM versions WHERE path = ?1 ORDER BY id DESC LIMIT 1",
                params![path_str],
                |r| r.get(0),
            )
            .optional()?;
        if last.as_deref() == Some(hash.as_str()) {
            return Ok(None);
        }

        let obj = self.object_path(&hash);
        if !obj.exists() {
            if let Some(parent) = obj.parent() {
                fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
            }
            let (tmp, mut file) = create_restore_temp(&obj)?;
            let write_result = file.write_all(&data).and_then(|_| file.sync_all());
            drop(file);
            if let Err(error) = write_result {
                let _ = fs::remove_file(&tmp);
                return Err(io_err(&tmp, error));
            }
            if let Err(error) = fs::rename(&tmp, &obj) {
                let _ = fs::remove_file(&tmp);
                return Err(io_err(&obj, error));
            }
        }

        self.conn.execute(
            "INSERT INTO versions (path, hash, size, timestamp_ms, pid)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![path_str, hash, data.len() as i64, timestamp_ms as i64, pid],
        )?;
        transaction.commit()?;
        Ok(Some(hash))
    }

    fn record_oversized_skip(&self, path: &Path) -> Result<(), RecoveryError> {
        self.conn.execute(
            "INSERT INTO recovery_status(path, oversized_skips) VALUES (?1, 1)
             ON CONFLICT(path) DO UPDATE SET oversized_skips = oversized_skips + 1",
            params![path.to_string_lossy().into_owned()],
        )?;
        Ok(())
    }

    /// 경로별 정상 복구 지점, 크기 제한 제외, 마지막 복구 시험 결과를 조회한다.
    pub fn readiness(&self) -> Result<Vec<RecoveryPathReadiness>, RecoveryError> {
        let mut statement = self.conn.prepare(
            "WITH paths AS (SELECT path FROM versions UNION SELECT path FROM recovery_status),
             backups AS (
                SELECT path, COUNT(*) AS version_count, SUM(known_good) AS known_good_versions,
                       MAX(timestamp_ms) AS latest_backup_ms,
                       MAX(CASE WHEN known_good = 1 THEN timestamp_ms END) AS latest_known_good_ms
                FROM versions GROUP BY path
             )
             SELECT paths.path, COALESCE(backups.version_count, 0), COALESCE(backups.known_good_versions, 0),
                    backups.latest_backup_ms, backups.latest_known_good_ms,
                    COALESCE(recovery_status.oversized_skips, 0), recovery_status.last_restore_test_ms,
                    recovery_status.last_restore_test_ok, recovery_status.last_restore_test_error
             FROM paths LEFT JOIN backups USING(path) LEFT JOIN recovery_status USING(path)
             ORDER BY paths.path",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(RecoveryPathReadiness {
                path: row.get(0)?,
                version_count: row.get(1)?,
                known_good_versions: row.get(2)?,
                latest_backup_ms: row.get(3)?,
                latest_known_good_ms: row.get(4)?,
                oversized_skips: row.get(5)?,
                last_restore_test_ms: row.get(6)?,
                last_restore_test_ok: row.get(7)?,
                last_restore_test_error: row.get(8)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 정상본을 임시 파일에 복원·동기화·재해시하는 시험. 원본 파일은 수정하지 않는다.
    /// 성공 및 실패를 모두 기록하여 '시험 없음'과 '시험 실패'를 구분한다.
    pub fn test_restore(
        &self,
        path: &Path,
        before_ms: Option<u64>,
    ) -> Result<BackupVersion, RecoveryError> {
        let result = (|| {
            let version = self.recommend(path, before_ms)?;
            let data = self.read_verified(&version)?;
            let (scratch, mut file) = create_restore_temp(&self.dir.join("restore-test"))?;
            let written = file.write_all(&data).and_then(|_| file.sync_all());
            drop(file);
            let verified = written.map_err(|e| io_err(&scratch, e)).and_then(|_| {
                let mut bytes = Vec::new();
                fs::File::open(&scratch)
                    .and_then(|f| {
                        f.take(version.size.saturating_add(1))
                            .read_to_end(&mut bytes)
                    })
                    .map_err(|e| io_err(&scratch, e))?;
                let actual = hex::encode(Sha256::digest(&bytes));
                if actual != version.hash {
                    return Err(RecoveryError::IntegrityMismatch {
                        expected: version.hash.clone(),
                        actual,
                    });
                }
                Ok(())
            });
            let _ = fs::remove_file(&scratch);
            verified?;
            Ok(version)
        })();
        let tested_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let error = result.as_ref().err().map(ToString::to_string);
        self.conn.execute(
            "INSERT INTO recovery_status(path, last_restore_test_ms, last_restore_test_ok, last_restore_test_error)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT(path) DO UPDATE SET
             last_restore_test_ms = excluded.last_restore_test_ms,
             last_restore_test_ok = excluded.last_restore_test_ok,
             last_restore_test_error = excluded.last_restore_test_error",
            params![path.to_string_lossy().into_owned(), tested_at, result.is_ok(), error],
        )?;
        result
    }

    /// 경로의 버전 이력 (최신순). known_good는 무결성 검증 결과가 아니다.
    pub fn versions(&self, path: &Path) -> Result<Vec<BackupVersion>, RecoveryError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, path, hash, size, timestamp_ms, pid, known_good, trust_note FROM versions
             WHERE path = ?1 ORDER BY timestamp_ms DESC, id DESC",
        )?;
        let rows = stmt
            .query_map(
                params![path.to_string_lossy().into_owned()],
                Self::map_version,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn version(&self, path: &Path, id: i64) -> Result<BackupVersion, RecoveryError> {
        self.conn.query_row(
            "SELECT id, path, hash, size, timestamp_ms, pid, known_good, trust_note FROM versions
             WHERE path = ?1 AND id = ?2",
            params![path.to_string_lossy().into_owned(), id],
            Self::map_version,
        ).optional()?.ok_or_else(|| RecoveryError::NotFound(format!("{} (버전 {id})", path.display())))
    }

    /// 운영자가 검토한 버전을 정상 복구 지점으로 지정한다.
    /// 해시 검증은 저장 손상만 검사한다. 내용이 정상이라는 판정 책임은 호출자에게 있다.
    pub fn mark_known_good(
        &self,
        path: &Path,
        version_id: i64,
        note: &str,
    ) -> Result<BackupVersion, RecoveryError> {
        if note.trim().is_empty() {
            return Err(RecoveryError::MissingTrustNote);
        }
        let version = self.version(path, version_id)?;
        self.read_verified(&version)?;
        self.conn.execute(
            "UPDATE versions SET known_good = 1, trust_note = ?1 WHERE id = ?2",
            params![note.trim(), version.id],
        )?;
        tracing::info!(path = %path.display(), version_id, "정상 복구 지점 지정");
        self.version(path, version_id)
    }

    /// 후속 조사에서 정상 판정을 취소한다. 사고 보존 고정은 별도로 유지된다.
    pub fn revoke_known_good(
        &self,
        path: &Path,
        version_id: i64,
        note: &str,
    ) -> Result<BackupVersion, RecoveryError> {
        if note.trim().is_empty() {
            return Err(RecoveryError::MissingTrustNote);
        }
        let version = self.version(path, version_id)?;
        self.conn.execute(
            "UPDATE versions SET known_good = 0, trust_note = ?1 WHERE id = ?2",
            params![note.trim(), version.id],
        )?;
        tracing::info!(path = %path.display(), version_id, "정상 복구 지점 판정 취소");
        self.version(path, version_id)
    }

    /// 정상 판정된 최신 버전을 추천한다. 공격 의심 시각을 주면 그 시각보다 이른 버전만 선택한다.
    /// 신뢰된 버전이 없다고 미검토 최신 버전으로 대체하지 않는다.
    pub fn recommend(
        &self,
        path: &Path,
        before_ms: Option<u64>,
    ) -> Result<BackupVersion, RecoveryError> {
        let versions = self.versions(path)?;
        if versions.is_empty() {
            return Err(RecoveryError::NotFound(path.display().to_string()));
        }
        versions
            .into_iter()
            .find(|v| v.known_good && before_ms.map_or(true, |cutoff| v.timestamp_ms < cutoff))
            .ok_or_else(|| RecoveryError::NoTrustedVersion(path.display().to_string()))
    }

    /// 정상 판정된 버전만 해시 검증 후 복구한다. 시점 생략도 최신 정상본을 의미한다.
    pub fn restore(
        &self,
        path: &Path,
        before_ms: Option<u64>,
    ) -> Result<BackupVersion, RecoveryError> {
        let version = self.recommend(path, before_ms)?;
        let data = self.read_verified(&version)?;
        // 심볼릭 링크를 따라 다른 파일의 소유권/권한을 복제하지 않는다.
        let target_metadata = match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => Some(metadata),
            Ok(_) => {
                return Err(RecoveryError::UnsafeRestoreTarget(
                    path.display().to_string(),
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_err(path, error)),
        };
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
        }
        // 기존 파일/심볼릭 링크를 임시 파일로 오인해 덮어쓰지 않도록 독점 생성한다.
        let (tmp, mut file) = create_restore_temp(path)?;
        let result = (|| {
            file.write_all(&data).map_err(|e| io_err(&tmp, e))?;
            apply_restore_metadata(&file, target_metadata.as_ref(), &tmp)?;
            file.sync_all().map_err(|e| io_err(&tmp, e))?;
            drop(file);
            fs::rename(&tmp, path).map_err(|e| io_err(path, e))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result?;
        tracing::info!(path = %path.display(), version_id = version.id, hash = %version.hash, "정상본 복구 완료");
        Ok(version)
    }

    /// 검토용으로 버전을 별도 새 파일에 복원한다. 미검토 버전도 허용하지만 원본은 변경하지 않는다.
    /// 대상 부모 디렉터리는 미리 존재해야 하며 기존 파일/심볼릭 링크는 덮어쓰지 않는다.
    pub fn preview(
        &self,
        path: &Path,
        version_id: i64,
        destination: &Path,
    ) -> Result<BackupVersion, RecoveryError> {
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent.canonicalize().map_err(|e| io_err(parent, e))?;
        let filename = destination
            .file_name()
            .ok_or_else(|| RecoveryError::UnsafePreview(destination.display().to_string()))?;
        let resolved = parent.join(filename);
        let source_parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let source = source_parent
            .canonicalize()
            .ok()
            .and_then(|p| path.file_name().map(|name| p.join(name)));
        let backup_dir = self.dir.canonicalize().map_err(|e| io_err(&self.dir, e))?;
        if source.as_deref() == Some(resolved.as_path()) || resolved.starts_with(&backup_dir) {
            return Err(RecoveryError::UnsafePreview(
                destination.display().to_string(),
            ));
        }
        let version = self.version(path, version_id)?;
        let data = self.read_verified(&version)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&resolved).map_err(|e| io_err(&resolved, e))?;
        if let Err(source) = output.write_all(&data).and_then(|_| output.sync_all()) {
            let _ = fs::remove_file(&resolved);
            return Err(io_err(&resolved, source));
        }
        Ok(version)
    }

    fn read_verified(&self, version: &BackupVersion) -> Result<Vec<u8>, RecoveryError> {
        if version.hash.len() != 64 || !version.hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(RecoveryError::InvalidMetadata(
                "객체 해시는 64자리 SHA-256이어야 합니다".into(),
            ));
        }
        let obj = self.object_path(&version.hash);
        let mut data = Vec::new();
        fs::File::open(&obj)
            .and_then(|f| {
                f.take(version.size.saturating_add(1))
                    .read_to_end(&mut data)
            })
            .map_err(|e| io_err(&obj, e))?;
        let actual = hex::encode(Sha256::digest(&data));
        if actual != version.hash {
            return Err(RecoveryError::IntegrityMismatch {
                expected: version.hash.clone(),
                actual,
            });
        }
        Ok(data)
    }

    fn map_version(r: &rusqlite::Row<'_>) -> rusqlite::Result<BackupVersion> {
        Ok(BackupVersion {
            id: r.get(0)?,
            path: r.get(1)?,
            hash: r.get(2)?,
            size: r.get(3)?,
            timestamp_ms: r.get(4)?,
            pid: r.get(5)?,
            known_good: r.get(6)?,
            trust_note: r.get(7)?,
        })
    }

    /// 보존 정책: 정상 복구 지점과 사고 보존 고정 버전 + 경로당 최근 `keep`개 미검토 버전을 남긴 뒤,
    /// 어떤 버전도 참조하지 않는 객체 파일을 삭제한다.
    pub fn prune(&self, keep: usize) -> Result<usize, RecoveryError> {
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.conn,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let removed = self.conn.execute(
            "DELETE FROM versions WHERE known_good = 0 AND NOT EXISTS (
                 SELECT 1 FROM retention_pins WHERE version_id = versions.id AND released_at_ms IS NULL
             ) AND id NOT IN (
                 SELECT id FROM (
                     SELECT id, ROW_NUMBER() OVER (PARTITION BY path ORDER BY id DESC) AS rn
                     FROM versions WHERE known_good = 0
                 ) WHERE rn <= ?1
             )",
            params![i64::try_from(keep).unwrap_or(i64::MAX)],
        )?;

        // 참조되지 않는 객체 삭제.
        let mut stmt = self.conn.prepare("SELECT DISTINCT hash FROM versions")?;
        let live: std::collections::HashSet<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;
        let objects_dir = self.dir.join("objects");
        if let Ok(shards) = fs::read_dir(&objects_dir) {
            for shard in shards.flatten() {
                let Ok(files) = fs::read_dir(shard.path()) else {
                    continue;
                };
                for f in files.flatten() {
                    let name = f.file_name().to_string_lossy().into_owned();
                    if !live.contains(&name) {
                        let _ = fs::remove_file(f.path());
                    }
                }
            }
        }
        transaction.commit()?;
        Ok(removed)
    }
}

/// 내용 복구로 소유권 또는 setuid/setgid 권한이 승격되지 않도록 한다.
fn apply_restore_metadata(
    file: &fs::File,
    existing: Option<&fs::Metadata>,
    temporary: &Path,
) -> Result<(), RecoveryError> {
    let Some(existing) = existing else {
        // 새 경로는 create_restore_temp의 소유자 전용 0600을 유지한다.
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        // 소유자 변경은 특수 권한을 지울 수 있으므로 반드시 chmod보다 먼저 한다.
        // 권한이 없어 소유권을 보존하지 못하면 원본을 교체하지 않고 실패한다.
        let result = unsafe { libc::fchown(file.as_raw_fd(), existing.uid(), existing.gid()) };
        if result != 0 {
            return Err(io_err(temporary, std::io::Error::last_os_error()));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(
            existing.permissions().mode() & 0o777,
        ))
        .map_err(|error| io_err(temporary, error))?;
    }
    #[cfg(not(unix))]
    file.set_permissions(existing.permissions())
        .map_err(|error| io_err(temporary, error))?;
    Ok(())
}

/// 원본과 같은 디렉터리에 고유한 임시 파일을 독점 생성한다.
fn create_restore_temp(path: &Path) -> Result<(PathBuf, fs::File), RecoveryError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    for _ in 0..100 {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!(
            "argos-restore-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_err(&tmp, error)),
        }
    }
    Err(io_err(
        path,
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "복구 임시 파일을 생성할 수 없습니다",
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("argos-recovery-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn backup_and_restore_roundtrip() {
        let dir = temp_dir("rt");
        let store = BackupStore::open(&dir.join("backup"), 1024 * 1024).unwrap();

        let target = dir.join("doc.txt");
        fs::write(&target, b"original content").unwrap();
        let h1 = store.backup(&target, 1000, 0).unwrap();
        assert!(h1.is_some());
        let first = store.versions(&target).unwrap()[0].id;
        store
            .mark_known_good(&target, first, "배포 원본 대조 완료")
            .unwrap();

        // 같은 내용 재백업은 스킵.
        assert!(store.backup(&target, 1500, 0).unwrap().is_none());

        // "랜섬웨어"가 파일을 덮어씀.
        fs::write(&target, b"ENCRYPTED!!!").unwrap();
        store.backup(&target, 2000, 0).unwrap();

        // 공격 시각(2000ms) 이전 버전으로 복구.
        let v = store.restore(&target, Some(2000)).unwrap();
        assert_eq!(v.timestamp_ms, 1000);
        assert_eq!(fs::read(&target).unwrap(), b"original content");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_missing_returns_not_found() {
        let dir = temp_dir("nf");
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let err = store.restore(&dir.join("nope.txt"), None).unwrap_err();
        assert!(matches!(err, RecoveryError::NotFound(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_keeps_latest_versions() {
        let dir = temp_dir("pr");
        let store = BackupStore::open(&dir.join("backup"), 1024 * 1024).unwrap();
        let target = dir.join("f.txt");
        for i in 0..5u64 {
            fs::write(&target, format!("v{i}")).unwrap();
            store.backup(&target, 1000 + i, 0).unwrap();
        }
        let removed = store.prune(2).unwrap();
        assert_eq!(removed, 3);
        assert_eq!(store.versions(&target).unwrap().len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_restore_never_uses_unreviewed_latest() {
        let dir = temp_dir("trusted-default");
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let target = dir.join("doc.txt");
        fs::write(&target, b"known original").unwrap();
        store.backup(&target, 100, 0).unwrap();
        let clean_id = store.versions(&target).unwrap()[0].id;
        assert!(matches!(
            store.restore(&target, None),
            Err(RecoveryError::NoTrustedVersion(_))
        ));
        assert!(matches!(
            store.restore(&target, Some(200)),
            Err(RecoveryError::NoTrustedVersion(_))
        ));
        store
            .mark_known_good(&target, clean_id, "배포 산출물과 비교 완료")
            .unwrap();
        fs::write(&target, b"ciphertext").unwrap();
        store.backup(&target, 200, 42).unwrap();
        assert!(!store.versions(&target).unwrap()[0].known_good);
        let restored = store.restore(&target, None).unwrap();
        assert_eq!(restored.id, clean_id);
        assert_eq!(
            restored.trust_note.as_deref(),
            Some("배포 산출물과 비교 완료")
        );
        assert_eq!(fs::read(&target).unwrap(), b"known original");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recommendations_respect_attack_cutoff_and_event_time() {
        let dir = temp_dir("cutoff");
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let target = dir.join("doc.txt");
        for timestamp in [100, 300, 200] {
            fs::write(&target, timestamp.to_string()).unwrap();
            store.backup(&target, timestamp, 0).unwrap();
            let id: i64 = store
                .conn
                .query_row("SELECT MAX(id) FROM versions", [], |r| r.get(0))
                .unwrap();
            store
                .mark_known_good(&target, id, "작업 승인 기록과 대조")
                .unwrap();
        }
        assert_eq!(store.recommend(&target, None).unwrap().timestamp_ms, 300);
        assert_eq!(
            store.recommend(&target, Some(300)).unwrap().timestamp_ms,
            200
        );
        assert_eq!(
            store.recommend(&target, Some(200)).unwrap().timestamp_ms,
            100
        );
        assert!(matches!(
            store.recommend(&target, Some(100)),
            Err(RecoveryError::NoTrustedVersion(_))
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn preview_unknown_version_is_separate_and_exclusive() {
        let dir = temp_dir("preview");
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let target = dir.join("doc.txt");
        fs::write(&target, b"saved version").unwrap();
        store.backup(&target, 100, 0).unwrap();
        let id = store.versions(&target).unwrap()[0].id;
        fs::write(&target, b"live content").unwrap();
        let destination = dir.join("review.txt");
        assert!(!store.preview(&target, id, &destination).unwrap().known_good);
        assert_eq!(fs::read(&destination).unwrap(), b"saved version");
        assert_eq!(fs::read(&target).unwrap(), b"live content");
        fs::write(&destination, b"reviewer edits").unwrap();
        assert!(store.preview(&target, id, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"reviewer edits");
        assert!(matches!(
            store.preview(&target, id, &target),
            Err(RecoveryError::UnsafePreview(_))
        ));
        assert!(matches!(
            store.preview(&target, id, &dir.join("backup/extra")),
            Err(RecoveryError::UnsafePreview(_))
        ));
        fs::remove_file(&target).unwrap();
        assert!(matches!(
            store.preview(&target, id, &target),
            Err(RecoveryError::UnsafePreview(_))
        ));
        assert!(!target.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hashes_prove_integrity_but_do_not_grant_trust() {
        let dir = temp_dir("integrity");
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let target = dir.join("doc.txt");
        fs::write(&target, b"unknown content").unwrap();
        store.backup(&target, 100, 0).unwrap();
        let version = store.versions(&target).unwrap()[0].clone();
        assert_eq!(store.read_verified(&version).unwrap(), b"unknown content");
        assert!(!store.versions(&target).unwrap()[0].known_good);
        assert!(matches!(
            store.mark_known_good(&target, version.id, "  "),
            Err(RecoveryError::MissingTrustNote)
        ));
        fs::write(store.object_path(&version.hash), b"corrupted object").unwrap();
        assert!(matches!(
            store.mark_known_good(&target, version.id, "검토"),
            Err(RecoveryError::IntegrityMismatch { .. })
        ));
        assert!(!store.versions(&target).unwrap()[0].known_good);
        assert!(matches!(
            store.preview(&target, version.id, &dir.join("preview")),
            Err(RecoveryError::IntegrityMismatch { .. })
        ));
        assert!(!dir.join("preview").exists());
        assert_eq!(fs::read(&target).unwrap(), b"unknown content");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_trusted_version_does_not_overwrite_live_file() {
        let dir = temp_dir("trusted-corrupt");
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let target = dir.join("doc.txt");
        fs::write(&target, b"original").unwrap();
        store.backup(&target, 100, 0).unwrap();
        let v = store.versions(&target).unwrap()[0].clone();
        store.mark_known_good(&target, v.id, "검토 완료").unwrap();
        fs::write(store.object_path(&v.hash), b"bad").unwrap();
        fs::write(&target, b"live data").unwrap();
        assert!(matches!(
            store.restore(&target, None),
            Err(RecoveryError::IntegrityMismatch { .. })
        ));
        assert_eq!(fs::read(&target).unwrap(), b"live data");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pruning_preserves_trusted_objects_until_explicit_revocation() {
        let dir = temp_dir("trusted-prune");
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let target = dir.join("doc.txt");
        fs::write(&target, b"clean").unwrap();
        store.backup(&target, 100, 0).unwrap();
        let clean_id = store.versions(&target).unwrap()[0].id;
        store
            .mark_known_good(&target, clean_id, "정상본 검사 완료")
            .unwrap();
        for timestamp in 200..205 {
            fs::write(&target, format!("encrypted {timestamp}")).unwrap();
            store.backup(&target, timestamp, 10).unwrap();
        }
        assert_eq!(store.prune(1).unwrap(), 4);
        assert_eq!(store.versions(&target).unwrap().len(), 2);
        assert_eq!(store.prune(0).unwrap(), 1);
        assert_eq!(store.restore(&target, None).unwrap().id, clean_id);
        assert_eq!(fs::read(&target).unwrap(), b"clean");
        store
            .revoke_known_good(&target, clean_id, "후속 조사에서 신뢰 취소")
            .unwrap();
        assert!(matches!(
            store.restore(&target, None),
            Err(RecoveryError::NoTrustedVersion(_))
        ));
        assert_eq!(store.prune(0).unwrap(), 1);
        assert!(store.versions(&target).unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_metadata_migrates_without_inventing_trust() {
        let dir = temp_dir("migration");
        let target = dir.join("doc.txt");
        let conn = Connection::open(dir.join("index.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL, hash TEXT NOT NULL,
            size INTEGER NOT NULL, timestamp_ms INTEGER NOT NULL, pid INTEGER NOT NULL
        );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO versions(path,hash,size,timestamp_ms,pid) VALUES (?1,?2,4,100,0)",
            params![target.to_string_lossy(), "a".repeat(64)],
        )
        .unwrap();
        drop(conn);
        for _ in 0..2 {
            let store = BackupStore::open(&dir, 1024).unwrap();
            let versions = store.versions(&target).unwrap();
            assert_eq!(versions.len(), 1);
            assert!(!versions[0].known_good);
            assert_eq!(versions[0].trust_note, None);
            assert!(matches!(
                store.recommend(&target, None),
                Err(RecoveryError::NoTrustedVersion(_))
            ));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn readiness_tracks_skipped_files_and_persists_restore_tests() {
        let dir = temp_dir("readiness");
        let backup_dir = dir.join("backup");
        let target = dir.join("doc.txt");
        let too_large = dir.join("large.bin");
        let store = BackupStore::open(&backup_dir, 20).unwrap();
        fs::write(&too_large, [1u8; 21]).unwrap();
        assert!(matches!(
            store.backup(&too_large, 100, 0),
            Err(RecoveryError::TooLarge { .. })
        ));
        fs::write(&target, b"clean").unwrap();
        store.backup(&target, 100, 0).unwrap();
        assert!(matches!(
            store.test_restore(&target, None),
            Err(RecoveryError::NoTrustedVersion(_))
        ));
        let states = store.readiness().unwrap();
        let state = states
            .iter()
            .find(|r| r.path == target.to_string_lossy())
            .unwrap();
        assert_eq!(state.version_count, 1);
        assert_eq!(state.known_good_versions, 0);
        assert_eq!(state.last_restore_test_ok, Some(false));
        assert!(state.last_restore_test_error.is_some());
        assert!(state.last_restore_test_ms.is_some());
        let id = store.versions(&target).unwrap()[0].id;
        store
            .mark_known_good(&target, id, "업무 원본 검사")
            .unwrap();
        fs::write(&target, b"live").unwrap();
        store.test_restore(&target, None).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"live");
        drop(store);
        let reopened = BackupStore::open(&backup_dir, 20).unwrap();
        let states = reopened.readiness().unwrap();
        let state = states
            .iter()
            .find(|r| r.path == target.to_string_lossy())
            .unwrap();
        assert_eq!(state.known_good_versions, 1);
        assert_eq!(state.latest_known_good_ms, Some(100));
        assert_eq!(state.last_restore_test_ok, Some(true));
        assert_eq!(state.last_restore_test_error, None);
        let excluded = states
            .iter()
            .find(|r| r.path == too_large.to_string_lossy())
            .unwrap();
        assert_eq!(excluded.oversized_skips, 1);
        assert_eq!(excluded.version_count, 0);
        assert_eq!(excluded.last_restore_test_ok, None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn preview_refuses_symlink_destinations_and_backup_directory_aliases() {
        use std::os::unix::fs::symlink;
        let dir = temp_dir("preview-symlink");
        let backup_dir = dir.join("backup");
        let store = BackupStore::open(&backup_dir, 1024).unwrap();
        let target = dir.join("doc.txt");
        fs::write(&target, b"saved").unwrap();
        store.backup(&target, 100, 0).unwrap();
        let version = store.versions(&target).unwrap()[0].clone();
        let link = dir.join("preview-link");
        symlink(&target, &link).unwrap();
        assert!(store.preview(&target, version.id, &link).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"saved");
        let alias = dir.join("backup-alias");
        symlink(&backup_dir, &alias).unwrap();
        assert!(matches!(
            store.preview(&target, version.id, &alias.join("output")),
            Err(RecoveryError::UnsafePreview(_))
        ));
        assert!(!backup_dir.join("output").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_selection_is_bound_to_requested_file() {
        let dir = temp_dir("path-bound");
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let target = dir.join("doc.txt");
        let other = dir.join("other.txt");
        fs::write(&target, b"saved").unwrap();
        store.backup(&target, 100, 0).unwrap();
        let version = store.versions(&target).unwrap()[0].clone();
        assert!(matches!(
            store.mark_known_good(&other, version.id, "검토"),
            Err(RecoveryError::NotFound(_))
        ));
        assert!(matches!(
            store.preview(&other, version.id, &dir.join("output")),
            Err(RecoveryError::NotFound(_))
        ));
        assert!(!dir.join("output").exists());
        assert!(!store.versions(&target).unwrap()[0].known_good);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn restore_strips_privileged_permission_bits_and_missing_target_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("restore-permissions");
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let target = dir.join("executable");
        fs::write(&target, b"known executable fixture").unwrap();
        store.backup(&target, 100, 0).unwrap();
        let id = store.versions(&target).unwrap()[0].id;
        store
            .mark_known_good(&target, id, "검토된 실행 파일")
            .unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o6755)).unwrap();
        store.restore(&target, None).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        fs::remove_file(&target).unwrap();
        store.restore(&target, None).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restore_preserves_existing_owner_and_group() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let dir = temp_dir("restore-ownership");
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let target = dir.join("document");
        fs::write(&target, b"business fixture").unwrap();
        store.backup(&target, 100, 0).unwrap();
        let id = store.versions(&target).unwrap()[0].id;
        store
            .mark_known_good(&target, id, "정상 파일 검사")
            .unwrap();
        let metadata = fs::metadata(&target).unwrap();
        let group_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        assert!(group_count >= 0);
        let mut groups = vec![0 as libc::gid_t; group_count as usize];
        assert_eq!(
            unsafe { libc::getgroups(group_count, groups.as_mut_ptr()) },
            group_count
        );
        let uid = if unsafe { libc::geteuid() } == 0 {
            65534
        } else {
            metadata.uid()
        };
        // 일반 계정에서도 현재 기본 그룹과 다른 보조 그룹으로 보존 동작을 검사한다.
        let gid = groups
            .into_iter()
            .find(|gid| *gid != metadata.gid())
            .unwrap_or(metadata.gid());
        let file = fs::File::open(&target).unwrap();
        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) }, 0);
        drop(file);
        store.restore(&target, None).unwrap();
        let restored = fs::metadata(&target).unwrap();
        assert_eq!(restored.uid(), uid);
        assert_eq!(restored.gid(), gid);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn restore_does_not_follow_or_replace_a_symlink_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = temp_dir("restore-symlink");
        let store = BackupStore::open(&dir.join("backup"), 1024).unwrap();
        let target = dir.join("document");
        let external = dir.join("external");
        fs::write(&target, b"known").unwrap();
        store.backup(&target, 100, 0).unwrap();
        let id = store.versions(&target).unwrap()[0].id;
        store.mark_known_good(&target, id, "정상본 확인").unwrap();
        fs::remove_file(&target).unwrap();
        fs::write(&external, b"unrelated data").unwrap();
        fs::set_permissions(&external, fs::Permissions::from_mode(0o4755)).unwrap();
        symlink(&external, &target).unwrap();
        assert!(matches!(
            store.restore(&target, None),
            Err(RecoveryError::UnsafeRestoreTarget(_))
        ));
        assert!(fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&external).unwrap(), b"unrelated data");
        assert_eq!(
            fs::metadata(&external).unwrap().permissions().mode() & 0o7777,
            0o4755
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
