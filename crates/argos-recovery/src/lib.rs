//! Argos Recovery: 변경 전 백업 + 복구 (요건서 10장).
//!
//! 설계:
//! - 내용 주소 저장(content-addressed): 파일 내용의 SHA-256을 키로
//!   `<backup_dir>/objects/<해시 앞2자리>/<해시>` 에 저장. 같은 내용은 한 번만 저장된다.
//! - 버전 메타데이터(경로, 해시, 크기, 시각, 원인 pid)는 SQLite 인덱스에 기록.
//! - 복구는 특정 시각 이전의 마지막 버전을 골라 해시 검증 후 원위치에 복사.

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

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
    #[error("무결성 검증 실패: 기대 해시 {expected}, 실제 {actual}")]
    IntegrityMismatch { expected: String, actual: String },
    #[error("파일이 백업 크기 제한({limit} bytes)을 초과합니다: {size} bytes")]
    TooLarge { size: u64, limit: u64 },
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
        let conn = Connection::open(dir.join("index.db"))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS versions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                path         TEXT NOT NULL,
                hash         TEXT NOT NULL,
                size         INTEGER NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                pid          INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_versions_path ON versions(path, timestamp_ms);",
        )?;
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
            return Err(RecoveryError::TooLarge {
                size: meta.len(),
                limit: self.max_file_bytes,
            });
        }

        let data = fs::read(path).map_err(|e| io_err(path, e))?;
        let hash = hex::encode(Sha256::digest(&data));
        let path_str = path.to_string_lossy().into_owned();

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
            // 임시 파일에 쓴 뒤 rename — 부분 쓰기 방지.
            let tmp = obj.with_extension("tmp");
            fs::write(&tmp, &data).map_err(|e| io_err(&tmp, e))?;
            fs::rename(&tmp, &obj).map_err(|e| io_err(&obj, e))?;
        }

        self.conn.execute(
            "INSERT INTO versions (path, hash, size, timestamp_ms, pid)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![path_str, hash, data.len() as i64, timestamp_ms as i64, pid],
        )?;
        Ok(Some(hash))
    }

    /// 경로의 버전 이력 (최신순).
    pub fn versions(&self, path: &Path) -> Result<Vec<BackupVersion>, RecoveryError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, path, hash, size, timestamp_ms, pid FROM versions
             WHERE path = ?1 ORDER BY id DESC",
        )?;
        let rows = stmt
            .query_map(params![path.to_string_lossy().into_owned()], |r| {
                Ok(BackupVersion {
                    id: r.get(0)?,
                    path: r.get(1)?,
                    hash: r.get(2)?,
                    size: r.get::<_, i64>(3)? as u64,
                    timestamp_ms: r.get::<_, i64>(4)? as u64,
                    pid: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// 지정 시각(epoch ms) 이전의 마지막 버전으로 복구한다.
    /// `before_ms`가 None이면 최신 버전으로 복구한다.
    /// 복구 전 객체의 해시를 재계산해 무결성을 검증한다 (요건서 10장 복구 검증).
    pub fn restore(
        &self,
        path: &Path,
        before_ms: Option<u64>,
    ) -> Result<BackupVersion, RecoveryError> {
        let path_str = path.to_string_lossy().into_owned();
        let version: Option<BackupVersion> = match before_ms {
            Some(t) => self
                .conn
                .query_row(
                    "SELECT id, path, hash, size, timestamp_ms, pid FROM versions
                     WHERE path = ?1 AND timestamp_ms < ?2 ORDER BY id DESC LIMIT 1",
                    params![path_str, t as i64],
                    Self::map_version,
                )
                .optional()?,
            None => self
                .conn
                .query_row(
                    "SELECT id, path, hash, size, timestamp_ms, pid FROM versions
                     WHERE path = ?1 ORDER BY id DESC LIMIT 1",
                    params![path_str],
                    Self::map_version,
                )
                .optional()?,
        };
        let version = version.ok_or_else(|| RecoveryError::NotFound(path_str.clone()))?;

        let obj = self.object_path(&version.hash);
        let mut data = Vec::new();
        fs::File::open(&obj)
            .and_then(|mut f| f.read_to_end(&mut data))
            .map_err(|e| io_err(&obj, e))?;

        let actual = hex::encode(Sha256::digest(&data));
        if actual != version.hash {
            return Err(RecoveryError::IntegrityMismatch {
                expected: version.hash.clone(),
                actual,
            });
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
        }
        let tmp = path.with_extension("argos-restore-tmp");
        fs::write(&tmp, &data).map_err(|e| io_err(&tmp, e))?;
        fs::rename(&tmp, path).map_err(|e| io_err(path, e))?;
        tracing::info!(path = %path.display(), hash = %version.hash, "파일 복구 완료");
        Ok(version)
    }

    fn map_version(r: &rusqlite::Row<'_>) -> rusqlite::Result<BackupVersion> {
        Ok(BackupVersion {
            id: r.get(0)?,
            path: r.get(1)?,
            hash: r.get(2)?,
            size: r.get::<_, i64>(3)? as u64,
            timestamp_ms: r.get::<_, i64>(4)? as u64,
            pid: r.get(5)?,
        })
    }

    /// 보존 정책: 경로당 최근 `keep`개 버전만 남기고 인덱스에서 제거한 뒤,
    /// 어떤 버전도 참조하지 않는 객체 파일을 삭제한다.
    pub fn prune(&self, keep: usize) -> Result<usize, RecoveryError> {
        let removed = self.conn.execute(
            "DELETE FROM versions WHERE id NOT IN (
                 SELECT id FROM (
                     SELECT id, ROW_NUMBER() OVER (PARTITION BY path ORDER BY id DESC) AS rn
                     FROM versions
                 ) WHERE rn <= ?1
             )",
            params![keep as i64],
        )?;

        // 참조되지 않는 객체 삭제.
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT hash FROM versions")?;
        let live: std::collections::HashSet<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;
        let objects_dir = self.dir.join("objects");
        if let Ok(shards) = fs::read_dir(&objects_dir) {
            for shard in shards.flatten() {
                let Ok(files) = fs::read_dir(shard.path()) else { continue };
                for f in files.flatten() {
                    let name = f.file_name().to_string_lossy().into_owned();
                    if !live.contains(&name) {
                        let _ = fs::remove_file(f.path());
                    }
                }
            }
        }
        Ok(removed)
    }
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
}
