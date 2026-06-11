//! Argos Storage: SQLite 기반 로컬 이벤트·탐지 저장소.
//!
//! 에이전트(쓰기)와 CLI(읽기)가 같은 DB 파일을 공유한다. WAL 모드로
//! 동시 읽기를 허용한다. Phase 2에서 중앙 서버 전송 큐가 추가된다.

use argos_common::{Detection, FileEvent};
use rusqlite::{params, Connection};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("DB 오류: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("직렬화 오류: {0}")]
    Json(#[from] serde_json::Error),
    #[error("IO 오류: {0}")]
    Io(#[from] std::io::Error),
}

pub struct EventStore {
    conn: Connection,
}

impl EventStore {
    /// DB를 열고 스키마를 초기화한다. 상위 디렉터리가 없으면 생성한다.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS file_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ms INTEGER NOT NULL,
                pid          INTEGER NOT NULL,
                path         TEXT NOT NULL,
                action       TEXT NOT NULL,
                size         INTEGER,
                entropy      REAL
            );
            CREATE INDEX IF NOT EXISTS idx_file_events_ts ON file_events(timestamp_ms);

            CREATE TABLE IF NOT EXISTS detections (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ms INTEGER NOT NULL,
                rule         TEXT NOT NULL,
                score        REAL NOT NULL,
                severity     TEXT NOT NULL,
                summary      TEXT NOT NULL,
                pid          INTEGER NOT NULL,
                paths_json   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(timestamp_ms);",
        )?;
        Ok(Self { conn })
    }

    /// 읽기 전용으로 연다 (CLI용). 파일이 없으면 오류.
    pub fn open_readonly(path: &Path) -> Result<Self, StorageError> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Ok(Self { conn })
    }

    pub fn insert_file_event(&self, e: &FileEvent) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO file_events (timestamp_ms, pid, path, action, size, entropy)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                e.timestamp_ms as i64,
                e.pid,
                e.path,
                format!("{:?}", e.action),
                e.size.map(|s| s as i64),
                e.entropy,
            ],
        )?;
        Ok(())
    }

    pub fn insert_detection(&self, d: &Detection) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO detections (timestamp_ms, rule, score, severity, summary, pid, paths_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                d.timestamp_ms as i64,
                d.rule,
                d.score,
                d.severity.as_str(),
                d.summary,
                d.pid,
                serde_json::to_string(&d.paths)?,
            ],
        )?;
        Ok(())
    }

    /// 최근 파일 이벤트 (timestamp_ms, pid, path, action) — 최신순.
    pub fn recent_events(
        &self,
        limit: usize,
    ) -> Result<Vec<(i64, u32, String, String)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ms, pid, path, action FROM file_events
             ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// 최근 탐지 (timestamp_ms, rule, score, severity, summary) — 최신순.
    pub fn recent_detections(
        &self,
        limit: usize,
    ) -> Result<Vec<(i64, String, f64, String, String)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ms, rule, score, severity, summary FROM detections
             ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn event_count(&self) -> Result<i64, StorageError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM file_events", [], |r| r.get(0))?)
    }

    pub fn detection_count(&self) -> Result<i64, StorageError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM detections", [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_common::{FileAction, Severity};

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join("argos-storage-test");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join(format!("t-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&db);

        let store = EventStore::open(&db).unwrap();
        store
            .insert_file_event(&FileEvent {
                timestamp_ms: 1,
                pid: 42,
                path: "/tmp/x".into(),
                action: FileAction::Modify,
                size: Some(10),
                entropy: Some(7.5),
            })
            .unwrap();
        store
            .insert_detection(&Detection {
                timestamp_ms: 2,
                rule: "behavior.test".into(),
                score: 90.0,
                severity: Severity::Critical,
                summary: "test".into(),
                pid: 42,
                paths: vec!["/tmp/x".into()],
            })
            .unwrap();

        assert_eq!(store.event_count().unwrap(), 1);
        assert_eq!(store.detection_count().unwrap(), 1);
        assert_eq!(store.recent_events(10).unwrap().len(), 1);
        assert_eq!(store.recent_detections(10).unwrap()[0].2, 90.0);

        drop(store);
        let _ = std::fs::remove_file(&db);
    }
}
