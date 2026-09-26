//! Argos Storage: SQLite 기반 로컬 이벤트·탐지 저장소.
//!
//! 에이전트(쓰기)와 CLI(읽기)가 같은 DB 파일을 공유한다. WAL 모드로
//! 동시 읽기를 허용한다. Phase 2에서 중앙 서버 전송 큐가 추가된다.

use argos_common::{Detection, FileAction, FileEvent, ProcessEvent};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;

mod evidence;
pub use evidence::{EvidenceBundle, EvidencePage, EvidenceQuery, ProcessEventRow};
mod outbox;
pub use outbox::{OutboxEntry, OutboxStats, RetentionJob, RetentionStats};
mod response_audit;
pub use response_audit::{ResponseAudit, ResponseAuditRow};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("DB 오류: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("직렬화 오류: {0}")]
    Json(#[from] serde_json::Error),
    #[error("IO 오류: {0}")]
    Io(#[from] std::io::Error),
    #[error("이벤트 조회 범위 오류: {0}")]
    InvalidRange(String),
}

/// 탐지 1건의 전체 행 (id 포함).
#[derive(Debug, Clone, Serialize)]
pub struct DetectionRow {
    pub id: i64,
    pub timestamp_ms: i64,
    pub rule: String,
    pub score: f64,
    pub severity: String,
    pub summary: String,
    pub pid: u32,
    pub paths: Vec<String>,
}

/// 정책 재생에 필요한 원본 값과 근거 ID. 현재 파일은 읽지 않는다.
#[derive(Debug, Clone, Serialize)]
pub struct FileEventRow {
    pub id: i64,
    pub event: FileEvent,
}

/// 한 DB 읽기 스냅샷에서 조회한 구간과 유실 없이 계산한 전체 건수.
#[derive(Debug, Clone)]
pub struct FileEventRange {
    pub from_ms: u64,
    pub to_ms: u64,
    pub total_events: u64,
    pub truncated: bool,
    pub events: Vec<FileEventRow>,
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
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
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
                entropy      REAL,
                event_json   TEXT
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
            CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(timestamp_ms);

            CREATE TABLE IF NOT EXISTS process_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ms INTEGER NOT NULL,
                pid          INTEGER NOT NULL,
                ppid         INTEGER NOT NULL,
                uid          INTEGER NOT NULL,
                comm         TEXT NOT NULL,
                cmdline      TEXT NOT NULL,
                start_time_ticks INTEGER,
                boot_id      TEXT,
                exe          TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_process_events_ts ON process_events(timestamp_ms);",
        )?;
        let file_columns = conn
            .prepare("PRAGMA table_info(file_events)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if !file_columns.iter().any(|name| name == "event_json") {
            conn.execute_batch("ALTER TABLE file_events ADD COLUMN event_json TEXT")?;
        }
        for (name, declaration) in [
            ("start_time_ticks", "INTEGER"),
            ("boot_id", "TEXT"),
            ("exe", "TEXT"),
            ("event_json", "TEXT"),
        ] {
            let mut stmt = conn.prepare("PRAGMA table_info(process_events)")?;
            let columns = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if !columns.iter().any(|column| column == name) {
                conn.execute_batch(&format!(
                    "ALTER TABLE process_events ADD COLUMN {name} {declaration}"
                ))?;
            }
        }
        outbox::init_schema(&conn)?;
        response_audit::init_schema(&conn)?;
        Ok(Self { conn })
    }

    /// 읽기 전용으로 연다 (CLI용). 파일이 없으면 오류.
    pub fn open_readonly(path: &Path) -> Result<Self, StorageError> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
    }

    pub fn insert_file_event(&self, e: &FileEvent) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO file_events (timestamp_ms, pid, path, action, size, entropy, event_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                e.timestamp_ms as i64,
                e.pid,
                e.path,
                format!("{:?}", e.action),
                e.size.map(|s| s as i64),
                e.entropy,
                serde_json::to_string(e)?,
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

    pub fn insert_process_event(&self, e: &ProcessEvent) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO process_events (timestamp_ms, pid, ppid, uid, comm, cmdline, start_time_ticks, boot_id, exe, event_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![e.timestamp_ms as i64, e.pid, e.ppid, e.uid, e.comm, e.cmdline, e.start_time_ticks, e.boot_id, e.exe, serde_json::to_string(e)?],
        )?;
        Ok(())
    }

    /// 최근 프로세스 이벤트 (ts, pid, ppid, uid, comm, cmdline) — 최신순.
    pub fn recent_processes(
        &self,
        limit: usize,
    ) -> Result<Vec<(i64, u32, u32, u32, String, String)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ms, pid, ppid, uid, comm, cmdline FROM process_events
             ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// 시간 구간 내 프로세스 이벤트 — AI 분석 근거용 (오래된 순).
    pub fn processes_between(
        &self,
        from_ms: i64,
        to_ms: i64,
        limit: usize,
    ) -> Result<Vec<(i64, u32, u32, u32, String, String)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ms, pid, ppid, uid, comm, cmdline FROM process_events
             WHERE timestamp_ms BETWEEN ?1 AND ?2 ORDER BY id ASC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![from_ms, to_ms, limit as i64], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// id로 탐지 1건 조회 (CLI explain용).
    pub fn detection_by_id(&self, id: i64) -> Result<Option<DetectionRow>, StorageError> {
        use rusqlite::OptionalExtension;
        let row = self
            .conn
            .query_row(
                "SELECT id, timestamp_ms, rule, score, severity, summary, pid, paths_json
                 FROM detections WHERE id = ?1",
                params![id],
                |r| {
                    let paths_json: String = r.get(7)?;
                    Ok(DetectionRow {
                        id: r.get(0)?,
                        timestamp_ms: r.get(1)?,
                        rule: r.get(2)?,
                        score: r.get(3)?,
                        severity: r.get(4)?,
                        summary: r.get(5)?,
                        pid: r.get(6)?,
                        paths: serde_json::from_str(&paths_json).unwrap_or_default(),
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// 최근 탐지의 id 목록 포함 조회 (CLI threats에서 id 노출용).
    pub fn recent_detections_with_id(
        &self,
        limit: usize,
    ) -> Result<Vec<DetectionRow>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp_ms, rule, score, severity, summary, pid, paths_json
             FROM detections ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                let paths_json: String = r.get(7)?;
                Ok(DetectionRow {
                    id: r.get(0)?,
                    timestamp_ms: r.get(1)?,
                    rule: r.get(2)?,
                    score: r.get(3)?,
                    severity: r.get(4)?,
                    summary: r.get(5)?,
                    pid: r.get(6)?,
                    paths: serde_json::from_str(&paths_json).unwrap_or_default(),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// 시간 구간 내 파일 이벤트 (ts, pid, action, path) — 오래된 순.
    /// AI 분석의 근거 로그로 사용한다.
    pub fn events_between(
        &self,
        from_ms: i64,
        to_ms: i64,
        limit: usize,
    ) -> Result<Vec<(i64, u32, String, String)>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ms, pid, action, path FROM file_events
             WHERE timestamp_ms BETWEEN ?1 AND ?2 ORDER BY id ASC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![from_ms, to_ms, limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// 양 끝을 포함한 구간의 원본 파일 이벤트를 (시각, ID) 순서로 조회한다.
    /// 제한 때문에 잘린 경우를 명시하며 건수와 행은 같은 읽기 스냅샷에서 얻는다.
    pub fn file_events_in_range(
        &self,
        from_ms: u64,
        to_ms: u64,
        limit: usize,
    ) -> Result<FileEventRange, StorageError> {
        if from_ms > to_ms || to_ms > i64::MAX as u64 {
            return Err(StorageError::InvalidRange(
                "시작 ≤ 종료 ≤ i64::MAX여야 합니다".into(),
            ));
        }
        if limit == 0 || limit > i64::MAX as usize {
            return Err(StorageError::InvalidRange(
                "조회 제한은 양수여야 합니다".into(),
            ));
        }
        let tx = self.conn.unchecked_transaction()?;
        let total_events: u64 = tx.query_row(
            "SELECT COUNT(*) FROM file_events WHERE timestamp_ms BETWEEN ?1 AND ?2",
            params![from_ms as i64, to_ms as i64],
            |r| r.get(0),
        )?;
        let events = {
            let columns = evidence::optional_columns(
                &tx,
                "file_events",
                "id, timestamp_ms, pid, path, action, size, entropy",
                &["event_json"],
            )?;
            let mut stmt = tx.prepare(&format!(
                "SELECT {columns} FROM file_events
                 WHERE timestamp_ms BETWEEN ?1 AND ?2
                 ORDER BY timestamp_ms ASC, id ASC LIMIT ?3"
            ))?;
            let rows = stmt.query_map(
                params![from_ms as i64, to_ms as i64, limit as i64],
                decode_file_event,
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        tx.commit()?;
        Ok(FileEventRange {
            from_ms,
            to_ms,
            total_events,
            truncated: (events.len() as u64) < total_events,
            events,
        })
    }

    pub fn event_count(&self) -> Result<i64, StorageError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM file_events", [], |r| r.get(0))?)
    }

    /// 시험 이전의 마지막 ID. 시계 역전이나 과거 경로 기록을 시험 성공으로 오인하지 않는다.
    pub fn last_file_event_id(&self) -> Result<i64, StorageError> {
        Ok(self
            .conn
            .query_row("SELECT COALESCE(MAX(id),0) FROM file_events", [], |r| {
                r.get(0)
            })?)
    }
    /// 지정한 새 시험 파일의 저장된 Create/Modify 행을 확인한다. 전체 이벤트를 메모리에 읽지 않는다.
    pub fn probe_file_event(
        &self,
        path: &str,
        after_id: i64,
    ) -> Result<Option<(i64, i64)>, StorageError> {
        use rusqlite::OptionalExtension;
        Ok(self.conn.query_row("SELECT id,timestamp_ms FROM file_events WHERE id>?1 AND path=?2 AND action IN ('Create','Modify') ORDER BY id LIMIT 1",params![after_id,path],|r|Ok((r.get(0)?,r.get(1)?))).optional()?)
    }

    pub fn detection_count(&self) -> Result<i64, StorageError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM detections", [], |r| r.get(0))?)
    }
}

fn decode_file_event(r: &rusqlite::Row<'_>) -> rusqlite::Result<FileEventRow> {
    let action_name: String = r.get(4)?;
    let action = match action_name.as_str() {
        "Create" => FileAction::Create,
        "Modify" => FileAction::Modify,
        "Delete" => FileAction::Delete,
        "Rename" => FileAction::Rename,
        "Chmod" => FileAction::Chmod,
        "Chown" => FileAction::Chown,
        _ => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("알 수 없는 파일 행위: {action_name}"),
                )),
            ))
        }
    };
    let entropy: Option<f64> = r.get(6)?;
    if entropy.is_some_and(|e| !e.is_finite() || !(0.0..=8.0).contains(&e)) {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Real,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "엔트로피는 유한한 0~8 값이어야 합니다",
            )),
        ));
    }
    let json: Option<String> = r.get(7)?;
    let mut value = match json {
        Some(json) => serde_json::from_str::<serde_json::Value>(&json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?,
        None => serde_json::json!({}),
    };
    if !value.is_object() {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "파일 이벤트 JSON은 객체여야 합니다",
            )),
        ));
    }
    // 인덱스 열을 정규 값으로 사용하고 추가 수집 맥락만 JSON에서 보존한다.
    value["timestamp_ms"] = serde_json::json!(r.get::<_, u64>(1)?);
    value["pid"] = serde_json::json!(r.get::<_, u32>(2)?);
    value["path"] = serde_json::json!(r.get::<_, String>(3)?);
    value["action"] = serde_json::json!(action);
    value["size"] = serde_json::json!(r.get::<_, Option<u64>>(5)?);
    value["entropy"] = serde_json::json!(entropy);
    let event = serde_json::from_value(value).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(FileEventRow {
        id: r.get(0)?,
        event,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_common::{FileAction, Severity};

    fn with_store(label: &str, run: impl FnOnce(&EventStore, &Path)) {
        let dir =
            std::env::temp_dir().join(format!("argos-storage-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = dir.join("events.db");
        let store = EventStore::open(&db).unwrap();
        run(&store, &db);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn file_event(timestamp_ms: u64) -> FileEvent {
        FileEvent {
            timestamp_ms,
            pid: 42,
            path: format!("/data/{timestamp_ms}"),
            action: FileAction::Modify,
            size: Some(123),
            entropy: Some(7.8),
            content: None,
            process: None,
        }
    }

    #[test]
    fn range_is_readonly_ordered_inclusive_and_reports_truncation() {
        with_store("range", |store, db| {
            for ts in [30, 10, 20, 20, 40] {
                store.insert_file_event(&file_event(ts)).unwrap();
            }
            let readonly = EventStore::open_readonly(db).unwrap();
            let range = readonly.file_events_in_range(10, 30, 3).unwrap();
            assert_eq!(range.total_events, 4);
            assert!(range.truncated);
            assert_eq!(
                range.events.iter().map(|r| r.id).collect::<Vec<_>>(),
                [2, 3, 4]
            );
            assert_eq!(range.events[0].event.size, Some(123));
            assert_eq!(range.events[0].event.entropy, Some(7.8));
            assert_eq!(range.events[0].event.action, FileAction::Modify);
            assert_eq!(readonly.event_count().unwrap(), 5);
            let complete = readonly.file_events_in_range(10, 30, 4).unwrap();
            assert!(!complete.truncated);
            assert_eq!(complete.events.last().unwrap().event.timestamp_ms, 30);
            assert!(readonly.insert_file_event(&file_event(50)).is_err());
        });
    }

    #[test]
    fn range_rejects_invalid_limits_and_unknown_actions() {
        with_store("range-invalid", |store, _| {
            assert!(store.file_events_in_range(30, 10, 10).is_err());
            assert!(store.file_events_in_range(0, u64::MAX, 10).is_err());
            assert!(store.file_events_in_range(0, 30, 0).is_err());
            store.insert_file_event(&file_event(10)).unwrap();
            store
                .conn
                .execute("UPDATE file_events SET action = 'Unexpected'", [])
                .unwrap();
            assert!(store.file_events_in_range(0, 30, 10).is_err());
            let empty = store.file_events_in_range(31, 40, 10).unwrap();
            assert_eq!(empty.total_events, 0);
            assert!(!empty.truncated);
        });
    }

    #[test]
    fn range_rejects_corrupt_entropy() {
        with_store("range-entropy", |store, _| {
            let mut event = file_event(10);
            event.entropy = Some(9.0);
            store.insert_file_event(&event).unwrap();
            assert!(store.file_events_in_range(0, 30, 10).is_err());
        });
    }

    #[test]
    fn file_process_context_survives_storage_and_invalid_json_is_rejected() {
        with_store("process-context", |store, _| {
            let mut event = file_event(10);
            event.process = Some(argos_common::FileProcessContext {
                uid: 1000,
                exe: "/bin/deploy".into(),
                start_time_ticks: 777,
                boot_id: "boot-a".into(),
                ancestors: vec![],
            });
            store.insert_file_event(&event).unwrap();
            assert_eq!(
                store.file_events_in_range(0, 20, 10).unwrap().events[0]
                    .event
                    .process,
                event.process
            );
            store
                .conn
                .execute("UPDATE file_events SET event_json='\"broken\"'", [])
                .unwrap();
            assert!(store.file_events_in_range(0, 20, 10).is_err());
        });
    }

    #[test]
    fn legacy_readonly_evidence_and_migration_preserve_unknown_identity() {
        let dir = std::env::temp_dir().join(format!("argos-storage-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("old.db");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE file_events(id INTEGER PRIMARY KEY,timestamp_ms INTEGER,pid INTEGER,path TEXT,action TEXT,size INTEGER,entropy REAL);
            INSERT INTO file_events VALUES(1,10,42,'/data/a','Modify',10,7.8);
            CREATE TABLE process_events(id INTEGER PRIMARY KEY,timestamp_ms INTEGER,pid INTEGER,ppid INTEGER,uid INTEGER,comm TEXT,cmdline TEXT);
            INSERT INTO process_events VALUES(1,10,42,1,1000,'old','old --job');
            CREATE TABLE detections(id INTEGER PRIMARY KEY,timestamp_ms INTEGER,rule TEXT,score REAL,severity TEXT,summary TEXT,pid INTEGER,paths_json TEXT);").unwrap();
        drop(db);
        let reader = EventStore::open_readonly(&path).unwrap();
        let evidence = reader
            .query_evidence(&EvidenceQuery {
                from_ms: 0,
                to_ms: 20,
                pid: None,
                limit: 10,
            })
            .unwrap();
        assert_eq!(evidence.files.rows[0].event.process, None);
        assert_eq!(evidence.processes.rows[0].event.start_time_ticks, None);
        assert_eq!(
            reader.file_events_in_range(0, 20, 10).unwrap().events.len(),
            1
        );
        drop(reader);
        let migrated = EventStore::open(&path).unwrap();
        assert_eq!(migrated.event_count().unwrap(), 1);
        assert_eq!(migrated.outbox_stats("a").unwrap().pending, 0);
        assert_eq!(
            migrated.file_events_in_range(0, 20, 10).unwrap().events[0]
                .event
                .process,
            None
        );
        drop(migrated);
        let _ = std::fs::remove_dir_all(dir);
    }

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
                content: None,
                process: None,
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
