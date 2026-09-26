//! AI·MCP 조사에 공통으로 사용하는 제한된 읽기 전용 근거 조회.

use crate::{decode_file_event, DetectionRow, EventStore, FileEventRow, StorageError};
use argos_common::ProcessEvent;
use rusqlite::{params, Transaction};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct EvidenceQuery {
    pub from_ms: u64,
    pub to_ms: u64,
    pub pid: Option<u32>,
    /// 종류별 최대 행 수. 전체 조회 최대치는 이 값의 3배다.
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidencePage<T> {
    pub total_rows: u64,
    pub truncated: bool,
    pub rows: Vec<T>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessEventRow {
    pub id: i64,
    pub event: ProcessEvent,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceBundle {
    pub from_ms: u64,
    pub to_ms: u64,
    pub pid: Option<u32>,
    pub files: EvidencePage<FileEventRow>,
    pub detections: EvidencePage<DetectionRow>,
    pub processes: EvidencePage<ProcessEventRow>,
}

impl EventStore {
    /// 동일한 읽기 스냅샷에서 기간·PID 조건에 맞는 근거와 전체 건수를 조회한다.
    /// 각 종류의 ID는 독립적이므로 인용 시 file/process/detection 종류를 붙여야 한다.
    pub fn query_evidence(&self, query: &EvidenceQuery) -> Result<EvidenceBundle, StorageError> {
        if query.from_ms > query.to_ms || query.to_ms > i64::MAX as u64 {
            return Err(StorageError::InvalidRange(
                "시작 ≤ 종료 ≤ i64::MAX여야 합니다".into(),
            ));
        }
        if query.limit == 0 || query.limit > 10_000 {
            return Err(StorageError::InvalidRange(
                "근거 조회 제한은 종류별 1~10,000건이어야 합니다".into(),
            ));
        }
        let tx = self.conn.unchecked_transaction()?;
        let file_columns = optional_columns(
            &tx,
            "file_events",
            "id, timestamp_ms, pid, path, action, size, entropy",
            &["event_json"],
        )?;
        let files = query_page(&tx, "file_events", &file_columns, query, decode_file_event)?;
        let detections = query_page(
            &tx,
            "detections",
            "id, timestamp_ms, rule, score, severity, summary, pid, paths_json",
            query,
            |r| {
                let paths: String = r.get(7)?;
                Ok(DetectionRow {
                    id: r.get(0)?,
                    timestamp_ms: r.get(1)?,
                    rule: r.get(2)?,
                    score: r.get(3)?,
                    severity: r.get(4)?,
                    summary: r.get(5)?,
                    pid: r.get(6)?,
                    paths: serde_json::from_str(&paths).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                })
            },
        )?;
        let process_columns = optional_columns(
            &tx,
            "process_events",
            "id, timestamp_ms, pid, ppid, uid, comm, cmdline",
            &["start_time_ticks", "boot_id", "exe"],
        )?;
        let processes = query_page(&tx, "process_events", &process_columns, query, |r| {
            Ok(ProcessEventRow {
                id: r.get(0)?,
                event: ProcessEvent {
                    timestamp_ms: r.get(1)?,
                    pid: r.get(2)?,
                    ppid: r.get(3)?,
                    uid: r.get(4)?,
                    comm: r.get(5)?,
                    cmdline: r.get(6)?,
                    start_time_ticks: r.get(7)?,
                    boot_id: r.get(8)?,
                    exe: r.get(9)?,
                },
            })
        })?;
        tx.commit()?;
        Ok(EvidenceBundle {
            from_ms: query.from_ms,
            to_ms: query.to_ms,
            pid: query.pid,
            files,
            detections,
            processes,
        })
    }
}

// SQL 식별자는 이 모듈의 고정 문자열만 전달한다. 사용자 입력은 전부 바인딩한다.
pub(crate) fn query_page<T>(
    tx: &Transaction<'_>,
    table: &'static str,
    columns: &str,
    query: &EvidenceQuery,
    decode: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<EvidencePage<T>, StorageError> {
    let filter = "timestamp_ms BETWEEN ?1 AND ?2 AND (?3 IS NULL OR pid = ?3)";
    let total_rows = tx.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE {filter}"),
        params![query.from_ms as i64, query.to_ms as i64, query.pid],
        |r| r.get(0),
    )?;
    let mut stmt = tx.prepare(&format!(
        "SELECT {columns} FROM {table} WHERE {filter} ORDER BY timestamp_ms ASC, id ASC LIMIT ?4"
    ))?;
    let rows = stmt
        .query_map(
            params![
                query.from_ms as i64,
                query.to_ms as i64,
                query.pid,
                query.limit as i64
            ],
            decode,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(EvidencePage {
        total_rows,
        truncated: (rows.len() as u64) < total_rows,
        rows,
    })
}

// 읽기 전용 CLI는 스키마를 변경하지 않고 이전 DB의 새 선택 필드를 NULL로 제공한다.
pub(crate) fn optional_columns(
    conn: &rusqlite::Connection,
    table: &str,
    base: &str,
    optional: &[&str],
) -> Result<String, StorageError> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut columns = base.to_string();
    for name in optional {
        columns.push_str(", ");
        if names.iter().any(|n| n == name) {
            columns.push_str(name);
        } else {
            columns.push_str("NULL");
        }
    }
    Ok(columns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_common::{Detection, FileAction, FileEvent, Severity};

    #[test]
    fn evidence_is_filtered_bounded_ordered_and_readonly() {
        let dir = std::env::temp_dir().join(format!("argos-evidence-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = dir.join("events.db");
        let writer = EventStore::open(&db).unwrap();
        for (ts, pid) in [(30, 42), (10, 42), (20, 43), (20, 42), (40, 42)] {
            writer
                .insert_file_event(&FileEvent {
                    timestamp_ms: ts,
                    pid,
                    path: format!("/data/{ts}"),
                    action: FileAction::Modify,
                    size: None,
                    entropy: Some(7.5),
                    process: None,
                })
                .unwrap();
            writer
                .insert_detection(&Detection {
                    timestamp_ms: ts,
                    rule: "test".into(),
                    score: 90.0,
                    severity: Severity::Critical,
                    summary: "근거".into(),
                    pid,
                    paths: vec![format!("/data/{ts}")],
                })
                .unwrap();
            writer
                .insert_process_event(&ProcessEvent {
                    timestamp_ms: ts,
                    pid,
                    ppid: 1,
                    uid: 1000,
                    comm: "test".into(),
                    cmdline: "test --file".into(),
                    start_time_ticks: Some(123),
                    boot_id: Some("boot-a".into()),
                    exe: Some("/bin/test".into()),
                })
                .unwrap();
        }
        let reader = EventStore::open_readonly(&db).unwrap();
        let query = EvidenceQuery {
            from_ms: 10,
            to_ms: 30,
            pid: Some(42),
            limit: 2,
        };
        let bundle = reader.query_evidence(&query).unwrap();
        assert_eq!(bundle.files.total_rows, 3);
        assert_eq!(bundle.detections.total_rows, 3);
        assert_eq!(bundle.processes.total_rows, 3);
        assert!(
            bundle.files.truncated && bundle.detections.truncated && bundle.processes.truncated
        );
        assert_eq!(
            bundle.files.rows.iter().map(|r| r.id).collect::<Vec<_>>(),
            [2, 4]
        );
        assert_eq!(bundle.detections.rows[1].timestamp_ms, 20);
        assert_eq!(bundle.processes.rows[0].event.uid, 1000);
        assert_eq!(bundle.processes.rows[0].event.start_time_ticks, Some(123));
        assert!(serde_json::to_value(&bundle).unwrap()["files"]["truncated"]
            .as_bool()
            .unwrap());
        let all = reader
            .query_evidence(&EvidenceQuery {
                pid: None,
                limit: 100,
                ..query.clone()
            })
            .unwrap();
        assert_eq!(all.files.total_rows, 4);
        assert!(!all.files.truncated);
        assert_eq!(writer.event_count().unwrap(), 5);
        assert!(reader
            .query_evidence(&EvidenceQuery {
                limit: 0,
                ..query.clone()
            })
            .is_err());
        assert!(reader
            .query_evidence(&EvidenceQuery {
                limit: 10_001,
                ..query.clone()
            })
            .is_err());
        assert!(reader
            .query_evidence(&EvidenceQuery {
                from_ms: 31,
                ..query
            })
            .is_err());
        drop(reader);
        drop(writer);
        let _ = std::fs::remove_dir_all(dir);
    }
}
