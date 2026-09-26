//! 대응 실행 결과를 탐지 점수와 별도로 보관하는 감사 기록.

use crate::{EventStore, EvidencePage, EvidenceQuery, StorageError};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAudit {
    pub timestamp_ms: u64,
    pub pid: u32,
    pub start_time_ticks: Option<u64>,
    pub boot_id: Option<String>,
    pub score: f64,
    pub action: String,
    pub outcome: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseAuditRow {
    pub id: i64,
    pub result: ResponseAudit,
}

pub(crate) fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS response_actions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp_ms INTEGER NOT NULL,
        pid INTEGER NOT NULL,result_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_response_actions_ts ON response_actions(timestamp_ms);",
    )
}

impl EventStore {
    pub fn insert_response_result(&self, result: &ResponseAudit) -> Result<(), StorageError> {
        if result.timestamp_ms > i64::MAX as u64
            || !result.score.is_finite()
            || !(0.0..=100.0).contains(&result.score)
        {
            return Err(StorageError::InvalidRange(
                "대응 기록의 시각·점수가 유효하지 않습니다".into(),
            ));
        }
        self.conn.execute(
            "INSERT INTO response_actions(timestamp_ms,pid,result_json) VALUES(?1,?2,?3)",
            params![
                result.timestamp_ms as i64,
                result.pid,
                serde_json::to_string(result)?
            ],
        )?;
        Ok(())
    }

    pub fn response_results(
        &self,
        query: &EvidenceQuery,
    ) -> Result<EvidencePage<ResponseAuditRow>, StorageError> {
        if query.from_ms > query.to_ms
            || query.to_ms > i64::MAX as u64
            || query.limit == 0
            || query.limit > 10_000
        {
            return Err(StorageError::InvalidRange(
                "대응 조회 구간과 제한(1~10,000)을 확인하세요".into(),
            ));
        }
        let tx = self.conn.unchecked_transaction()?;
        let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='response_actions')",[],|r|r.get(0))?;
        if !exists {
            return Ok(EvidencePage {
                total_rows: 0,
                truncated: false,
                rows: vec![],
            });
        }
        let page =
            crate::evidence::query_page(&tx, "response_actions", "id,result_json", query, |r| {
                let json: String = r.get(1)?;
                Ok(ResponseAuditRow {
                    id: r.get(0)?,
                    result: serde_json::from_str(&json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                })
            })?;
        tx.commit()?;
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn response_outcome_is_stored_separately_with_identity_and_filter() {
        let dir = std::env::temp_dir().join(format!("argos-response-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = EventStore::open(&dir.join("audit.db")).unwrap();
        for pid in [42, 43] {
            store
                .insert_response_result(&ResponseAudit {
                    timestamp_ms: 10,
                    pid,
                    start_time_ticks: Some(123),
                    boot_id: Some("boot-a".into()),
                    score: 90.0,
                    action: "kill_process_instance".into(),
                    outcome: "identity_mismatch".into(),
                    error: Some("프로세스 인스턴스 불일치".into()),
                })
                .unwrap();
        }
        let page = store
            .response_results(&EvidenceQuery {
                from_ms: 0,
                to_ms: 20,
                pid: Some(42),
                limit: 10,
            })
            .unwrap();
        assert_eq!(page.total_rows, 1);
        assert_eq!(page.rows[0].result.outcome, "identity_mismatch");
        assert_eq!(page.rows[0].result.start_time_ticks, Some(123));
        assert_eq!(store.detection_count().unwrap(), 0);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
}
