//! 탐지 저장과 함께 기록하고 중앙 ACK 이후에만 삭제하는 영속 전송 대기열.

use crate::{EventStore, StorageError};
use argos_common::Detection;
use rusqlite::{params, Connection};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct OutboxEntry {
    pub delivery_id: String,
    pub agent_id: String,
    pub detection: Detection,
    pub attempts: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboxStats {
    pub pending: u64,
    pub failed_attempts: u64,
    pub acknowledged: u64,
    pub oldest_pending_ms: Option<u64>,
}

pub(crate) fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS detection_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            delivery_id TEXT NOT NULL UNIQUE,
            agent_id TEXT NOT NULL,
            detection_json TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_outbox_agent ON detection_outbox(agent_id,id);
        CREATE TABLE IF NOT EXISTS delivery_counters (
            agent_id TEXT PRIMARY KEY,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            acknowledged INTEGER NOT NULL DEFAULT 0
        );",
    )
}

impl EventStore {
    /// 로컬 증거와 전송 대기를 한 트랜잭션으로 기록한다.
    /// 전송 실패·재시작에도 전달 ID를 보존해 중복 수집을 막는다.
    pub fn insert_detection_with_outbox(
        &self,
        d: &Detection,
        agent_id: &str,
    ) -> Result<(), StorageError> {
        if agent_id.trim().is_empty() {
            return Err(StorageError::InvalidRange(
                "전송할 에이전트 ID가 비어 있습니다".into(),
            ));
        }
        let payload = serde_json::to_string(d)?;
        let tx = self.conn.unchecked_transaction()?;
        self.insert_detection(d)?;
        tx.execute(
            "INSERT INTO detection_outbox (delivery_id,agent_id,detection_json,created_at_ms)
             VALUES (lower(hex(randomblob(16))),?1,?2,?3)",
            params![agent_id, payload, argos_common::now_ms() as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn pending_deliveries(
        &self,
        agent_id: &str,
        limit: usize,
    ) -> Result<Vec<OutboxEntry>, StorageError> {
        if limit == 0 || limit > 1000 {
            return Err(StorageError::InvalidRange(
                "전송 묶음은 1~1,000건이어야 합니다".into(),
            ));
        }
        let mut stmt = self.conn.prepare(
            "SELECT delivery_id,agent_id,detection_json,attempts FROM detection_outbox
             WHERE agent_id=?1 ORDER BY id ASC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![agent_id, limit as i64], |r| {
                let json: String = r.get(2)?;
                Ok(OutboxEntry {
                    delivery_id: r.get(0)?,
                    agent_id: r.get(1)?,
                    attempts: r.get(3)?,
                    detection: serde_json::from_str(&json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn acknowledge_delivery(
        &self,
        delivery_id: &str,
        agent_id: &str,
    ) -> Result<(), StorageError> {
        let tx = self.conn.unchecked_transaction()?;
        let deleted = tx.execute(
            "DELETE FROM detection_outbox WHERE delivery_id=?1 AND agent_id=?2",
            params![delivery_id, agent_id],
        )?;
        if deleted > 0 {
            tx.execute(
                "INSERT INTO delivery_counters(agent_id,acknowledged) VALUES(?1,1)
                ON CONFLICT(agent_id) DO UPDATE SET acknowledged=acknowledged+1",
                params![agent_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn record_delivery_failure(
        &self,
        delivery_id: &str,
        agent_id: &str,
        error: &str,
    ) -> Result<(), StorageError> {
        let tx = self.conn.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE detection_outbox SET attempts=attempts+1,last_error=?3
            WHERE delivery_id=?1 AND agent_id=?2",
            params![
                delivery_id,
                agent_id,
                error.chars().take(512).collect::<String>()
            ],
        )?;
        if changed > 0 {
            tx.execute(
                "INSERT INTO delivery_counters(agent_id,failed_attempts) VALUES(?1,1)
                ON CONFLICT(agent_id) DO UPDATE SET failed_attempts=failed_attempts+1",
                params![agent_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn outbox_stats(&self, agent_id: &str) -> Result<OutboxStats, StorageError> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*),MIN(created_at_ms),
             COALESCE((SELECT failed_attempts FROM delivery_counters WHERE agent_id=?1),0),
             COALESCE((SELECT acknowledged FROM delivery_counters WHERE agent_id=?1),0)
             FROM detection_outbox WHERE agent_id=?1",
            params![agent_id],
            |r| {
                Ok(OutboxStats {
                    pending: r.get(0)?,
                    oldest_pending_ms: r.get(1)?,
                    failed_attempts: r.get(2)?,
                    acknowledged: r.get(3)?,
                })
            },
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_common::Severity;

    #[test]
    fn outbox_survives_restart_and_acknowledges_only_matching_agent() {
        let dir = std::env::temp_dir().join(format!("argos-outbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = dir.join("events.db");
        let store = EventStore::open(&db).unwrap();
        let d = Detection {
            timestamp_ms: 1,
            rule: "test".into(),
            score: 90.0,
            severity: Severity::Critical,
            summary: "test".into(),
            pid: 42,
            paths: vec!["/data/a".into()],
        };
        store.insert_detection_with_outbox(&d, "a").unwrap();
        assert_eq!(store.detection_count().unwrap(), 1);
        let id = store.pending_deliveries("a", 10).unwrap()[0]
            .delivery_id
            .clone();
        store.record_delivery_failure(&id, "a", "오프라인").unwrap();
        drop(store);
        let store = EventStore::open(&db).unwrap();
        let pending = store.pending_deliveries("a", 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].delivery_id, id);
        assert_eq!(pending[0].attempts, 1);
        assert_eq!(pending[0].detection.pid, 42);
        assert!(store.pending_deliveries("b", 10).unwrap().is_empty());
        store.acknowledge_delivery(&id, "b").unwrap();
        assert_eq!(store.outbox_stats("a").unwrap().pending, 1);
        store.acknowledge_delivery(&id, "a").unwrap();
        store.acknowledge_delivery(&id, "a").unwrap();
        let stats = store.outbox_stats("a").unwrap();
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.failed_attempts, 1);
        assert_eq!(stats.acknowledged, 1);
        assert_eq!(store.detection_count().unwrap(), 1);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
}
