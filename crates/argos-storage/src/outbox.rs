//! 탐지와 같은 트랜잭션으로 저장하는 중앙 전송·사건 보존 작업 대기열.
//! 보존 작업은 별도 작업자가 완료한 뒤 삭제하며, 용량 초과도 영속 계수로 남긴다.

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

#[derive(Debug, Clone)]
pub struct RetentionJob {
    pub detection_id: i64,
    pub detection: Detection,
    pub attempts: u64,
}

#[derive(Debug, Clone)]
pub struct RetentionStats {
    pub pending: u64,
    pub failed_attempts: u64,
    pub overflow: u64,
    pub completed: u64,
}

const RETENTION_CAPACITY: i64 = 10_000;

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
        );
        CREATE TABLE IF NOT EXISTS retention_jobs (
            detection_id INTEGER PRIMARY KEY,
            detection_json TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            next_attempt_ms INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_retention_due ON retention_jobs(next_attempt_ms,detection_id);
        CREATE TABLE IF NOT EXISTS retention_counters (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            overflow INTEGER NOT NULL DEFAULT 0,
            completed INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO retention_counters(singleton) VALUES(1);",
    )
}

impl EventStore {
    /// 탐지·outbox·사건 보존 요청을 같은 트랜잭션으로 기록한다.
    /// 보존 큐 10,000건 초과 시 탐지는 유지하며 누락을 영속 계수에 남긴다.
    /// 이 경로는 백업 DB나 객체 저장소에 접근하지 않는다.
    pub fn record_detection(
        &self,
        d: &Detection,
        agent_id: Option<&str>,
        retain: bool,
    ) -> Result<i64, StorageError> {
        if agent_id.is_some_and(|id| id.trim().is_empty()) {
            return Err(StorageError::InvalidRange("에이전트 ID 없음".into()));
        }
        let tx = self.conn.unchecked_transaction()?;
        self.insert_detection(d)?;
        let id = tx.last_insert_rowid();
        if let Some(agent_id) = agent_id {
            tx.execute("INSERT INTO detection_outbox (delivery_id,agent_id,detection_json,created_at_ms) VALUES (lower(hex(randomblob(16))),?1,?2,?3)", params![agent_id, serde_json::to_string(d)?, argos_common::now_ms() as i64])?;
        }
        if retain {
            let pending: i64 =
                tx.query_row("SELECT COUNT(*) FROM retention_jobs", [], |r| r.get(0))?;
            if pending < RETENTION_CAPACITY {
                tx.execute(
                    "INSERT INTO retention_jobs(detection_id,detection_json) VALUES(?1,?2)",
                    params![id, serde_json::to_string(d)?],
                )?;
            } else {
                tx.execute(
                    "UPDATE retention_counters SET overflow=overflow+1 WHERE singleton=1",
                    [],
                )?;
            }
        }
        tx.commit()?;
        Ok(id)
    }

    /// 반환 시 읽기 statement는 닫혀 있다. 백업 DB 잠금 대기 중 이벤트 DB를 잡지 않는다.
    pub fn pending_retention_jobs(
        &self,
        now_ms: u64,
        limit: usize,
    ) -> Result<Vec<RetentionJob>, StorageError> {
        if limit == 0 || limit > 100 || now_ms > i64::MAX as u64 {
            return Err(StorageError::InvalidRange(
                "보존 묶음은 1~100건, 시각은 i64 범위여야 합니다".into(),
            ));
        }
        let mut stmt=self.conn.prepare("SELECT detection_id,detection_json,attempts FROM retention_jobs WHERE next_attempt_ms<=?1 ORDER BY next_attempt_ms,detection_id LIMIT ?2")?;
        let rows = stmt
            .query_map(params![now_ms as i64, limit as i64], |r| {
                let payload: String = r.get(1)?;
                Ok(RetentionJob {
                    detection_id: r.get(0)?,
                    detection: serde_json::from_str(&payload).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                    attempts: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn acknowledge_retention_job(&self, id: i64) -> Result<(), StorageError> {
        let tx = self.conn.unchecked_transaction()?;
        if tx.execute(
            "DELETE FROM retention_jobs WHERE detection_id=?1",
            params![id],
        )? > 0
        {
            tx.execute(
                "UPDATE retention_counters SET completed=completed+1 WHERE singleton=1",
                [],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn record_retention_failure(
        &self,
        id: i64,
        error: &str,
        next_attempt_ms: u64,
    ) -> Result<(), StorageError> {
        if next_attempt_ms > i64::MAX as u64 {
            return Err(StorageError::InvalidRange(
                "보존 재시도 시각 범위 초과".into(),
            ));
        }
        let tx = self.conn.unchecked_transaction()?;
        if tx.execute("UPDATE retention_jobs SET attempts=attempts+1,last_error=?2,next_attempt_ms=?3 WHERE detection_id=?1",params![id,error.chars().take(512).collect::<String>(),next_attempt_ms as i64])?>0 {
            tx.execute("UPDATE retention_counters SET failed_attempts=failed_attempts+1 WHERE singleton=1",[])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn retention_stats(&self) -> Result<RetentionStats, StorageError> {
        Ok(self.conn.query_row("SELECT (SELECT COUNT(*) FROM retention_jobs),failed_attempts,overflow,completed FROM retention_counters WHERE singleton=1",[],|r|Ok(RetentionStats{pending:r.get(0)?,failed_attempts:r.get(1)?,overflow:r.get(2)?,completed:r.get(3)?}))?)
    }
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

    fn retention_detection() -> Detection {
        Detection {
            timestamp_ms: 10,
            rule: "test".into(),
            score: 90.0,
            severity: Severity::Critical,
            summary: "test".into(),
            pid: 42,
            paths: vec!["/data/a".into()],
        }
    }

    #[test]
    fn retention_requests_survive_restart_and_backoff_without_losing_detection() {
        let dir =
            std::env::temp_dir().join(format!("argos-retention-outbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = dir.join("events.db");
        let store = EventStore::open(&db).unwrap();
        let id = store
            .record_detection(&retention_detection(), Some("a"), true)
            .unwrap();
        assert_eq!(store.detection_count().unwrap(), 1);
        assert_eq!(store.pending_deliveries("a", 10).unwrap().len(), 1);
        store.record_retention_failure(id, "locked", 100).unwrap();
        drop(store);
        let store = EventStore::open(&db).unwrap();
        assert!(store.pending_retention_jobs(99, 10).unwrap().is_empty());
        let jobs = store.pending_retention_jobs(100, 10).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].detection_id, id);
        assert_eq!(jobs[0].attempts, 1);
        assert_eq!(jobs[0].detection.paths, vec!["/data/a"]);
        store.acknowledge_retention_job(id).unwrap();
        store.acknowledge_retention_job(id).unwrap();
        let stats = store.retention_stats().unwrap();
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.failed_attempts, 1);
        assert_eq!(store.detection_count().unwrap(), 1);
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retention_capacity_keeps_detection_and_persistent_overflow_count() {
        let dir =
            std::env::temp_dir().join(format!("argos-retention-capacity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = dir.join("events.db");
        let store = EventStore::open(&db).unwrap();
        let payload = serde_json::to_string(&retention_detection()).unwrap();
        store.conn.execute("WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<10000) INSERT INTO retention_jobs(detection_id,detection_json) SELECT n,?1 FROM ids",params![payload]).unwrap();
        store
            .record_detection(&retention_detection(), Some("a"), true)
            .unwrap();
        assert_eq!(store.detection_count().unwrap(), 1);
        assert_eq!(store.outbox_stats("a").unwrap().pending, 1);
        drop(store);
        let store = EventStore::open(&db).unwrap();
        let stats = store.retention_stats().unwrap();
        assert_eq!(stats.pending, 10_000);
        assert_eq!(stats.overflow, 1);
        assert!(store.pending_retention_jobs(0, 101).is_err());
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }

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
