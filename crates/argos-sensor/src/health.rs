//! 수집 경로의 독립적인 상태와 유실 계수. 가득 찬 큐에서 수집 스레드를 기다리게 하지 않는다.

use argos_common::now_ms;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{error::TrySendError, Sender};

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct SensorHealthSnapshot {
    /// 핸들이 유지되고 리더가 종료되지 않았음. notify 내부 OS 스레드의 별도 생존 검사는 아니다.
    pub alive: bool,
    pub delivered_events: u64,
    /// 에이전트 큐가 가득 차서 버린 이벤트 수. 커널 내부에서 잃은 개수는 알 수 없다.
    pub dropped_events: u64,
    pub errors: u64,
    /// fanotify 큐 넘침 또는 notify의 재스캔 요구 횟수.
    pub kernel_overflows: u64,
    /// 마지막 수집 시도 시각. 이벤트가 없으면 None이며, 그 자체로 센서 중단을 의미하지 않는다.
    pub last_event_ms: Option<u64>,
}

#[derive(Default)]
struct Counters {
    alive: AtomicBool,
    delivered: AtomicU64,
    dropped: AtomicU64,
    errors: AtomicU64,
    overflows: AtomicU64,
    last_event: AtomicU64,
}

#[derive(Clone, Default)]
pub(crate) struct SensorHealth(Arc<Counters>);

impl SensorHealth {
    pub fn start(&self) {
        self.0.alive.store(true, Ordering::Release);
    }
    pub fn stop(&self) {
        self.0.alive.store(false, Ordering::Release);
    }
    pub fn error(&self) {
        self.0.errors.fetch_add(1, Ordering::Relaxed);
    }
    pub fn overflow(&self) {
        self.0.overflows.fetch_add(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> SensorHealthSnapshot {
        let last = self.0.last_event.load(Ordering::Relaxed);
        SensorHealthSnapshot {
            alive: self.0.alive.load(Ordering::Acquire),
            delivered_events: self.0.delivered.load(Ordering::Relaxed),
            dropped_events: self.0.dropped.load(Ordering::Relaxed),
            errors: self.0.errors.load(Ordering::Relaxed),
            kernel_overflows: self.0.overflows.load(Ordering::Relaxed),
            last_event_ms: (last != 0).then_some(last),
        }
    }
    /// false이면 수신측 종료. 큐 포화에서는 유실을 기록하고 계속 커널 큐를 비운다.
    pub fn deliver<T>(&self, tx: &Sender<T>, event: T) -> bool {
        self.0.last_event.store(now_ms(), Ordering::Relaxed);
        match tx.try_send(event) {
            Ok(()) => {
                self.0.delivered.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_)) => {
                self.0.dropped.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Closed(_)) => {
                self.stop();
                false
            }
        }
    }
}

pub(crate) struct LivenessGuard(pub SensorHealth);
impl Drop for LivenessGuard {
    fn drop(&mut self) {
        self.0.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_queue_drops_without_blocking_and_closed_queue_stops() {
        let health = SensorHealth::default();
        health.start();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        assert!(health.deliver(&tx, 1));
        assert!(health.deliver(&tx, 2));
        let snapshot = health.snapshot();
        assert!(snapshot.alive);
        assert_eq!(snapshot.delivered_events, 1);
        assert_eq!(snapshot.dropped_events, 1);
        assert_eq!(rx.try_recv().unwrap(), 1);
        assert!(snapshot.last_event_ms.is_some());
        drop(rx);
        assert!(!health.deliver(&tx, 3));
        assert!(!health.snapshot().alive);
    }

    #[test]
    fn reader_exit_records_liveness_even_without_events() {
        let health = SensorHealth::default();
        health.start();
        {
            let _guard = LivenessGuard(health.clone());
            assert!(health.snapshot().alive);
            health.error();
            health.overflow();
        }
        let snapshot = health.snapshot();
        assert!(!snapshot.alive);
        assert_eq!(snapshot.errors, 1);
        assert_eq!(snapshot.kernel_overflows, 1);
        assert_eq!(snapshot.last_event_ms, None);
    }
}
