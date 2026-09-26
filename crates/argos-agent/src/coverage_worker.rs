use argos_common::config::{CoverageConfig, SensorKind};
use argos_sensor::coverage::{CoverageInspector, CoverageReport};
use std::{
    io,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

struct Snapshot {
    report: CoverageReport,
    started: Instant,
}

/// 탐색은 별도 작업자에서 수행한다. 막힌 파일시스템 I/O를 기다리며 종료를 막지 않는다.
pub struct CoverageWorker {
    report: Arc<Mutex<Option<Snapshot>>>,
    stop: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    interval_secs: u64,
}
struct Liveness(Arc<AtomicBool>);
impl Drop for Liveness {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl CoverageWorker {
    /// 호환 호출. 실제 센서에 전달한 경로가 있으면 spawn_registered를 사용한다.
    #[allow(dead_code)]
    pub fn spawn(
        config: &CoverageConfig,
        sensor: SensorKind,
        paths: &[PathBuf],
    ) -> io::Result<Self> {
        Self::start(
            config,
            CoverageInspector::new(paths, sensor, config.max_entries)?,
        )
    }
    pub fn spawn_registered(
        config: &CoverageConfig,
        sensor: SensorKind,
        paths: &[PathBuf],
        registered_paths: &[PathBuf],
    ) -> io::Result<Self> {
        Self::start(
            config,
            CoverageInspector::new_registered(paths, registered_paths, sensor, config.max_entries)?,
        )
    }
    fn start(config: &CoverageConfig, inspector: CoverageInspector) -> io::Result<Self> {
        if !(1..=3600).contains(&config.interval_secs) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "coverage.interval_secs는 1~3600 필요",
            ));
        }
        let report = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let alive = Arc::new(AtomicBool::new(true));
        let thread_report = report.clone();
        let thread_stop = stop.clone();
        let thread_alive = alive.clone();
        let interval = config.interval_secs;
        std::thread::Builder::new()
            .name("argos-coverage".into())
            .spawn(move || {
                let _alive = Liveness(thread_alive);
                while !thread_stop.load(Ordering::Acquire) {
                    let started = Instant::now();
                    let latest = inspector.inspect();
                    if latest.has_gap() {
                        tracing::warn!("보호 경로 공백/검사 누락 — coverage 지표 확인 필요");
                    }
                    if let Ok(mut slot) = thread_report.lock() {
                        *slot = Some(Snapshot {
                            report: latest,
                            started,
                        });
                    } else {
                        break;
                    }
                    for _ in 0..interval * 10 {
                        if thread_stop.load(Ordering::Acquire) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            })?;
        Ok(Self {
            report,
            stop,
            alive,
            interval_secs: config.interval_secs,
        })
    }
    pub fn status(&self) -> (bool, serde_json::Value) {
        let alive = self.alive.load(Ordering::Acquire);
        let Ok(slot) = self.report.lock() else {
            return (
                false,
                serde_json::json!({"enabled":true,"worker_alive":alive,"stale":true,"assessment":"unavailable"}),
            );
        };
        match slot.as_ref() {
            Some(snapshot) => {
                // 벽시계 역행도 오류로 표시하되 경과 시간은 단조 시계로 판정한다.
                let age_ms = snapshot.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                let stale = age_ms > self.interval_secs.saturating_mul(2000).max(60_000)
                    || argos_common::now_ms() < snapshot.report.checked_at_ms;
                (
                    !stale && alive && !snapshot.report.has_gap(),
                    serde_json::json!({"enabled":true,"worker_alive":alive,"age_ms":age_ms,"stale":stale,"report":snapshot.report}),
                )
            }
            None => (
                false,
                serde_json::json!({"enabled":true,"worker_alive":alive,"stale":true,"assessment":"pending_or_unavailable"}),
            ),
        }
    }
}
impl Drop for CoverageWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn worker(report: Option<CoverageReport>, age: Duration, alive: bool) -> CoverageWorker {
        CoverageWorker {
            report: Arc::new(Mutex::new(report.map(|report| Snapshot {
                report,
                started: Instant::now() - age,
            }))),
            stop: Arc::new(AtomicBool::new(false)),
            alive: Arc::new(AtomicBool::new(alive)),
            interval_secs: 1,
        }
    }
    fn report() -> CoverageReport {
        CoverageReport {
            checked_at_ms: argos_common::now_ms(),
            assessment: "no_observed_gap".into(),
            mount_namespace: None,
            roots: vec![],
            limitations: vec![],
        }
    }
    #[test]
    fn pending_stale_dead_and_backward_clock_are_unhealthy() {
        let pending = worker(None, Duration::ZERO, true);
        assert!(!pending.status().0);
        assert_eq!(pending.status().1["assessment"], "pending_or_unavailable");
        let fresh = worker(Some(report()), Duration::ZERO, true);
        assert!(fresh.status().0);
        let stale = worker(Some(report()), Duration::from_secs(61), true);
        assert!(!stale.status().0);
        assert_eq!(stale.status().1["stale"], true);
        let dead = worker(Some(report()), Duration::ZERO, false);
        assert!(!dead.status().0);
        assert_eq!(dead.status().1["worker_alive"], false);
        let mut future = report();
        future.checked_at_ms += 10_000;
        assert!(!worker(Some(future), Duration::ZERO, true).status().0);
    }
    #[test]
    fn gap_cannot_be_masked_by_freshness_and_liveness_guard_reports_exit() {
        let mut gap = report();
        gap.assessment = "gap_or_incomplete".into();
        assert!(!worker(Some(gap), Duration::ZERO, true).status().0);
        let alive = Arc::new(AtomicBool::new(true));
        {
            let _guard = Liveness(alive.clone());
        }
        assert!(!alive.load(Ordering::Acquire));
    }
    #[test]
    fn drop_requests_stop_without_waiting_for_a_blocked_scan() {
        let worker = worker(Some(report()), Duration::ZERO, true);
        let stop = worker.stop.clone();
        drop(worker);
        assert!(stop.load(Ordering::Acquire));
    }
}
