//! 크기가 제한된 별도 백업 작업자. 백업 지연/실패가 대응 판단을 막지 않는다.
use argos_common::{config::BackupConfig, FileEvent};
use argos_recovery::{BackupStore, RecoveryError};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc::{self, SyncSender},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct BackupMetrics {
    pub queued: AtomicU64,
    pub dropped: AtomicU64,
    pub failed: AtomicU64,
    pub oversized: AtomicU64,
    pub completed: AtomicU64,
    pub last_delay_ms: AtomicU64,
    pub pin_failed: AtomicU64,
    pub pin_pending: AtomicU64,
    pub pin_overflow: AtomicU64,
    pub pin_completed: AtomicU64,
    pub pin_worker_errors: AtomicU64,
}

struct Job {
    path: PathBuf,
    pid: u32,
    queued_at: Instant,
}

pub struct BackupWorker {
    tx: SyncSender<Job>,
    pub metrics: Arc<BackupMetrics>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    retention_thread: Option<std::thread::JoinHandle<()>>,
}

impl BackupWorker {
    pub fn spawn(
        config: &BackupConfig,
        paths: &[PathBuf],
        event_db: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if config.queue_capacity == 0 || config.io_bytes_per_sec == 0 {
            return Err("backup.queue_capacity와 io_bytes_per_sec는 0보다 커야 합니다".into());
        }
        let store = BackupStore::open(&config.dir, config.max_file_bytes)?;
        let (tx, rx) = mpsc::sync_channel::<Job>(config.queue_capacity);
        let metrics = Arc::new(BackupMetrics::default());
        let stop = Arc::new(AtomicBool::new(false));
        let worker_metrics = Arc::clone(&metrics);
        let worker_stop = Arc::clone(&stop);
        let retention_config = config.clone();
        let event_db = event_db.to_path_buf();
        let config = config.clone();
        let paths = paths.to_vec();
        let thread = std::thread::Builder::new()
            .name("argos-backup".into())
            .spawn(move || {
                let mut next_io = Instant::now();
                let capture = |job: Job, next_io: &mut Instant| {
                    while Instant::now() < *next_io {
                        if worker_stop.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(
                            next_io
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_millis(20)),
                        );
                    }
                    worker_metrics.last_delay_ms.store(
                        job.queued_at.elapsed().as_millis() as u64,
                        Ordering::Relaxed,
                    );
                    // 큐 지연 후 읽은 내용을 과거 이벤트 시각의 정상본으로 표시하지 않는다.
                    let bytes = std::fs::symlink_metadata(&job.path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    match store.backup(&job.path, argos_common::now_ms(), job.pid) {
                        Ok(_) => {
                            let completed =
                                worker_metrics.completed.fetch_add(1, Ordering::Relaxed) + 1;
                            if completed % 100 == 0 {
                                if let Err(error) = store.prune(config.keep_versions) {
                                    worker_metrics.failed.fetch_add(1, Ordering::Relaxed);
                                    tracing::warn!(%error, "백업 보존 정책 적용 실패");
                                }
                            }
                        }
                        Err(RecoveryError::TooLarge { .. }) => {
                            worker_metrics.oversized.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            worker_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(path = %job.path.display(), error = %e, "백업 실패");
                        }
                    }
                    // 최대 한 파일 크기의 burst를 허용하고 이후 작업 간격으로 평균 I/O 예산을 지킨다.
                    let seconds =
                        bytes.min(config.max_file_bytes) as f64 / config.io_bytes_per_sec as f64;
                    *next_io = Instant::now() + Duration::from_secs_f64(seconds.min(86400.0));
                };
                if config.baseline_on_start {
                    let mut stack = paths;
                    while let Some(path) = stack.pop() {
                        if worker_stop.load(Ordering::Relaxed) {
                            return;
                        }
                        let Ok(meta) = std::fs::symlink_metadata(&path) else {
                            continue;
                        };
                        if meta.file_type().is_symlink() {
                            continue;
                        }
                        if meta.is_dir() {
                            if let Ok(entries) = std::fs::read_dir(path) {
                                stack.extend(entries.flatten().map(|entry| entry.path()));
                            }
                        } else if meta.is_file() {
                            capture(
                                Job {
                                    path,
                                    pid: 0,
                                    queued_at: Instant::now(),
                                },
                                &mut next_io,
                            );
                        }
                    }
                    tracing::info!("베이스라인 수집 완료 — 정상본 판정은 별도 검토 필요");
                }
                while !worker_stop.load(Ordering::Relaxed) {
                    match rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(job) => {
                            worker_metrics.queued.fetch_sub(1, Ordering::Relaxed);
                            capture(job, &mut next_io);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })?;
        let retention_stop = Arc::clone(&stop);
        let retention_metrics = Arc::clone(&metrics);
        let retention_thread = match std::thread::Builder::new()
            .name("argos-retention".into())
            .spawn(move || {
                run_retention(
                    retention_config,
                    event_db,
                    retention_stop,
                    retention_metrics,
                )
            }) {
            Ok(thread) => thread,
            Err(error) => {
                stop.store(true, Ordering::Relaxed);
                let _ = thread.join();
                return Err(error.into());
            }
        };
        Ok(Self {
            tx,
            metrics,
            stop,
            thread: Some(thread),
            retention_thread: Some(retention_thread),
        })
    }

    pub fn enqueue(&self, event: &FileEvent) {
        self.metrics.queued.fetch_add(1, Ordering::Relaxed);
        if self
            .tx
            .try_send(Job {
                path: PathBuf::from(&event.path),
                pid: event.pid,
                queued_at: Instant::now(),
            })
            .is_err()
        {
            self.metrics.queued.fetch_sub(1, Ordering::Relaxed);
            self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(path = %event.path, "백업 큐 가득 참/중단 — 백업 누락");
        }
    }
}

fn wait_retention(stop: &AtomicBool, duration: Duration) {
    let until = Instant::now() + duration;
    while !stop.load(Ordering::Relaxed) && Instant::now() < until {
        std::thread::sleep(
            until
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100)),
        );
    }
}

fn update_retention_metrics(store: &argos_storage::EventStore, metrics: &BackupMetrics) {
    match store.retention_stats() {
        Ok(stats) => {
            metrics.pin_pending.store(stats.pending, Ordering::Relaxed);
            metrics
                .pin_failed
                .store(stats.failed_attempts, Ordering::Relaxed);
            metrics
                .pin_overflow
                .store(stats.overflow, Ordering::Relaxed);
            metrics
                .pin_completed
                .store(stats.completed, Ordering::Relaxed);
        }
        Err(error) => {
            metrics.pin_worker_errors.fetch_add(1, Ordering::Relaxed);
            tracing::error!(%error,"보존 작업 상태 조회 실패");
        }
    }
}

/// 보존 요청은 탐지 트랜잭션에 저장되어 있다. 백업 잠금·fsync는 이 전용 스레드에서만 기다린다.
fn run_retention(
    config: BackupConfig,
    event_db: PathBuf,
    stop: Arc<AtomicBool>,
    metrics: Arc<BackupMetrics>,
) {
    while !stop.load(Ordering::Relaxed) {
        let store = match argos_storage::EventStore::open(&event_db) {
            Ok(store) => store,
            Err(error) => {
                metrics.pin_worker_errors.fetch_add(1, Ordering::Relaxed);
                tracing::error!(%error,"보존 작업 DB 열기 실패 — 영속 요청 유지");
                wait_retention(&stop, Duration::from_secs(1));
                continue;
            }
        };
        update_retention_metrics(&store, &metrics);
        let backup = match BackupStore::open(&config.dir, config.max_file_bytes) {
            Ok(store) => store,
            Err(error) => {
                metrics.pin_worker_errors.fetch_add(1, Ordering::Relaxed);
                tracing::error!(%error,"보존 저장소 열기 실패 — 영속 요청 유지");
                wait_retention(&stop, Duration::from_secs(1));
                continue;
            }
        };
        while !stop.load(Ordering::Relaxed) {
            update_retention_metrics(&store, &metrics);
            let jobs = match store.pending_retention_jobs(argos_common::now_ms(), 16) {
                Ok(jobs) => jobs,
                Err(error) => {
                    metrics.pin_worker_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(%error,"보존 작업 조회 실패");
                    wait_retention(&stop, Duration::from_secs(1));
                    continue;
                }
            };
            if jobs.is_empty() {
                wait_retention(&stop, Duration::from_millis(100));
                continue;
            }
            // pending_retention_jobs가 Vec을 반환하기 전에 이벤트 DB 읽기 statement를 닫는다.
            for job in jobs {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let incident = format!("detection-{}", job.detection_id);
                let mut failure = None;
                for path in &job.detection.paths {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Err(error) = backup.pin_known_good_before(
                        Path::new(path),
                        job.detection.timestamp_ms,
                        &incident,
                        "argos-agent",
                        "탐지 이전 정상 복구 지점 자동 보존",
                    ) {
                        failure = Some(error.to_string());
                    }
                }
                let result = if let Some(error) = failure {
                    let delay_ms = 1000u64
                        .saturating_mul(1u64 << job.attempts.min(6))
                        .min(60_000);
                    tracing::warn!(%incident,%error,delay_ms,"사건 보존 실패 — 영속 요청 재시도");
                    store.record_retention_failure(
                        job.detection_id,
                        &error,
                        argos_common::now_ms()
                            .saturating_add(delay_ms)
                            .min(i64::MAX as u64),
                    )
                } else {
                    // 재시작/ACK 실패 뒤 재실행해도 사건·버전 고유 참조가 중복 고정을 막는다.
                    store.acknowledge_retention_job(job.detection_id)
                };
                if let Err(error) = result {
                    metrics.pin_worker_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(%incident,%error,"보존 결과 기록 실패 — 요청 유지");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_common::FileAction;

    #[test]
    fn locked_backup_never_blocks_detection_and_pending_pin_survives_restart() {
        let dir =
            std::env::temp_dir().join(format!("argos-retention-worker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file");
        std::fs::write(&path, b"reviewed original").unwrap();
        let config = BackupConfig {
            dir: dir.join("backup"),
            baseline_on_start: false,
            ..BackupConfig::default()
        };
        let db = dir.join("events.db");
        let events = argos_storage::EventStore::open(&db).unwrap();
        let backup = BackupStore::open(&config.dir, config.max_file_bytes).unwrap();
        backup.backup(&path, 1, 0).unwrap();
        let version = backup.versions(&path).unwrap()[0].id;
        backup.mark_known_good(&path, version, "검토 완료").unwrap();
        let worker = BackupWorker::spawn(&config, &[], &db).unwrap();
        let blocker = rusqlite::Connection::open(config.dir.join("index.db")).unwrap();
        blocker.busy_timeout(Duration::from_secs(5)).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = Instant::now();
        let detection = argos_common::Detection {
            timestamp_ms: 2,
            rule: "test".into(),
            score: 90.0,
            severity: argos_common::Severity::Critical,
            summary: "test".into(),
            pid: 42,
            paths: vec![path.to_string_lossy().into_owned()],
        };
        let id = events.record_detection(&detection, None, true).unwrap();
        worker.enqueue(&FileEvent {
            timestamp_ms: 2,
            pid: 42,
            path: path.to_string_lossy().into_owned(),
            action: FileAction::Modify,
            size: None,
            entropy: None,
            content: None,
            process: None,
        });
        // A synchronous pin would wait for the backup connection's five-second timeout.
        assert!(started.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(events.retention_stats().unwrap().pending, 1);
        drop(worker); // The unacknowledged request remains on disk while stopped.
        assert_eq!(events.retention_stats().unwrap().pending, 1);
        blocker.execute_batch("ROLLBACK").unwrap();
        let incident = format!("detection-{id}");
        // Simulate successful pinning followed by loss of the event-DB acknowledgement.
        backup
            .pin_known_good_before(
                &path,
                2,
                &incident,
                "argos-agent",
                "탐지 이전 정상 복구 지점 자동 보존",
            )
            .unwrap();
        let worker = BackupWorker::spawn(&config, &[], &db).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while events.retention_stats().unwrap().pending > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(events.retention_stats().unwrap().pending, 0);
        assert_eq!(events.retention_stats().unwrap().completed, 1);
        assert_eq!(
            backup.retention_pins(Some(&incident), false).unwrap().len(),
            1
        );
        drop(worker);
        drop(blocker);
        drop(backup);
        drop(events);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn saturated_backup_queue_is_bounded_nonblocking_and_cancellable() {
        let dir = std::env::temp_dir().join(format!("argos-backup-queue-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file");
        std::fs::write(&path, vec![1u8; 100]).unwrap();
        let config = BackupConfig {
            dir: dir.join("backup"),
            queue_capacity: 1,
            io_bytes_per_sec: 1,
            baseline_on_start: false,
            ..BackupConfig::default()
        };
        let worker = BackupWorker::spawn(&config, &[], &dir.join("events.db")).unwrap();
        let event = FileEvent {
            timestamp_ms: 1,
            pid: 0,
            path: path.display().to_string(),
            action: FileAction::Modify,
            size: Some(100),
            entropy: None,
            content: None,
            process: None,
        };
        let started = Instant::now();
        for _ in 0..1000 {
            worker.enqueue(&event);
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(worker.metrics.queued.load(Ordering::Relaxed) <= 2);
        assert!(worker.metrics.dropped.load(Ordering::Relaxed) > 0);
        drop(worker);
        assert!(started.elapsed() < Duration::from_secs(3));
        let _ = std::fs::remove_dir_all(dir);
    }
}

impl Drop for BackupWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.retention_thread.take() {
            let _ = thread.join();
        }
        let remaining = self.metrics.queued.load(Ordering::Relaxed);
        if remaining > 0 {
            tracing::warn!(remaining, "종료로 미처리 백업 작업 취소");
        }
    }
}
