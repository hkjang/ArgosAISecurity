//! 크기가 제한된 별도 백업 작업자. 백업 지연/실패가 대응 판단을 막지 않는다.
use argos_common::{config::BackupConfig, FileEvent};
use argos_recovery::{BackupStore, RecoveryError};
use std::path::PathBuf;
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
}

impl BackupWorker {
    pub fn spawn(
        config: &BackupConfig,
        paths: &[PathBuf],
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
        Ok(Self {
            tx,
            metrics,
            stop,
            thread: Some(thread),
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

#[cfg(test)]
mod tests {
    use super::*;
    use argos_common::FileAction;

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
        let worker = BackupWorker::spawn(&config, &[]).unwrap();
        let event = FileEvent {
            timestamp_ms: 1,
            pid: 0,
            path: path.display().to_string(),
            action: FileAction::Modify,
            size: Some(100),
            entropy: None,
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
        let remaining = self.metrics.queued.load(Ordering::Relaxed);
        if remaining > 0 {
            tracing::warn!(remaining, "종료로 미처리 백업 작업 취소");
        }
    }
}
