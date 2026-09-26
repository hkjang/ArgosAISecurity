//! Argos Sensor: 파일 시스템 이벤트 수집.
//!
//! 두 가지 백엔드를 제공한다:
//! - `notify` (기본): inotify/ReadDirectoryChanges 기반. 크로스 플랫폼이라
//!   개발·테스트가 쉽지만 이벤트에 pid가 없다 (pid 0으로 보고).
//! - `fanotify` (Linux, root 필요, 옵트인): 커널 fanotify API로
//!   수정 이벤트에 **원인 pid**가 포함된다. 프로세스 단위 탐지·차단의 전제.
//!
//! 공개 API(`spawn_sensor`)는 백엔드와 무관하게 동일하다.

use argos_common::{config::SensorKind, now_ms, FileAction, FileEvent};
use notify::{Event as NotifyEvent, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use tokio::sync::mpsc::Sender;

mod health;
use health::SensorHealth;
pub use health::SensorHealthSnapshot;

#[cfg(target_os = "linux")]
mod fanotify;
#[cfg(target_os = "linux")]
pub mod procmon;

#[cfg(target_os = "linux")]
pub use procmon::{spawn_proc_monitor, ProcessMonitorHandle};

#[derive(Debug, thiserror::Error)]
pub enum SensorError {
    #[error("파일 감시 초기화 실패: {0}")]
    Watch(#[from] notify::Error),
    #[error("fanotify 초기화 실패 ({context}): {source}")]
    Fanotify {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("fanotify는 Linux에서만 지원됩니다")]
    FanotifyUnsupported,
}

/// 감시를 유지하는 핸들. drop되면 감시 중단을 요청한다.
pub struct SensorHandle {
    _backend: SensorBackend,
    health: SensorHealth,
}

enum SensorBackend {
    Notify {
        _watcher: RecommendedWatcher,
    },
    #[cfg(target_os = "linux")]
    Fanotify {
        _handle: fanotify::FanotifyHandle,
    },
}

impl SensorHandle {
    pub fn health(&self) -> SensorHealthSnapshot {
        self.health.snapshot()
    }
}

impl Drop for SensorHandle {
    fn drop(&mut self) {
        self.health.stop();
    }
}

/// 설정된 백엔드로 센서를 시작한다.
pub fn spawn_sensor(
    kind: SensorKind,
    paths: &[PathBuf],
    tx: Sender<FileEvent>,
) -> Result<SensorHandle, SensorError> {
    match kind {
        SensorKind::Notify => spawn_notify_sensor(paths, tx),
        SensorKind::Fanotify => {
            #[cfg(target_os = "linux")]
            {
                let health = SensorHealth::default();
                let handle = fanotify::spawn(paths, tx, health.clone())?;
                Ok(SensorHandle {
                    _backend: SensorBackend::Fanotify { _handle: handle },
                    health,
                })
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (paths, tx);
                Err(SensorError::FanotifyUnsupported)
            }
        }
    }
}

/// notify 콜백은 try_send로 전달한다. 포화된 에이전트 큐 때문에 OS 수집 스레드를 멈추지 않는다.
fn spawn_notify_sensor(
    paths: &[PathBuf],
    tx: Sender<FileEvent>,
) -> Result<SensorHandle, SensorError> {
    let health = SensorHealth::default();
    let callback_health = health.clone();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
        handle_notify_event(res, &tx, &callback_health);
    })?;
    for path in paths {
        watcher.watch(path, RecursiveMode::Recursive)?;
        tracing::info!(path = %path.display(), backend = "notify", "감시 시작");
    }
    health.start();
    Ok(SensorHandle {
        _backend: SensorBackend::Notify { _watcher: watcher },
        health,
    })
}

fn handle_notify_event(
    res: notify::Result<NotifyEvent>,
    tx: &Sender<FileEvent>,
    health: &SensorHealth,
) {
    let event = match res {
        Ok(e) => e,
        Err(err) => {
            health.error();
            tracing::warn!(error = %err, "notify 이벤트 오류 — 보호 상태 저하");
            return;
        }
    };
    if event.need_rescan() {
        health.overflow();
        tracing::warn!("notify 재스캔 요청 — 커널 이벤트 유실 가능");
    }
    let Some(action) = map_action(&event.kind) else {
        return;
    };
    for path in &event.paths {
        let size = std::fs::metadata(path).ok().map(|m| m.len());
        let file_event = FileEvent {
            timestamp_ms: now_ms(),
            pid: 0,
            path: path.to_string_lossy().into_owned(),
            action,
            size,
            entropy: None,
            content: None,
            process: None,
        };
        if !health.deliver(tx, file_event) {
            return;
        }
    }
}

fn map_action(kind: &EventKind) -> Option<FileAction> {
    use notify::event::ModifyKind;
    match kind {
        EventKind::Create(_) => Some(FileAction::Create),
        EventKind::Remove(_) => Some(FileAction::Delete),
        EventKind::Modify(ModifyKind::Name(_)) => Some(FileAction::Rename),
        EventKind::Modify(ModifyKind::Metadata(_)) => Some(FileAction::Chmod),
        EventKind::Modify(_) => Some(FileAction::Modify),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_overflow_is_reported_even_without_a_file_action() {
        let health = SensorHealth::default();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let event = NotifyEvent::new(EventKind::Other).set_flag(notify::event::Flag::Rescan);
        handle_notify_event(Ok(event), &tx, &health);
        handle_notify_event(
            Err(notify::Error::generic("테스트 수집 오류")),
            &tx,
            &health,
        );
        let snapshot = health.snapshot();
        assert_eq!(snapshot.kernel_overflows, 1);
        assert_eq!(snapshot.errors, 1);
        assert_eq!(snapshot.delivered_events, 0);
    }
}
