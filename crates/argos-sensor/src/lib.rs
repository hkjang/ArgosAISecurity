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

#[cfg(target_os = "linux")]
mod fanotify;
#[cfg(target_os = "linux")]
pub mod procmon;

#[cfg(target_os = "linux")]
pub use procmon::spawn_proc_monitor;

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

/// 감시를 유지하는 핸들. drop되면 감시가 중단된다.
pub enum SensorHandle {
    Notify(RecommendedWatcher),
    #[cfg(target_os = "linux")]
    Fanotify(fanotify::FanotifyHandle),
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
                fanotify::spawn(paths, tx).map(SensorHandle::Fanotify)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (paths, tx);
                Err(SensorError::FanotifyUnsupported)
            }
        }
    }
}

/// notify 기반 센서. 콜백은 notify의 자체 스레드에서 호출되므로
/// `blocking_send`를 사용한다. 채널이 가득 차면 backpressure로 대기한다.
fn spawn_notify_sensor(
    paths: &[PathBuf],
    tx: Sender<FileEvent>,
) -> Result<SensorHandle, SensorError> {
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
        let event = match res {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(error = %err, "notify 이벤트 오류");
                return;
            }
        };
        let Some(action) = map_action(&event.kind) else {
            return;
        };
        for path in &event.paths {
            let size = std::fs::metadata(path).ok().map(|m| m.len());
            let file_event = FileEvent {
                timestamp_ms: now_ms(),
                pid: 0, // notify 한계: pid를 제공하지 않음.
                path: path.to_string_lossy().into_owned(),
                action,
                size,
                entropy: None, // 엔트로피는 파이프라인(agent)에서 계산.
            };
            if tx.blocking_send(file_event).is_err() {
                // 수신측 종료 — 에이전트가 내려가는 중.
                return;
            }
        }
    })?;

    for path in paths {
        watcher.watch(path, RecursiveMode::Recursive)?;
        tracing::info!(path = %path.display(), backend = "notify", "감시 시작");
    }

    Ok(SensorHandle::Notify(watcher))
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
