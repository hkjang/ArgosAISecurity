//! Argos Sensor: 파일 시스템 이벤트 수집.
//!
//! Phase 1: 크로스 플랫폼 `notify`(inotify/ReadDirectoryChanges) 기반.
//!   - 장점: Linux/Windows/macOS에서 동일하게 동작해 개발·테스트 용이.
//!   - 한계: 이벤트에 pid가 없다 (pid 0으로 보고).
//! Phase 3(eBPF 고도화): fanotify(FAN_REPORT_FID + pid)와 eBPF LSM 훅으로
//!   교체하며, 이 크레이트의 공개 인터페이스(`spawn_fs_sensor`)는 유지한다.

use argos_common::{now_ms, FileAction, FileEvent};
use notify::{Event as NotifyEvent, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use tokio::sync::mpsc::Sender;

#[derive(Debug, thiserror::Error)]
pub enum SensorError {
    #[error("파일 감시 초기화 실패: {0}")]
    Watch(#[from] notify::Error),
}

/// 감시를 유지하는 핸들. drop되면 감시가 중단된다.
pub struct FsSensorHandle {
    _watcher: RecommendedWatcher,
}

/// 지정 경로들을 재귀 감시하고 FileEvent를 채널로 전송한다.
///
/// notify 콜백은 자체 스레드에서 호출되므로 `blocking_send`를 사용한다.
/// 채널이 가득 차면 backpressure로 콜백이 대기한다 (이벤트 유실 방지).
pub fn spawn_fs_sensor(
    paths: &[PathBuf],
    tx: Sender<FileEvent>,
) -> Result<FsSensorHandle, SensorError> {
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
                pid: 0, // Phase 1 한계: notify는 pid를 제공하지 않음.
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
        tracing::info!(path = %path.display(), "감시 시작");
    }

    Ok(FsSensorHandle { _watcher: watcher })
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
