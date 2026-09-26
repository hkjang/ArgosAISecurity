//! fanotify 기반 센서 (Linux 전용, CAP_SYS_ADMIN/root 필요).
//!
//! 마운트 단위 수정 이벤트에서 경로와 원인 PID를 수집한다. 에이전트 큐 포화와
//! FAN_Q_OVERFLOW를 각각 계수한다. 읽기 FD는 리더 스레드가 소유하여 종료 시 닫는다.

use super::health::{LivenessGuard, SensorHealth};
use super::SensorError;
use argos_common::{now_ms, FileAction, FileEvent};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

const FANOTIFY_METADATA_VERSION: u8 = 3;

pub struct FanotifyHandle {
    stop: Arc<AtomicBool>,
}

impl Drop for FanotifyHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

pub fn spawn(
    paths: &[PathBuf],
    tx: Sender<FileEvent>,
    health: SensorHealth,
) -> Result<FanotifyHandle, SensorError> {
    let raw_fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
            (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_uint,
        )
    };
    if raw_fd < 0 {
        return Err(SensorError::Fanotify {
            context: "fanotify_init (root 권한 필요)",
            source: std::io::Error::last_os_error(),
        });
    }
    // 모든 초기화 실패 경로와 리더 종료에서 정확히 한 번 닫는다.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mask: u64 = libc::FAN_MODIFY | libc::FAN_CLOSE_WRITE;
    let mut prefixes = Vec::new();
    for path in paths {
        let prefix = path
            .canonicalize()
            .map_err(|source| SensorError::Fanotify {
                context: "감시 경로 정규화",
                source,
            })?;
        let c_path =
            CString::new(prefix.as_os_str().as_bytes()).map_err(|_| SensorError::Fanotify {
                context: "경로에 NUL 문자 포함",
                source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
            })?;
        let ret = unsafe {
            libc::fanotify_mark(
                fd.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                mask,
                libc::AT_FDCWD,
                c_path.as_ptr(),
            )
        };
        if ret != 0 {
            return Err(SensorError::Fanotify {
                context: "fanotify_mark",
                source: std::io::Error::last_os_error(),
            });
        }
        tracing::info!(path = %path.display(), backend = "fanotify", "감시 시작 (마운트 단위)");
        prefixes.push(prefix);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let reader_stop = stop.clone();
    health.start();
    let reader_health = health.clone();
    std::thread::Builder::new()
        .name("argos-fanotify".into())
        .spawn(move || read_loop(fd, prefixes, tx, reader_stop, reader_health))
        .map_err(|source| {
            health.stop();
            SensorError::Fanotify {
                context: "리더 스레드 생성",
                source,
            }
        })?;
    Ok(FanotifyHandle { stop })
}

fn valid_metadata(meta: &libc::fanotify_event_metadata, remaining: usize) -> bool {
    let size = std::mem::size_of::<libc::fanotify_event_metadata>();
    meta.event_len as usize >= size
        && meta.event_len as usize <= remaining
        && meta.metadata_len as usize >= size
        && meta.metadata_len as u32 <= meta.event_len
}

fn in_scope(path: &Path, prefixes: &[PathBuf]) -> bool {
    prefixes.iter().any(|prefix| path.starts_with(prefix))
}

fn read_loop(
    fd: OwnedFd,
    prefixes: Vec<PathBuf>,
    tx: Sender<FileEvent>,
    stop: Arc<AtomicBool>,
    health: SensorHealth,
) {
    let _guard = LivenessGuard(health.clone());
    let self_pid = std::process::id();
    let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
    let mut buf = vec![0u8; 64 * 1024];
    while !stop.load(Ordering::Acquire) && !tx.is_closed() {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 250) };
        if ready == 0 {
            continue;
        }
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            health.error();
            tracing::error!(%error, "fanotify 대기 실패 — 센서 중단");
            return;
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            health.error();
            tracing::error!(events = poll.revents, "fanotify FD 오류 — 센서 중단");
            return;
        }
        let n = unsafe {
            libc::read(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            health.error();
            tracing::error!(%error, "fanotify 읽기 실패 — 센서 중단");
            return;
        }
        if n == 0 {
            health.error();
            return;
        }
        let n = n as usize;
        let mut offset = 0;
        let mut receiver_closed = false;
        while offset + meta_size <= n {
            let meta = unsafe {
                std::ptr::read_unaligned(
                    buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata
                )
            };
            // 커널이 건넨 이벤트 FD는 전달 성공 여부와 무관하게 이 반복에서 해제한다.
            let event_fd = (meta.fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(meta.fd) });
            if !valid_metadata(&meta, n - offset) || meta.vers != FANOTIFY_METADATA_VERSION {
                health.error();
                tracing::error!(
                    version = meta.vers,
                    "fanotify 메타데이터 불일치 — 센서 중단"
                );
                return;
            }
            if meta.mask & libc::FAN_Q_OVERFLOW != 0 {
                health.overflow();
                tracing::warn!("fanotify 커널 큐 넘침 — 파일 이벤트 유실");
            }
            if let Some(event_fd) = event_fd {
                // 수신측 종료 후에도 현재 버퍼의 나머지 FD는 모두 닫는다.
                if !receiver_closed {
                    match std::fs::read_link(format!("/proc/self/fd/{}", event_fd.as_raw_fd())) {
                        Ok(path)
                            if in_scope(&path, &prefixes)
                                && meta.pid > 0
                                && meta.pid as u32 != self_pid =>
                        {
                            let file = std::fs::File::from(event_fd);
                            let event = FileEvent {
                                timestamp_ms: now_ms(),
                                pid: meta.pid as u32,
                                path: path.to_string_lossy().into_owned(),
                                action: FileAction::Modify,
                                size: file.metadata().ok().map(|m| m.len()),
                                entropy: None,
                                content: None,
                                process: super::procmon::read_file_process_context(meta.pid as u32),
                            };
                            receiver_closed = !health.deliver(&tx, event);
                        }
                        Ok(_) => {}
                        Err(error) => {
                            health.error();
                            tracing::debug!(%error, "fanotify 경로 조회 실패");
                        }
                    }
                }
            }
            offset += meta.event_len as usize;
        }
        if offset != n {
            health.error();
        }
        if receiver_closed {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_matching_uses_path_components() {
        let prefixes = vec![PathBuf::from("/data/watch")];
        assert!(in_scope(Path::new("/data/watch/file"), &prefixes));
        assert!(in_scope(Path::new("/data/watch"), &prefixes));
        assert!(!in_scope(Path::new("/data/watched/file"), &prefixes));
    }

    #[test]
    fn malformed_kernel_records_cannot_run_past_read_buffer() {
        let size = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut metadata: libc::fanotify_event_metadata = unsafe { std::mem::zeroed() };
        metadata.event_len = size as u32;
        metadata.metadata_len = size as u16;
        assert!(valid_metadata(&metadata, size));
        assert!(!valid_metadata(&metadata, size - 1));
        metadata.metadata_len = (size - 1) as u16;
        assert!(!valid_metadata(&metadata, size));
        metadata.metadata_len = size as u16;
        metadata.event_len = 0;
        assert!(!valid_metadata(&metadata, size));
    }

    #[test]
    fn overflow_record_updates_health_and_reader_exits_on_receiver_close() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let fd: OwnedFd = reader.into();
        let health = SensorHealth::default();
        health.start();
        let worker_health = health.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let thread =
            std::thread::spawn(move || read_loop(fd, vec![], tx, worker_stop, worker_health));
        let size = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut metadata: libc::fanotify_event_metadata = unsafe { std::mem::zeroed() };
        metadata.event_len = size as u32;
        metadata.metadata_len = size as u16;
        metadata.vers = FANOTIFY_METADATA_VERSION;
        metadata.mask = libc::FAN_Q_OVERFLOW;
        metadata.fd = -1;
        let bytes = unsafe { std::slice::from_raw_parts(&metadata as *const _ as *const u8, size) };
        writer.write_all(bytes).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while health.snapshot().kernel_overflows == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(health.snapshot().kernel_overflows, 1);
        assert_eq!(health.snapshot().dropped_events, 0);
        drop(rx);
        thread.join().unwrap();
        assert!(!health.snapshot().alive);
    }
}
