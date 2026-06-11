//! fanotify 기반 센서 (Linux 전용, CAP_SYS_ADMIN/root 필요).
//!
//! FAN_MARK_MOUNT로 감시 경로가 속한 마운트 전체를 마크하고,
//! 이벤트의 fd를 /proc/self/fd로 역참조해 경로를 얻은 뒤
//! 감시 경로 prefix로 필터링한다. 이벤트에는 원인 pid가 포함된다.
//!
//! 한계: FAN_MODIFY/FAN_CLOSE_WRITE만 수집한다 (수정 계열).
//! 생성/삭제/이름변경 디렉터리 이벤트(FAN_CREATE 등)는 FAN_REPORT_FID
//! (kernel 5.1+)가 필요해 Phase 3 eBPF 고도화에서 다룬다.
//! 자기 자신(에이전트 pid)의 이벤트는 피드백 루프 방지를 위해 무시한다.

use super::SensorError;
use argos_common::{now_ms, FileAction, FileEvent};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use tokio::sync::mpsc::Sender;

const FANOTIFY_METADATA_VERSION: u8 = 3;

pub struct FanotifyHandle {
    fd: libc::c_int,
}

impl Drop for FanotifyHandle {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

pub fn spawn(paths: &[PathBuf], tx: Sender<FileEvent>) -> Result<FanotifyHandle, SensorError> {
    let fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC,
            (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(SensorError::Fanotify {
            context: "fanotify_init (root 권한 필요)",
            source: std::io::Error::last_os_error(),
        });
    }

    let mask: u64 = libc::FAN_MODIFY | libc::FAN_CLOSE_WRITE;
    for path in paths {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            SensorError::Fanotify {
                context: "경로에 NUL 문자 포함",
                source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
            }
        })?;
        let ret = unsafe {
            libc::fanotify_mark(
                fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                mask,
                libc::AT_FDCWD,
                c_path.as_ptr(),
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(SensorError::Fanotify {
                context: "fanotify_mark",
                source: err,
            });
        }
        tracing::info!(path = %path.display(), backend = "fanotify", "감시 시작 (마운트 단위)");
    }

    // 마운트 전체 이벤트 중 감시 경로 하위만 통과시키는 prefix 필터.
    let prefixes: Vec<String> = paths
        .iter()
        .map(|p| {
            p.canonicalize()
                .unwrap_or_else(|_| p.clone())
                .to_string_lossy()
                .into_owned()
        })
        .collect();

    let read_fd = fd;
    std::thread::Builder::new()
        .name("argos-fanotify".into())
        .spawn(move || read_loop(read_fd, prefixes, tx))
        .map_err(|e| SensorError::Fanotify {
            context: "리더 스레드 생성",
            source: e,
        })?;

    Ok(FanotifyHandle { fd })
}

fn read_loop(fd: libc::c_int, prefixes: Vec<String>, tx: Sender<FileEvent>) {
    let self_pid = std::process::id();
    let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // EBADF 등 — 핸들이 drop되어 fd가 닫힌 정상 종료 경로 포함.
            tracing::info!(error = %err, "fanotify 리더 종료");
            return;
        }
        if n == 0 {
            return;
        }

        let n = n as usize;
        let mut offset = 0usize;
        while offset + meta_size <= n {
            // 커널이 채워준 메타데이터를 정렬된 버퍼에서 읽는다.
            let meta = unsafe {
                std::ptr::read_unaligned(
                    buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata
                )
            };
            if meta.event_len < meta_size as u32 {
                break;
            }
            if meta.vers != FANOTIFY_METADATA_VERSION {
                tracing::error!(
                    vers = meta.vers,
                    "fanotify 메타데이터 버전 불일치 — 센서 중단"
                );
                return;
            }

            if meta.fd >= 0 {
                let pid = meta.pid as u32;
                let path = std::fs::read_link(format!("/proc/self/fd/{}", meta.fd))
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let size = std::fs::metadata(format!("/proc/self/fd/{}", meta.fd))
                    .ok()
                    .map(|m| m.len());
                unsafe {
                    libc::close(meta.fd);
                }

                let in_scope = !path.is_empty()
                    && prefixes.iter().any(|prefix| path.starts_with(prefix));
                if in_scope && pid != self_pid {
                    let event = FileEvent {
                        timestamp_ms: now_ms(),
                        pid,
                        path,
                        action: FileAction::Modify,
                        size,
                        entropy: None,
                    };
                    if tx.blocking_send(event).is_err() {
                        return; // 수신측 종료.
                    }
                }
            }

            offset += meta.event_len as usize;
        }
    }
}
