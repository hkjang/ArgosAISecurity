//! Argos Response: 위협 대응 실행 (프로세스 종료·일시 중지).
//!
//! 요건서 9장. Phase 1은 프로세스 차단만 구현한다.
//! 경로 잠금, 네트워크 격리, 세션 제한, 승인 기반 대응은 Phase 3.

pub mod isolate;

use argos_common::Pid;

#[derive(Debug, Clone)]
pub enum ResponseAction {
    /// SIGKILL — 즉시 종료.
    KillProcess(Pid),
    /// 수집 당시 신원과 일치하는 프로세스만 pidfd로 종료한다.
    KillProcessInstance {
        pid: Pid,
        start_time_ticks: u64,
        boot_id: String,
    },
    /// SIGSTOP — 분석을 위한 일시 중지.
    SuspendProcess(Pid),
}

#[derive(Debug, thiserror::Error)]
pub enum ResponseError {
    #[error("대응 실행 실패 (pid {pid}): {source}")]
    Signal {
        pid: Pid,
        #[source]
        source: std::io::Error,
    },
    #[error("이 플랫폼에서는 지원하지 않는 대응입니다: {0}")]
    Unsupported(&'static str),
    #[error("pid 0은 차단 대상이 될 수 없습니다 (센서가 pid를 제공하지 않음)")]
    UnknownPid,
    #[error("보호되거나 유효하지 않은 pid는 차단할 수 없습니다: {0}")]
    ProtectedPid(Pid),
    #[error("수집한 프로세스 신원과 현재 신원이 다릅니다: pid {0}")]
    IdentityChanged(Pid),
    #[error("종료 신호는 전달했으나 프로세스 종료를 1초 안에 확인하지 못했습니다: pid {0}")]
    Unconfirmed(Pid),
}

pub trait Responder: Send {
    fn execute(&self, action: &ResponseAction) -> Result<(), ResponseError>;
}

/// 실제 차단 없이 로그만 남기는 Responder.
/// auto_block=false 정책 및 비 Linux 개발 환경에서 사용한다.
pub struct DryRunResponder;

impl Responder for DryRunResponder {
    fn execute(&self, action: &ResponseAction) -> Result<(), ResponseError> {
        tracing::warn!(?action, "DRY-RUN: 자동 차단이 비활성화되어 실행하지 않음");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub struct LinuxResponder;

#[cfg(target_os = "linux")]
impl Responder for LinuxResponder {
    fn execute(&self, action: &ResponseAction) -> Result<(), ResponseError> {
        let (pid, signal) = match action {
            ResponseAction::KillProcess(pid) => (*pid, libc::SIGKILL),
            ResponseAction::KillProcessInstance { pid, .. } => (*pid, libc::SIGKILL),
            ResponseAction::SuspendProcess(pid) => (*pid, libc::SIGSTOP),
        };
        if pid == 0 {
            // kill(0, ...)은 프로세스 그룹 전체에 시그널을 보낸다 — 절대 금지.
            return Err(ResponseError::UnknownPid);
        }
        // 음수 pid 변환은 프로세스 그룹/전체 프로세스에 시그널을 보낼 수 있다.
        if pid == 1 || pid > i32::MAX as u32 || pid == std::process::id() {
            return Err(ResponseError::ProtectedPid(pid));
        }
        let ret = if let ResponseAction::KillProcessInstance {
            start_time_ticks,
            boot_id,
            ..
        } = action
        {
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
            // PID 확인과 시그널 사이에 종료/재사용되더라도 같은 커널 프로세스를 참조한다.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if fd < 0 {
                return Err(ResponseError::Signal {
                    pid,
                    source: std::io::Error::last_os_error(),
                });
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            if !process_identity_matches(pid, *start_time_ticks, boot_id) {
                return Err(ResponseError::IdentityChanged(pid));
            }
            let sent = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                ) as i32
            };
            if sent == 0 {
                let mut poll = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ready = unsafe { libc::poll(&mut poll, 1, 1000) };
                if ready <= 0 || poll.revents & libc::POLLIN == 0 {
                    return Err(ResponseError::Unconfirmed(pid));
                }
            }
            sent
        } else {
            unsafe { libc::kill(pid as libc::pid_t, signal) }
        };
        if ret != 0 {
            return Err(ResponseError::Signal {
                pid,
                source: std::io::Error::last_os_error(),
            });
        }
        tracing::warn!(pid, signal, "위험 프로세스 차단 실행");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn process_identity_matches(pid: Pid, start_time_ticks: u64, boot_id: &str) -> bool {
    if boot_id.is_empty() || start_time_ticks == 0 {
        return false;
    }
    let current_boot =
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let ticks = stat
        .rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|n| n.parse::<u64>().ok());
    current_boot.trim() == boot_id && ticks == Some(start_time_ticks)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn dangerous_pids_are_rejected_before_signalling() {
        assert!(matches!(
            LinuxResponder.execute(&ResponseAction::KillProcess(0)),
            Err(ResponseError::UnknownPid)
        ));
        for pid in [1, u32::MAX, i32::MAX as u32 + 1, std::process::id()] {
            assert!(matches!(
                LinuxResponder.execute(&ResponseAction::KillProcess(pid)),
                Err(ResponseError::ProtectedPid(_))
            ));
        }
    }

    #[test]
    fn linux_response_terminates_only_test_child() {
        use std::os::unix::process::ExitStatusExt;
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap();
        let ticks = stat
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
            .to_owned();
        let mismatched = ResponseAction::KillProcessInstance {
            pid: child.id(),
            start_time_ticks: ticks + 1,
            boot_id: boot.clone(),
        };
        assert!(matches!(
            LinuxResponder.execute(&mismatched),
            Err(ResponseError::IdentityChanged(_))
        ));
        assert!(child.try_wait().unwrap().is_none());
        let result = LinuxResponder.execute(&ResponseAction::KillProcessInstance {
            pid: child.id(),
            start_time_ticks: ticks,
            boot_id: boot,
        });
        if result.is_err() {
            let _ = child.kill();
        }
        let status = child.wait().unwrap();
        result.unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }
}

/// 현재 플랫폼·정책에 맞는 Responder를 만든다.
pub fn make_responder(auto_block: bool) -> Box<dyn Responder> {
    #[cfg(target_os = "linux")]
    {
        if auto_block {
            return Box::new(LinuxResponder);
        }
    }
    let _ = auto_block;
    Box::new(DryRunResponder)
}
