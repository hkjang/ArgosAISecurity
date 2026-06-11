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
            ResponseAction::SuspendProcess(pid) => (*pid, libc::SIGSTOP),
        };
        if pid == 0 {
            // kill(0, ...)은 프로세스 그룹 전체에 시그널을 보낸다 — 절대 금지.
            return Err(ResponseError::UnknownPid);
        }
        let ret = unsafe { libc::kill(pid as libc::pid_t, signal) };
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
