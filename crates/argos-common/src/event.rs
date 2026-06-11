use serde::{Deserialize, Serialize};

pub type Pid = u32;

/// 파일 행위 종류 (요건서 4. 파일 행위 감시).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileAction {
    Create,
    Modify,
    Delete,
    Rename,
    Chmod,
    Chown,
}

/// 센서가 수집한 파일 이벤트.
///
/// Phase 1(notify 기반)에서는 pid를 알 수 없어 0으로 채운다.
/// Linux fanotify/eBPF 센서로 교체 시 실제 pid가 들어온다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub timestamp_ms: u64,
    pub pid: Pid,
    pub path: String,
    pub action: FileAction,
    /// 변경 후 파일 크기 (알 수 있는 경우).
    pub size: Option<u64>,
    /// 파일 내용 샘플의 Shannon 엔트로피 (0.0 ~ 8.0).
    pub entropy: Option<f64>,
}

/// 프로세스 실행 이벤트 (요건서 4. 프로세스 감시).
///
/// Phase 3: /proc 폴링 기반 — exec 추적, 부모·자식 관계, 실행 사용자.
/// eBPF 센서로 교체 시 폴링 간격 사이에 종료되는 단명 프로세스도 잡는다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub timestamp_ms: u64,
    pub pid: Pid,
    pub ppid: Pid,
    pub uid: u32,
    /// 커널 comm (프로세스 이름, 최대 15자).
    pub comm: String,
    /// 전체 명령행.
    pub cmdline: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    File(FileEvent),
    Process(ProcessEvent),
    // Phase 3+: Network(NetworkEvent), Privilege(PrivilegeEvent)
}

impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Event::File(_) => "file",
            Event::Process(_) => "process",
        }
    }

    pub fn timestamp_ms(&self) -> u64 {
        match self {
            Event::File(e) => e.timestamp_ms,
            Event::Process(e) => e.timestamp_ms,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// 탐지 엔진이 산출한 위협 판단 결과.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub timestamp_ms: u64,
    /// 탐지 룰/스코어러 식별자 (예: "behavior.mass_change").
    pub rule: String,
    /// 위험 점수 0 ~ 100.
    pub score: f64,
    pub severity: Severity,
    /// 사람이 읽을 수 있는 한 줄 요약.
    pub summary: String,
    pub pid: Pid,
    /// 탐지 근거가 된 대표 경로들 (최대 수십 개로 제한).
    pub paths: Vec<String>,
}
