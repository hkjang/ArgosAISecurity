use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("설정 파일을 읽을 수 없습니다: {0}")]
    Io(#[from] std::io::Error),
    #[error("설정 파일 형식 오류: {0}")]
    Parse(#[from] toml::de::Error),
}

/// 센서 종류 (요건서 18장: fanotify 기본, 호환성 폴백).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SensorKind {
    /// notify(inotify/ReadDirectoryChanges) — 크로스 플랫폼, pid 없음.
    Notify,
    /// fanotify — Linux 전용, root 필요, pid 제공.
    Fanotify,
}

/// 에이전트 전체 설정 (argos.toml).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// 감시 대상 경로 목록.
    pub watch_paths: Vec<PathBuf>,
    /// 로컬 이벤트/탐지 저장소(SQLite) 경로.
    pub db_path: PathBuf,
    pub sensor: SensorKind,
    pub detection: DetectionConfig,
    pub response: ResponseConfig,
    pub backup: BackupConfig,
    pub central: CentralConfig,
    pub policy: PolicyFileConfig,
    pub process_monitor: ProcessMonitorConfig,
    pub ai: AiConfig,
    pub semantic: SemanticConfig,
    pub coverage: CoverageConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            watch_paths: vec![default_watch_path()],
            db_path: default_db_path(),
            sensor: SensorKind::Notify,
            detection: DetectionConfig::default(),
            response: ResponseConfig::default(),
            backup: BackupConfig::default(),
            central: CentralConfig::default(),
            policy: PolicyFileConfig::default(),
            process_monitor: ProcessMonitorConfig::default(),
            ai: AiConfig::default(),
            semantic: SemanticConfig::default(),
            coverage: CoverageConfig::default(),
        }
    }
}

/// 감시 경로의 접근·교체·마운트 변경을 제한된 읽기 전용 검사로 확인한다.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoverageConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub max_entries: usize,
}

impl Default for CoverageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            max_entries: 10_000,
        }
    }
}

/// 명시적으로 선택한 Linux 설정 파일의 의미 변화 감시. 감시 경로에도 포함해야 한다.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SemanticConfig {
    pub files: Vec<PathBuf>,
    pub max_file_bytes: usize,
}

impl Default for SemanticConfig {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            max_file_bytes: 262_144,
        }
    }
}

/// 외부 API 또는 온프레미스 Ollama. 키 값은 설정 파일 대신 환경변수에서 읽는다.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    pub provider: String,
    /// API 전체 URL. 비어 있으면 제공자 기본 주소.
    pub endpoint: String,
    /// 비어 있으면 ARGOS_AI_MODEL 환경변수 사용.
    pub model: String,
    pub api_key_env: String,
    pub timeout_secs: u64,
    pub evidence_limit: usize,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: "anthropic".into(),
            endpoint: String::new(),
            model: String::new(),
            api_key_env: String::new(),
            timeout_secs: 60,
            evidence_limit: 200,
        }
    }
}

/// 서명된 정책 파일 설정 (요건서 11장 — 서명된 정책만 적용).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyFileConfig {
    /// 정책 파일 경로. 비어 있으면 argos.toml의 값을 그대로 사용.
    pub path: PathBuf,
    /// 이전 CLI 서명 확인용 검증키. 활성화에는 trusted_keys를 사용한다.
    pub pubkey: String,
    /// 로컬에서 승인한 정책 계열 ID. 서명된 policy_id와 같아야 한다.
    pub policy_id: String,
    /// 로컬 서버 ID와 서버 그룹. 정책 파일이 이 값을 재정의할 수 없다.
    pub host_id: String,
    pub groups: Vec<String>,
    /// 로컬 신뢰 목록: 서명키 ID -> Ed25519 공개키(hex 64자).
    pub trusted_keys: std::collections::BTreeMap<String, String>,
    /// 정책 상태 DB. 기본: <db_path>.policy-state/state.sqlite3.
    /// 별도 경로 사용 시 전용 디렉터리는 현재 계정 소유, 권한 0700이어야 한다.
    pub state_path: PathBuf,
}

impl PolicyFileConfig {
    pub fn is_enabled(&self) -> bool {
        !self.path.as_os_str().is_empty()
    }
}

/// 프로세스 감시 설정 (요건서 4장 — Linux 전용, /proc 폴링).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessMonitorConfig {
    pub enabled: bool,
    /// /proc 스캔 간격(ms).
    pub interval_ms: u64,
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectionConfig {
    /// 행위 점수 계산 슬라이딩 윈도우(초).
    pub window_secs: u64,
    /// 윈도우 내 변경 파일 수가 이 값을 넘으면 대량 변경으로 가중.
    pub mass_change_threshold: usize,
    /// 윈도우 내 변경 파일 수가 이 값 미만이면 탐지하지 않는다 (단일 파일 오탐 방지).
    pub min_changed_files: usize,
    /// 이 값 이상의 엔트로피는 암호화 의심 쓰기로 간주 (0.0 ~ 8.0).
    pub entropy_threshold: f64,
    /// Detection 생성 최소 점수.
    pub detect_score: f64,
    /// 엔트로피 계산 시 파일 앞부분에서 읽을 최대 바이트.
    pub entropy_sample_bytes: usize,
    /// 오탐 방지: 점수 계산에서 제외할 경로 prefix (백업, 로그 로테이션 등).
    pub exclude_paths: Vec<PathBuf>,
    /// 시간·경로·실행 파일·계정이 모두 일치할 때 지정 규칙만 조정한다.
    pub approved_changes: Vec<ApprovedChange>,
    /// 변경·삭제·이름 변경을 고위험 신호로 취급하는 미끼 파일의 정확한 경로.
    pub canary_paths: Vec<PathBuf>,
    /// 여러 시간창과 보호 경로 집계. 명시적으로 켠 경우에만 평가한다.
    pub multi_window: MultiWindowConfig,
    /// 총 읽기 예산을 앞·중간·끝에 분배하는 내용 관찰. 정상본 판정이 아니다.
    pub content_sampling: ContentSamplingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectionWindow {
    pub window_secs: u64,
    pub min_changed_files: usize,
    pub mass_change_threshold: usize,
    pub detect_score: f64,
}

impl Default for DetectionWindow {
    fn default() -> Self {
        Self {
            window_secs: 10,
            min_changed_files: 5,
            mass_change_threshold: 30,
            detect_score: 65.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MultiWindowConfig {
    pub enabled: bool,
    pub windows: Vec<DetectionWindow>,
    pub protected_paths: Vec<PathBuf>,
    pub aggregate_by_user: bool,
    pub aggregate_by_ancestry: bool,
    pub max_events: usize,
    pub max_groups: usize,
    pub max_path_bytes: usize,
}

impl Default for MultiWindowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            windows: vec![
                DetectionWindow::default(),
                DetectionWindow {
                    window_secs: 60,
                    min_changed_files: 8,
                    mass_change_threshold: 40,
                    detect_score: 65.0,
                },
                DetectionWindow {
                    window_secs: 600,
                    min_changed_files: 12,
                    mass_change_threshold: 60,
                    detect_score: 65.0,
                },
            ],
            protected_paths: Vec::new(),
            aggregate_by_user: true,
            aggregate_by_ancestry: true,
            max_events: 10_000,
            max_groups: 2048,
            max_path_bytes: 4096,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContentSamplingConfig {
    pub enabled: bool,
    pub total_bytes: usize,
    pub max_files: usize,
    pub history_secs: u64,
    pub min_entropy_increase: f64,
}

impl Default for ContentSamplingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            total_bytes: 64 * 1024,
            max_files: 2048,
            history_secs: 600,
            min_entropy_increase: 1.0,
        }
    }
}

/// 승인된 작업. 파일 변경 이벤트의 불변 프로세스 맥락이 있어야 적용한다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedChange {
    pub id: String,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub paths: Vec<PathBuf>,
    pub exe: PathBuf,
    pub uid: u32,
    /// 현재 지원하는 조정: behavior.ransomware_pattern의 해당 이벤트 증거 제외.
    pub adjusted_rules: Vec<String>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            window_secs: 10,
            mass_change_threshold: 30,
            min_changed_files: 5,
            entropy_threshold: 7.2,
            detect_score: 40.0,
            entropy_sample_bytes: 64 * 1024,
            exclude_paths: Vec::new(),
            approved_changes: Vec::new(),
            canary_paths: Vec::new(),
            multi_window: MultiWindowConfig::default(),
            content_sampling: ContentSamplingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponseConfig {
    /// true면 차단 점수 초과 시 프로세스를 자동 종료한다.
    /// false면 탐지·로그만 남긴다 (요건서 18. 단계적 차단).
    pub auto_block: bool,
    /// 자동 차단 발동 점수.
    pub block_score: f64,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            auto_block: false,
            block_score: 80.0,
        }
    }
}

/// 백업·복구 설정 (요건서 10장).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupConfig {
    pub enabled: bool,
    /// 백업 저장 디렉터리. 감시 경로 밖에 두어야 한다.
    pub dir: PathBuf,
    /// 이 크기를 넘는 파일은 백업하지 않는다.
    pub max_file_bytes: u64,
    /// 경로당 보존 버전 수 (prune 시 적용).
    pub keep_versions: usize,
    /// 에이전트 시작 시 감시 경로의 기존 파일을 1회 베이스라인 백업.
    pub baseline_on_start: bool,
    /// 탐지 경로와 분리된 백업 작업 큐 상한.
    pub queue_capacity: usize,
    /// 백업 작업 처리 예산(bytes/sec). 0은 허용하지 않는다.
    pub io_bytes_per_sec: u64,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: if cfg!(target_os = "linux") {
                PathBuf::from("/var/lib/argos/backup")
            } else {
                PathBuf::from("./argos-data/backup")
            },
            max_file_bytes: 50 * 1024 * 1024,
            keep_versions: 5,
            baseline_on_start: true,
            queue_capacity: 256,
            io_bytes_per_sec: 10 * 1024 * 1024,
        }
    }
}

/// 중앙관리 서버 연동 설정 (요건서 15장).
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CentralConfig {
    /// 비어 있으면 중앙 서버 연동을 하지 않는다 (standalone 모드).
    pub url: String,
    /// Bearer 인증 토큰. Phase 4에서 mTLS 인증서 기반으로 교체 예정.
    pub token: String,
    /// 비어 있으면 hostname을 사용한다.
    pub agent_id: String,
}

impl std::fmt::Debug for CentralConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CentralConfig")
            .field("url", &self.url)
            .field("token", &"[REDACTED]")
            .field("agent_id", &self.agent_id)
            .finish()
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn agent_debug_redacts_central_token() {
        let mut config = AgentConfig::default();
        config.central.token = "never-log-this-secret".into();
        let log = format!("{config:?}");
        assert!(!log.contains("never-log-this-secret"));
        assert!(log.contains("[REDACTED]"));
    }
}

impl Default for CentralConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            token: String::new(),
            agent_id: String::new(),
        }
    }
}

impl AgentConfig {
    /// TOML 설정 파일을 읽는다. 파일이 없으면 기본값을 반환한다.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }
}

fn default_watch_path() -> PathBuf {
    if cfg!(target_os = "linux") {
        PathBuf::from("/home")
    } else {
        PathBuf::from("./watched")
    }
}

pub fn default_db_path() -> PathBuf {
    if cfg!(target_os = "linux") {
        PathBuf::from("/var/lib/argos/argos.db")
    } else {
        PathBuf::from("./argos-data/argos.db")
    }
}
