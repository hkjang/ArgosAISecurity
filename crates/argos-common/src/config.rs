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
        }
    }
}

/// 중앙관리 서버 연동 설정 (요건서 15장).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CentralConfig {
    /// 비어 있으면 중앙 서버 연동을 하지 않는다 (standalone 모드).
    pub url: String,
    /// Bearer 인증 토큰. Phase 4에서 mTLS 인증서 기반으로 교체 예정.
    pub token: String,
    /// 비어 있으면 hostname을 사용한다.
    pub agent_id: String,
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
