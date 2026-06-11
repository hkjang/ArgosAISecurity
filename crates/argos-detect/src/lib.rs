//! Argos Detect: 행위 기반 랜섬웨어 탐지 엔진 (룰 엔진 + 행위 점수).
//!
//! 요건서 8장: 행위 기반 탐지 우선, 점수 기반 룰, 1초 이내 1차 판단.

pub mod entropy;
pub mod scorer;

pub use entropy::{file_entropy, shannon_entropy};
pub use scorer::BehaviorScorer;

use argos_common::{config::DetectionConfig, Detection, FileEvent};

/// 탐지 엔진. 현재는 행위 스코어러 단일 구성이며,
/// Phase 2에서 정적 룰(YAML)·동적 룰을 같은 인터페이스로 추가한다.
pub struct DetectionEngine {
    scorer: BehaviorScorer,
    config: DetectionConfig,
}

impl DetectionEngine {
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            scorer: BehaviorScorer::new(config.clone()),
            config,
        }
    }

    /// 파일 이벤트 하나를 관찰하고, 위험 점수가 임계치를 넘으면 Detection을 반환한다.
    pub fn observe(&mut self, event: &FileEvent) -> Option<Detection> {
        if self.is_excluded(&event.path) {
            return None;
        }
        self.scorer.observe(event)
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.config
            .exclude_paths
            .iter()
            .any(|p| path.starts_with(p.to_string_lossy().as_ref()))
    }
}
