//! Argos 공통 타입: 이벤트 모델, 탐지 결과, 에이전트 설정.

pub mod config;
pub mod event;

pub use config::AgentConfig;
pub use event::*;

use std::time::{SystemTime, UNIX_EPOCH};

/// 현재 시각을 epoch 밀리초로 반환한다.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
