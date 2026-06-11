//! 슬라이딩 윈도우 기반 행위 점수 산정.
//!
//! 요건서 8장 위험 점수 요소 중 Phase 1 범위:
//! 파일 변경 속도, 변경 파일 수, 엔트로피, 확장자 변경(이름 변경) 빈도.
//! 프로세스 신뢰도·사용자 권한·자산 중요도는 Phase 2+.

use argos_common::{config::DetectionConfig, Detection, FileAction, FileEvent, Pid, Severity};
use std::collections::{HashMap, HashSet, VecDeque};

/// 윈도우에 보관하는 이벤트 요약.
struct WindowEntry {
    timestamp_ms: u64,
    path: String,
    action: FileAction,
    entropy: Option<f64>,
}

/// pid별 슬라이딩 윈도우를 유지하며 행위 점수를 계산한다.
///
/// Phase 1 센서(notify)는 pid를 제공하지 못해 모든 이벤트가 pid 0으로
/// 합산된다(호스트 단위 점수). fanotify 센서 적용 시 프로세스 단위가 된다.
pub struct BehaviorScorer {
    config: DetectionConfig,
    windows: HashMap<Pid, VecDeque<WindowEntry>>,
    /// pid별 마지막 Detection (시각, 점수) — 같은 사고의 중복 탐지 억제.
    last_emit: HashMap<Pid, (u64, f64)>,
}

/// 쿨다운 중이라도 점수가 이만큼 오르면 다시 보고한다 (사고 악화 감지).
const ESCALATION_DELTA: f64 = 15.0;

impl BehaviorScorer {
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            config,
            windows: HashMap::new(),
            last_emit: HashMap::new(),
        }
    }

    pub fn observe(&mut self, event: &FileEvent) -> Option<Detection> {
        let window = self.windows.entry(event.pid).or_default();
        window.push_back(WindowEntry {
            timestamp_ms: event.timestamp_ms,
            path: event.path.clone(),
            action: event.action,
            entropy: event.entropy,
        });

        // 윈도우 밖 이벤트 제거.
        let horizon = event
            .timestamp_ms
            .saturating_sub(self.config.window_secs * 1000);
        while window.front().map_or(false, |e| e.timestamp_ms < horizon) {
            window.pop_front();
        }

        // 단일·소수 파일 변경은 점수와 무관하게 탐지하지 않는다 (오탐 방지).
        let changed_files: HashSet<&str> = window.iter().map(|e| e.path.as_str()).collect();
        if changed_files.len() < self.config.min_changed_files {
            return None;
        }

        let score = Self::score(window, &self.config);
        if score < self.config.detect_score {
            return None;
        }

        // 쿨다운: 같은 pid의 사고는 윈도우당 1회만 보고하되,
        // 점수가 크게 오르면(악화) 즉시 다시 보고한다.
        if let Some(&(last_ts, last_score)) = self.last_emit.get(&event.pid) {
            let in_cooldown =
                event.timestamp_ms.saturating_sub(last_ts) < self.config.window_secs * 1000;
            if in_cooldown && score < last_score + ESCALATION_DELTA {
                return None;
            }
        }
        self.last_emit.insert(event.pid, (event.timestamp_ms, score));

        let distinct: HashSet<&str> = window.iter().map(|e| e.path.as_str()).collect();
        let mut paths: Vec<String> = distinct.iter().take(20).map(|s| s.to_string()).collect();
        paths.sort();

        Some(Detection {
            timestamp_ms: event.timestamp_ms,
            rule: "behavior.ransomware_pattern".to_string(),
            score,
            severity: Self::severity(score),
            summary: format!(
                "{}초 내 파일 {}개 변경 (이벤트 {}건, 위험 점수 {:.0})",
                self.config.window_secs,
                distinct.len(),
                window.len(),
                score
            ),
            pid: event.pid,
            paths,
        })
    }

    /// 0 ~ 100 위험 점수.
    fn score(window: &VecDeque<WindowEntry>, config: &DetectionConfig) -> f64 {
        let distinct_paths: HashSet<&str> = window.iter().map(|e| e.path.as_str()).collect();
        let renames = window
            .iter()
            .filter(|e| e.action == FileAction::Rename)
            .count();
        let deletes = window
            .iter()
            .filter(|e| e.action == FileAction::Delete)
            .count();
        let high_entropy_writes = window
            .iter()
            .filter(|e| {
                e.action == FileAction::Modify
                    && e.entropy.map_or(false, |x| x >= config.entropy_threshold)
            })
            .count();

        // 대량 변경: 임계치 대비 비율 (최대 40점).
        let mass = (distinct_paths.len() as f64 / config.mass_change_threshold as f64).min(1.0) * 40.0;
        // 고엔트로피 쓰기: 변경 파일 대비 비율 (최대 35점).
        let enc = if distinct_paths.is_empty() {
            0.0
        } else {
            (high_entropy_writes as f64 / distinct_paths.len() as f64).min(1.0) * 35.0
        };
        // 이름 변경(확장자 변경 의심) + 삭제: 합산 비율 (최대 25점).
        let churn = if window.is_empty() {
            0.0
        } else {
            ((renames + deletes) as f64 / window.len() as f64).min(1.0) * 25.0
        };

        (mass + enc + churn).min(100.0)
    }

    fn severity(score: f64) -> Severity {
        if score >= 85.0 {
            Severity::Critical
        } else if score >= 65.0 {
            Severity::High
        } else if score >= 40.0 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_common::config::DetectionConfig;

    fn event(ts: u64, path: &str, action: FileAction, entropy: Option<f64>) -> FileEvent {
        FileEvent {
            timestamp_ms: ts,
            pid: 0,
            path: path.to_string(),
            action,
            size: None,
            entropy,
        }
    }

    #[test]
    fn single_edit_does_not_detect() {
        let mut s = BehaviorScorer::new(DetectionConfig::default());
        let d = s.observe(&event(1000, "/home/a.txt", FileAction::Modify, Some(4.0)));
        assert!(d.is_none());
    }

    #[test]
    fn mass_encryption_pattern_detects() {
        let config = DetectionConfig::default();
        let mut s = BehaviorScorer::new(config);
        let mut best: Option<Detection> = None;
        let mut emitted = 0usize;
        for i in 0..40u64 {
            // 짧은 시간 내 다수 파일 고엔트로피 쓰기 + 이름 변경 = 랜섬웨어 패턴.
            for d in [
                s.observe(&event(
                    1000 + i * 10,
                    &format!("/home/file{i}.docx"),
                    FileAction::Modify,
                    Some(7.9),
                )),
                s.observe(&event(
                    1000 + i * 10 + 5,
                    &format!("/home/file{i}.docx.locked"),
                    FileAction::Rename,
                    None,
                )),
            ]
            .into_iter()
            .flatten()
            {
                emitted += 1;
                best = Some(d);
            }
        }
        let d = best.expect("mass change should produce a detection");
        // 에스컬레이션 재보고는 +15 단위라 마지막 발행 점수는 detect_score+15 부근이다.
        assert!(d.score >= 50.0, "score {}", d.score);
        assert!(d.severity >= Severity::Medium, "severity {:?}", d.severity);
        // 쿨다운: 80회 이벤트에 탐지가 소수만 발생해야 한다 (악화 시 재보고 포함).
        assert!(emitted <= 5, "emitted {emitted} detections (cooldown broken)");
    }

    #[test]
    fn old_events_fall_out_of_window() {
        let config = DetectionConfig::default();
        let window_ms = config.window_secs * 1000;
        let mut s = BehaviorScorer::new(config);
        for i in 0..40u64 {
            s.observe(&event(
                1000 + i * 10,
                &format!("/home/f{i}"),
                FileAction::Modify,
                Some(7.9),
            ));
        }
        // 윈도우를 훨씬 지난 단일 이벤트는 탐지되지 않아야 한다.
        let d = s.observe(&event(
            1000 + 400 + window_ms + 1000,
            "/home/later.txt",
            FileAction::Modify,
            Some(4.0),
        ));
        assert!(d.is_none());
    }
}
