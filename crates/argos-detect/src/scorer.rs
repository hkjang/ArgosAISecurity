//! 슬라이딩 윈도우 기반 행위 점수 산정.
//!
//! 요건서 8장 위험 점수 요소 중 Phase 1 범위:
//! 파일 변경 속도, 변경 파일 수, 엔트로피, 확장자 변경(이름 변경) 빈도.
//! 프로세스 신뢰도·사용자 권한·자산 중요도는 Phase 2+.

use argos_common::{
    config::{DetectionConfig, ResponseConfig, SensorKind},
    Detection, FileAction, FileEvent, Pid, Severity,
};
use std::collections::{HashMap, HashSet, VecDeque};

/// 매 이벤트의 위험 평가. 알림 쿨다운은 `alert`에만 적용된다.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub score: f64,
    pub pid: Pid,
    /// 최소 변경 파일 수를 충족하며 제외 경로가 아닌 경우에만 true.
    pub eligible: bool,
    pub alert: Option<Detection>,
    /// 해당 이벤트의 행위 룰 증거를 제외한 승인 작업 ID (감사용).
    pub approved_change_id: Option<String>,
    /// 집계·추가 시간창의 알림. 집계 결과로 현재 PID를 자동 차단하지 않는다.
    pub additional_alerts: Vec<Detection>,
    /// 메모리 상한 또는 지원하지 않는 증거 때문에 일부 관찰을 제외했다.
    pub evidence_truncated: bool,
}

impl Evaluation {
    /// 관찰 모드에서도 확인할 수 있는 차단 예상 대상 여부.
    pub fn block_candidate(&self, response: &ResponseConfig) -> bool {
        self.eligible && self.pid != 0 && self.score >= response.block_score
    }

    /// 자동 대응 정책을 포함한 판단. 알림 여부와 무관하다.
    pub fn should_block(&self, response: &ResponseConfig) -> bool {
        response.auto_block && self.block_candidate(response)
    }
}

/// 윈도우에 보관하는 이벤트 요약.
struct WindowEntry {
    timestamp_ms: u64,
    path: String,
    action: FileAction,
    encryption_signal: bool,
}

/// pid별 슬라이딩 윈도우를 유지하며 행위 점수를 계산한다.
///
/// Phase 1 센서(notify)는 pid를 제공하지 못해 모든 이벤트가 pid 0으로
/// 합산된다(호스트 단위 점수). fanotify 센서 적용 시 프로세스 단위가 된다.
pub struct BehaviorScorer {
    config: DetectionConfig,
    sensor: SensorKind,
    windows: HashMap<Pid, VecDeque<WindowEntry>>,
    /// pid별 마지막 Detection (시각, 점수) — 같은 사고의 중복 탐지 억제.
    last_emit: HashMap<Pid, (u64, f64)>,
    /// PID 재사용이나 재부팅 시 이전 프로세스의 위험 점수를 이어받지 않는다.
    process_identities: HashMap<Pid, Option<(u64, String)>>,
    incomplete_until: Option<u64>,
}

/// 쿨다운 중이라도 점수가 이만큼 오르면 다시 보고한다 (사고 악화 감지).
const ESCALATION_DELTA: f64 = 15.0;

impl BehaviorScorer {
    pub fn new(config: DetectionConfig) -> Self {
        Self::with_sensor(config, SensorKind::Notify)
    }

    pub fn with_sensor(config: DetectionConfig, sensor: SensorKind) -> Self {
        Self {
            config,
            sensor,
            windows: HashMap::new(),
            last_emit: HashMap::new(),
            process_identities: HashMap::new(),
            incomplete_until: None,
        }
    }

    pub fn observe(&mut self, event: &FileEvent) -> Option<Detection> {
        self.evaluate(event).alert
    }

    /// 이벤트에 기록된 시각만 사용하므로 저장 이벤트 재생도 같은 결과를 낸다.
    pub fn evaluate(&mut self, event: &FileEvent) -> Evaluation {
        self.evaluate_with_approval(event, None)
    }

    pub(crate) fn evaluate_with_approval(
        &mut self,
        event: &FileEvent,
        approved_change_id: Option<String>,
    ) -> Evaluation {
        let horizon = event
            .timestamp_ms
            .saturating_sub(self.config.window_secs.saturating_mul(1000));
        self.windows.retain(|_, window| {
            window.retain(|entry| entry.timestamp_ms >= horizon);
            !window.is_empty()
        });
        self.last_emit
            .retain(|pid, _| self.windows.contains_key(pid));
        self.process_identities
            .retain(|pid, _| self.windows.contains_key(pid));
        let max_groups = self.config.multi_window.max_groups.clamp(1, 16_384);
        let max_events = self.config.multi_window.max_events.clamp(1, 100_000);
        if !self.windows.contains_key(&event.pid) && self.windows.len() >= max_groups {
            if let Some(oldest) = self
                .windows
                .iter()
                .min_by_key(|(pid, events)| (events.back().map_or(0, |e| e.timestamp_ms), **pid))
                .map(|(pid, _)| *pid)
            {
                self.windows.remove(&oldest);
                self.last_emit.remove(&oldest);
                self.process_identities.remove(&oldest);
            }
            self.incomplete_until = Some(
                event
                    .timestamp_ms
                    .saturating_add(self.config.window_secs.saturating_mul(1000)),
            );
        }
        let mut count: usize = self.windows.values().map(VecDeque::len).sum();
        while count >= max_events {
            if let Some(oldest) = self
                .windows
                .iter()
                .filter(|(_, entries)| !entries.is_empty())
                .min_by_key(|(pid, entries)| (entries.front().unwrap().timestamp_ms, **pid))
                .map(|(pid, _)| *pid)
            {
                self.windows.get_mut(&oldest).unwrap().pop_front();
            }
            count -= 1;
            self.incomplete_until = Some(
                event
                    .timestamp_ms
                    .saturating_add(self.config.window_secs.saturating_mul(1000)),
            );
        }
        if event.path.len() > self.config.multi_window.max_path_bytes
            || event
                .process
                .as_ref()
                .is_some_and(|p| p.boot_id.len() > 128)
        {
            return Evaluation {
                score: 0.0,
                pid: event.pid,
                eligible: false,
                alert: None,
                approved_change_id,
                additional_alerts: Vec::new(),
                evidence_truncated: true,
            };
        }
        let identity = event
            .process
            .as_ref()
            .map(|p| (p.start_time_ticks, p.boot_id.clone()));
        if self
            .process_identities
            .get(&event.pid)
            .is_some_and(|old| *old != identity)
        {
            self.windows.remove(&event.pid);
            self.last_emit.remove(&event.pid);
        }
        self.process_identities.insert(event.pid, identity);
        let window = self.windows.entry(event.pid).or_default();
        if approved_change_id.is_none() {
            window.push_back(WindowEntry {
                timestamp_ms: event.timestamp_ms,
                path: event.path.clone(),
                action: event.action,
                encryption_signal: crate::entropy::encryption_signal(event, &self.config),
            });
        }

        // 윈도우 밖 이벤트 제거.
        let horizon = event
            .timestamp_ms
            .saturating_sub(self.config.window_secs.saturating_mul(1000));
        while window.front().map_or(false, |e| e.timestamp_ms < horizon) {
            window.pop_front();
        }

        // 위험 점수와 최소 파일 수 조건은 알림 억제보다 먼저 매번 평가한다.
        let changed_files: HashSet<&str> = window.iter().map(|e| e.path.as_str()).collect();
        let score = Self::score(window, &self.config, self.sensor);
        let mut evaluation = Evaluation {
            score,
            pid: event.pid,
            eligible: changed_files.len() >= self.config.min_changed_files
                && !self
                    .incomplete_until
                    .is_some_and(|until| event.timestamp_ms <= until),
            alert: None,
            approved_change_id,
            additional_alerts: Vec::new(),
            evidence_truncated: self
                .incomplete_until
                .is_some_and(|until| event.timestamp_ms <= until),
        };
        if !evaluation.eligible || score < self.config.detect_score {
            return evaluation;
        }

        // 쿨다운: 같은 pid의 사고는 윈도우당 1회만 보고하되,
        // 점수가 크게 오르면(악화) 즉시 다시 보고한다.
        if let Some(&(last_ts, last_score)) = self.last_emit.get(&event.pid) {
            let in_cooldown = event.timestamp_ms.saturating_sub(last_ts)
                < self.config.window_secs.saturating_mul(1000);
            if in_cooldown && score < last_score + ESCALATION_DELTA {
                return evaluation;
            }
        }
        self.last_emit
            .insert(event.pid, (event.timestamp_ms, score));

        let distinct: HashSet<&str> = window.iter().map(|e| e.path.as_str()).collect();
        let mut paths: Vec<String> = distinct.iter().map(|s| s.to_string()).collect();
        paths.sort();
        paths.truncate(20);

        evaluation.alert = Some(Detection {
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
        });
        evaluation
    }

    /// 0 ~ 100 위험 점수.
    fn score(window: &VecDeque<WindowEntry>, config: &DetectionConfig, sensor: SensorKind) -> f64 {
        let distinct_paths: HashSet<&str> = window.iter().map(|e| e.path.as_str()).collect();
        let renames = window
            .iter()
            .filter(|e| e.action == FileAction::Rename)
            .count();
        let deletes = window
            .iter()
            .filter(|e| e.action == FileAction::Delete)
            .count();
        let high_entropy_paths: HashSet<&str> = window
            .iter()
            .filter(|e| e.action == FileAction::Modify && e.encryption_signal)
            .map(|e| e.path.as_str())
            .collect();

        // 대량 변경: 임계치 대비 비율 (최대 40점).
        let mass = (distinct_paths.len() as f64 / config.mass_change_threshold.max(1) as f64)
            .min(1.0)
            * 40.0;
        // fanotify는 수정 이벤트만 제공한다. 미지원 churn의 25점을
        // 엔트로피 증거에 배정한다. 반복 쓰기는 파일당 한 번만 계산한다.
        let entropy_weight = match sensor {
            SensorKind::Notify => 35.0,
            SensorKind::Fanotify => 60.0,
        };
        let enc = if distinct_paths.is_empty() {
            0.0
        } else {
            high_entropy_paths.len() as f64 / distinct_paths.len() as f64 * entropy_weight
        };
        // 이름 변경(확장자 변경 의심) + 삭제: 합산 비율 (최대 25점).
        let churn = if window.is_empty() || sensor == SensorKind::Fanotify {
            0.0
        } else {
            ((renames + deletes) as f64 / window.len() as f64).min(1.0) * 25.0
        };

        (mass + enc + churn).min(100.0)
    }

    pub(crate) fn severity(score: f64) -> Severity {
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
            process: None,
            content: None,
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
        assert!(
            emitted <= 5,
            "emitted {emitted} detections (cooldown broken)"
        );
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

    #[test]
    fn fanotify_crosses_default_block_score_while_alert_is_suppressed() {
        let mut scorer =
            BehaviorScorer::with_sensor(DetectionConfig::default(), SensorKind::Fanotify);
        let response = ResponseConfig {
            auto_block: true,
            ..ResponseConfig::default()
        };
        let mut last = None;
        for i in 0..15 {
            let mut e = event(
                1000 + i,
                &format!("/home/{i}.txt"),
                FileAction::Modify,
                Some(7.9),
            );
            e.pid = 42;
            let assessment = scorer.evaluate(&e);
            if i < 14 {
                assert!(!assessment.should_block(&response));
            }
            last = Some(assessment);
        }
        let crossing = last.unwrap();
        assert_eq!(crossing.score, 80.0);
        assert!(
            crossing.alert.is_none(),
            "+15 미만의 상승은 알림 쿨다운 유지"
        );
        assert!(
            crossing.should_block(&response),
            "알림 없이도 임계치 통과를 판정"
        );
        assert!(crossing.block_candidate(&ResponseConfig::default()));
        assert!(
            !crossing.should_block(&ResponseConfig::default()),
            "자동 대응 기본 비활성"
        );
    }

    #[test]
    fn response_threshold_does_not_depend_on_alert_threshold() {
        let config = DetectionConfig {
            detect_score: 90.0,
            ..DetectionConfig::default()
        };
        let mut scorer = BehaviorScorer::with_sensor(config, SensorKind::Fanotify);
        let mut last = None;
        for i in 0..15 {
            let mut e = event(i, &format!("/home/{i}"), FileAction::Modify, Some(7.9));
            e.pid = 42;
            last = Some(scorer.evaluate(&e));
        }
        let assessment = last.unwrap();
        assert!(assessment.alert.is_none());
        assert!(assessment.block_candidate(&ResponseConfig::default()));
    }

    #[test]
    fn minimum_files_and_known_pid_remain_required_for_response() {
        let config = DetectionConfig {
            mass_change_threshold: 1,
            ..DetectionConfig::default()
        };
        let mut scorer = BehaviorScorer::with_sensor(config, SensorKind::Fanotify);
        let mut e = event(1000, "/home/one", FileAction::Modify, Some(7.9));
        e.pid = 42;
        let single = scorer.evaluate(&e);
        assert_eq!(single.score, 100.0);
        assert!(!single.eligible);
        assert!(!single.block_candidate(&ResponseConfig::default()));

        for i in 0..30 {
            let unknown = scorer.evaluate(&event(
                i,
                &format!("/home/{i}"),
                FileAction::Modify,
                Some(7.9),
            ));
            assert!(!unknown.block_candidate(&ResponseConfig::default()));
        }
    }

    #[test]
    fn repeated_entropy_writes_count_distinct_files() {
        let mut scorer =
            BehaviorScorer::with_sensor(DetectionConfig::default(), SensorKind::Fanotify);
        for i in 0..30 {
            scorer.evaluate(&event(
                i,
                &format!("/home/{i}"),
                FileAction::Modify,
                Some(3.0),
            ));
        }
        for i in 0..30 {
            let assessment =
                scorer.evaluate(&event(100 + i, "/home/0", FileAction::Modify, Some(7.9)));
            assert_eq!(
                assessment.score, 42.0,
                "동일 파일의 반복 쓰기로 점수를 증폭하지 않음"
            );
        }
    }

    #[test]
    fn fanotify_without_entropy_cannot_reach_block_threshold() {
        let mut scorer =
            BehaviorScorer::with_sensor(DetectionConfig::default(), SensorKind::Fanotify);
        for i in 0..100 {
            let mut e = event(i, &format!("/home/{i}"), FileAction::Modify, None);
            e.pid = 42;
            let assessment = scorer.evaluate(&e);
            assert!(assessment.score <= 40.0);
            assert!(!assessment.block_candidate(&ResponseConfig::default()));
        }
    }

    #[test]
    fn replay_uses_event_time_and_has_deterministic_evidence() {
        let mut left =
            BehaviorScorer::with_sensor(DetectionConfig::default(), SensorKind::Fanotify);
        let mut right =
            BehaviorScorer::with_sensor(DetectionConfig::default(), SensorKind::Fanotify);
        for i in 0..60 {
            let e = event(
                1000 + i,
                &format!("/home/{i}"),
                FileAction::Modify,
                Some(7.9),
            );
            let l = left.evaluate(&e);
            let r = right.evaluate(&e);
            assert_eq!(l.score, r.score);
            assert_eq!(
                l.alert.as_ref().map(|d| &d.paths),
                r.alert.as_ref().map(|d| &d.paths)
            );
        }
        let after_window =
            left.evaluate(&event(20000, "/home/later", FileAction::Modify, Some(7.9)));
        assert!(!after_window.eligible);
        assert!(after_window.alert.is_none());
    }

    #[test]
    fn legacy_windows_and_identity_caches_obey_memory_limits() {
        let mut config = DetectionConfig::default();
        config.multi_window.max_events = 6;
        config.multi_window.max_groups = 2;
        let mut scorer = BehaviorScorer::with_sensor(config, SensorKind::Fanotify);
        for i in 0..100 {
            let mut e = event(i, &format!("/home/{i}"), FileAction::Modify, Some(7.9));
            e.pid = i as u32 + 1;
            let result = scorer.evaluate(&e);
            assert!(scorer.windows.len() <= 2);
            assert!(scorer.windows.values().map(VecDeque::len).sum::<usize>() <= 6);
            assert!(scorer.process_identities.len() <= 2 && scorer.last_emit.len() <= 2);
            if i > 1 {
                assert!(result.evidence_truncated);
                assert!(!result.eligible);
            }
        }
    }
}
