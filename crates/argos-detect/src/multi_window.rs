//! 장기·분산 변경의 제한된 메모리 집계. 집계 위험은 개별 PID 차단 근거가 아니다.
use argos_common::{
    config::{DetectionConfig, SensorKind},
    Detection, FileAction, FileEvent,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
    sync::Arc,
};

pub const INSTANCE_RULE: &str = "behavior.multi_window.instance";
pub const USER_RULE: &str = "behavior.multi_window.user_path";
pub const PATH_RULE: &str = "behavior.multi_window.protected_path";
pub const ANCESTOR_RULE: &str = "behavior.multi_window.ancestor";
pub const RULES: [&str; 4] = [INSTANCE_RULE, USER_RULE, PATH_RULE, ANCESTOR_RULE];

type Instance = (u32, u64, String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Group {
    Instance(Instance),
    User(u32, String, String),
    ProtectedPath(String, String),
    Ancestor(Instance, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DetectionEngine;
    use argos_common::{
        config::{ApprovedChange, DetectionWindow},
        FileProcessContext, ProcessIdentity,
    };

    fn config() -> DetectionConfig {
        let mut config = DetectionConfig::default();
        config.multi_window.enabled = true;
        config.multi_window.protected_paths = vec!["/data".into()];
        config.multi_window.windows = vec![
            DetectionWindow {
                window_secs: 10,
                min_changed_files: 5,
                mass_change_threshold: 10,
                detect_score: 80.0,
            },
            DetectionWindow {
                window_secs: 60,
                min_changed_files: 5,
                mass_change_threshold: 10,
                detect_score: 80.0,
            },
            DetectionWindow {
                window_secs: 600,
                min_changed_files: 5,
                mass_change_threshold: 10,
                detect_score: 80.0,
            },
        ];
        config
    }

    fn event(timestamp_ms: u64, pid: u32, start: u64, index: u32) -> FileEvent {
        FileEvent {
            timestamp_ms,
            pid,
            path: format!("/data/file-{index}"),
            action: FileAction::Modify,
            entropy: Some(7.9),
            size: Some(100),
            content: None,
            process: Some(FileProcessContext {
                uid: 1000,
                exe: "/usr/bin/task".into(),
                start_time_ticks: start,
                boot_id: "boot-a".into(),
                ancestors: vec![ProcessIdentity {
                    pid: 10,
                    start_time_ticks: 10,
                    boot_id: "boot-a".into(),
                }],
            }),
        }
    }

    #[test]
    fn low_and_slow_activity_crosses_long_window_with_per_instance_evidence() {
        let mut engine = DetectionEngine::with_sensor(config(), SensorKind::Fanotify);
        for i in 0..5 {
            let result = engine.evaluate(&event(i as u64 * 110_000, 42, 42, i));
            if i < 4 {
                assert!(!result.block_candidate(&argos_common::config::ResponseConfig::default()));
            } else {
                assert!(result.block_candidate(&argos_common::config::ResponseConfig::default()));
                assert!(
                    result
                        .additional_alerts
                        .iter()
                        .any(|alert| alert.rule == INSTANCE_RULE
                            && alert.summary.starts_with("600초"))
                );
                assert!(
                    result.alert.is_none(),
                    "기존 10초 룰에는 파일 하나만 남는다"
                );
            }
        }
    }

    #[test]
    fn distributed_pids_aggregate_by_user_path_and_ancestry_without_blocking_current_pid() {
        let mut engine = DetectionEngine::with_sensor(config(), SensorKind::Fanotify);
        for i in 0..5 {
            let result = engine.evaluate(&event(i as u64 * 10_001, 100 + i, 100 + i as u64, i));
            assert!(!result.block_candidate(&argos_common::config::ResponseConfig::default()));
            if i == 4 {
                for rule in [USER_RULE, PATH_RULE, ANCESTOR_RULE] {
                    let alert = result
                        .additional_alerts
                        .iter()
                        .find(|alert| alert.rule == rule)
                        .unwrap();
                    assert_eq!(alert.pid, 0);
                    assert!(alert.summary.contains("자동 차단=금지"));
                    assert!(alert.summary.contains("100") && alert.summary.contains("104"));
                }
                assert!(!result
                    .additional_alerts
                    .iter()
                    .any(|alert| alert.rule == INSTANCE_RULE));
            }
        }
    }

    #[test]
    fn window_boundary_included_and_one_millisecond_older_expired() {
        let mut config = config();
        config.multi_window.windows.truncate(1);
        let mut exact = MultiWindowScorer::new(config.clone(), SensorKind::Fanotify);
        let mut expired = MultiWindowScorer::new(config, SensorKind::Fanotify);
        for i in 0..4 {
            let e = event(i as u64, 42, 42, i);
            exact.evaluate(&e, &[]);
            expired.evaluate(&e, &[]);
        }
        assert!(!exact
            .evaluate(&event(10_000, 42, 42, 4), &[])
            .alerts
            .is_empty());
        assert!(expired
            .evaluate(&event(10_001, 42, 42, 4), &[])
            .alerts
            .is_empty());
    }

    #[test]
    fn pid_reuse_never_combines_instance_scores_but_shared_path_remains_investigable() {
        let mut engine = DetectionEngine::with_sensor(config(), SensorKind::Fanotify);
        for i in 0..5 {
            let result = engine.evaluate(&event(i as u64 * 11_000, 42, i as u64 + 1, i));
            assert!(!result.block_candidate(&argos_common::config::ResponseConfig::default()));
            assert!(!result
                .additional_alerts
                .iter()
                .any(|alert| alert.rule == INSTANCE_RULE));
            if i == 4 {
                assert!(result
                    .additional_alerts
                    .iter()
                    .any(|alert| alert.rule == PATH_RULE));
            }
        }
    }

    #[test]
    fn approval_adjusts_only_explicitly_named_rule() {
        let mut configuration = config();
        configuration.approved_changes = vec![ApprovedChange {
            id: "deploy".into(),
            valid_from_ms: 0,
            valid_until_ms: 600_000,
            paths: vec!["/data".into()],
            exe: "/usr/bin/task".into(),
            uid: 1000,
            adjusted_rules: vec![crate::BEHAVIOR_RULE.into(), USER_RULE.into()],
        }];
        let mut engine = DetectionEngine::with_sensor(configuration, SensorKind::Fanotify);
        for i in 0..5 {
            let result = engine.evaluate(&event(i as u64, 100 + i, i as u64 + 1, i));
            if i == 4 {
                assert!(result
                    .additional_alerts
                    .iter()
                    .any(|alert| alert.rule == PATH_RULE));
                assert!(!result
                    .additional_alerts
                    .iter()
                    .any(|alert| alert.rule == USER_RULE));
                assert_eq!(result.approved_change_id.as_deref(), Some("deploy"));
            }
        }
    }

    #[test]
    fn memory_capacity_and_stale_groups_are_bounded_and_coverage_loss_is_visible() {
        let mut configuration = config();
        configuration.multi_window.max_events = 6;
        configuration.multi_window.max_groups = 3;
        let mut scorer = MultiWindowScorer::new(configuration, SensorKind::Fanotify);
        for i in 0..100 {
            let outcome = scorer.evaluate(&event(i as u64, 100 + i, i as u64 + 1, i), &[]);
            assert!(scorer.events.len() <= 6);
            assert!(scorer.groups.len() <= 3);
            assert!(
                outcome.instance_score.is_none(),
                "집계 누락 상태에서 차단 신원을 추정하지 않는다"
            );
            if i > 0 {
                assert!(outcome.truncated);
            }
        }
        scorer.evaluate(&event(700_000, 999, 999, 999), &[]);
        assert_eq!(scorer.events.len(), 1);
    }

    #[test]
    fn replay_is_deterministic_and_missing_identity_cannot_create_instance_groups() {
        let mut a = DetectionEngine::with_sensor(config(), SensorKind::Fanotify);
        let mut b = DetectionEngine::with_sensor(config(), SensorKind::Fanotify);
        for i in 0..20 {
            let mut e = event(i as u64 * 11_000, 100 + i, i as u64 + 1, i);
            if i % 2 == 0 {
                e.process = None;
                e.pid = 0;
            }
            let x = a.evaluate(&e);
            let y = b.evaluate(&e);
            assert_eq!(x.score, y.score);
            assert_eq!(
                x.additional_alerts
                    .iter()
                    .map(|d| (&d.rule, &d.summary, &d.paths))
                    .collect::<Vec<_>>(),
                y.additional_alerts
                    .iter()
                    .map(|d| (&d.rule, &d.summary, &d.paths))
                    .collect::<Vec<_>>()
            );
            assert!(!x.additional_alerts.iter().any(|d| d.rule == INSTANCE_RULE));
        }
    }
}

impl Group {
    fn rule(&self) -> &'static str {
        match self {
            Self::Instance(_) => INSTANCE_RULE,
            Self::User(..) => USER_RULE,
            Self::ProtectedPath(..) => PATH_RULE,
            Self::Ancestor(..) => ANCESTOR_RULE,
        }
    }
    fn label(&self) -> String {
        match self {
            Self::Instance((pid, start, boot)) => format!("process={pid}/{start}/{boot}"),
            Self::User(uid, boot, path) => format!("effective_uid={uid}, boot={boot}, path={path}"),
            Self::ProtectedPath(boot, path) => format!("boot={boot}, protected_path={path}"),
            Self::Ancestor((pid, start, boot), path) => {
                format!("ancestor={pid}/{start}/{boot}, path={path}")
            }
        }
    }
}

struct Observation {
    sequence: u64,
    timestamp_ms: u64,
    path: String,
    pid: u32,
    instance: Option<Instance>,
    action: FileAction,
    encrypted: bool,
    groups: Vec<Group>,
}

#[derive(Default)]
struct GroupState {
    events: VecDeque<Arc<Observation>>,
    last_emit: BTreeMap<u64, (u64, f64)>,
}

#[derive(Default)]
pub(crate) struct MultiOutcome {
    pub alerts: Vec<Detection>,
    pub instance_score: Option<f64>,
    pub truncated: bool,
    pub approval_applied: bool,
}

pub(crate) struct MultiWindowScorer {
    config: DetectionConfig,
    sensor: SensorKind,
    events: VecDeque<Arc<Observation>>,
    groups: BTreeMap<Group, GroupState>,
    sequence: u64,
    watermark: u64,
    incomplete_until: Option<u64>,
}

impl MultiWindowScorer {
    pub fn new(config: DetectionConfig, sensor: SensorKind) -> Self {
        Self {
            config,
            sensor,
            events: VecDeque::new(),
            groups: BTreeMap::new(),
            sequence: 0,
            watermark: 0,
            incomplete_until: None,
        }
    }

    fn horizon_ms(&self) -> u64 {
        self.config
            .multi_window
            .windows
            .iter()
            .map(|w| w.window_secs.saturating_mul(1000))
            .max()
            .unwrap_or(0)
    }

    fn truncate(&mut self, now: u64) {
        self.incomplete_until = Some(now.saturating_add(self.horizon_ms()));
    }

    fn expire_front(&mut self) {
        if let Some(old) = self.events.pop_front() {
            for group in &old.groups {
                if let Some(state) = self.groups.get_mut(group) {
                    if state
                        .events
                        .front()
                        .is_some_and(|event| event.sequence == old.sequence)
                    {
                        state.events.pop_front();
                    }
                    if state.events.is_empty() {
                        self.groups.remove(group);
                    }
                }
            }
        }
    }

    fn group_keys(&self, event: &FileEvent) -> Vec<Group> {
        let mut keys = Vec::new();
        let context = event.process.as_ref().filter(|p| {
            event.pid != 0
                && p.start_time_ticks > 0
                && !p.boot_id.is_empty()
                && p.boot_id.len() <= 128
        });
        if let Some(p) = context {
            keys.push(Group::Instance((
                event.pid,
                p.start_time_ticks,
                p.boot_id.clone(),
            )));
        }
        let root = self
            .config
            .multi_window
            .protected_paths
            .iter()
            .filter(|root| Path::new(&event.path).starts_with(root))
            .max_by_key(|root| root.components().count());
        if let Some(root) = root {
            let root = root.to_string_lossy().into_owned();
            let boot = context
                .map_or("unidentified", |p| p.boot_id.as_str())
                .to_string();
            keys.push(Group::ProtectedPath(boot.clone(), root.clone()));
            if let Some(p) = context {
                if self.config.multi_window.aggregate_by_user {
                    keys.push(Group::User(p.uid, boot.clone(), root.clone()));
                }
                if self.config.multi_window.aggregate_by_ancestry {
                    for ancestor in p
                        .ancestors
                        .iter()
                        .take(4)
                        .filter(|a| a.pid != 0 && a.start_time_ticks != 0 && a.boot_id == boot)
                    {
                        // PID 1은 모든 프로세스를 결합하므로 계보의 유의미한 집계 근거로 쓰지 않는다.
                        if ancestor.pid != 1 {
                            keys.push(Group::Ancestor(
                                (
                                    ancestor.pid,
                                    ancestor.start_time_ticks,
                                    ancestor.boot_id.clone(),
                                ),
                                root.clone(),
                            ));
                        }
                    }
                }
            }
        }
        keys.sort();
        keys.dedup();
        keys
    }

    pub fn evaluate(&mut self, event: &FileEvent, adjusted_rules: &[String]) -> MultiOutcome {
        if !self.config.multi_window.enabled {
            return MultiOutcome::default();
        }
        let now = self.watermark.max(event.timestamp_ms);
        self.watermark = now;
        let horizon = now.saturating_sub(self.horizon_ms());
        while self
            .events
            .front()
            .is_some_and(|e| e.timestamp_ms < horizon)
        {
            self.expire_front();
        }
        if event.timestamp_ms < now
            || event.path.len() > self.config.multi_window.max_path_bytes
            || !super::absolute_clean_path(Path::new(&event.path))
        {
            self.truncate(now);
            return MultiOutcome {
                truncated: true,
                ..MultiOutcome::default()
            };
        }
        let keys = self.group_keys(event);
        let included: Vec<_> = keys
            .iter()
            .filter(|key| !adjusted_rules.iter().any(|rule| rule == key.rule()))
            .cloned()
            .collect();
        let approval_applied = included.len() < keys.len();
        if !included.is_empty()
            && matches!(
                event.action,
                FileAction::Modify | FileAction::Create | FileAction::Delete | FileAction::Rename
            )
        {
            let max_events = self.config.multi_window.max_events.clamp(1, 100_000);
            while self.events.len() >= max_events {
                self.truncate(now);
                self.expire_front();
            }
            self.sequence = self.sequence.saturating_add(1);
            let entry = Arc::new(Observation {
                sequence: self.sequence,
                timestamp_ms: now,
                path: event.path.clone(),
                pid: event.pid,
                instance: event
                    .process
                    .as_ref()
                    .filter(|p| {
                        event.pid != 0
                            && p.start_time_ticks > 0
                            && !p.boot_id.is_empty()
                            && p.boot_id.len() <= 128
                    })
                    .map(|p| (event.pid, p.start_time_ticks, p.boot_id.clone())),
                action: event.action,
                encrypted: super::entropy::encryption_signal(event, &self.config),
                groups: included.clone(),
            });
            for key in included {
                if !self.groups.contains_key(&key)
                    && self.groups.len() >= self.config.multi_window.max_groups.clamp(1, 16_384)
                {
                    let oldest = self
                        .groups
                        .iter()
                        .min_by_key(|(key, state)| {
                            (state.events.back().map_or(0, |e| e.timestamp_ms), *key)
                        })
                        .map(|(key, _)| key.clone());
                    if let Some(oldest) = oldest {
                        self.groups.remove(&oldest);
                        self.truncate(now);
                    }
                }
                self.groups
                    .entry(key)
                    .or_default()
                    .events
                    .push_back(Arc::clone(&entry));
            }
            self.events.push_back(entry);
        }
        let truncated = self.incomplete_until.is_some_and(|until| now <= until);
        let mut outcome = MultiOutcome {
            truncated,
            approval_applied,
            ..MultiOutcome::default()
        };
        for key in keys {
            let Some(state) = self.groups.get_mut(&key) else {
                continue;
            };
            for window in self.config.multi_window.windows.iter().take(8) {
                let window_ms = window.window_secs.saturating_mul(1000);
                let selected: Vec<_> = state
                    .events
                    .iter()
                    .filter(|e| e.timestamp_ms >= now.saturating_sub(window_ms))
                    .collect();
                let paths: BTreeSet<_> = selected.iter().map(|e| e.path.as_str()).collect();
                if paths.len() < window.min_changed_files {
                    continue;
                }
                let high: BTreeSet<_> = selected
                    .iter()
                    .filter(|e| e.action == FileAction::Modify && e.encrypted)
                    .map(|e| e.path.as_str())
                    .collect();
                let mass = (paths.len() as f64 / window.mass_change_threshold.max(1) as f64)
                    .min(1.0)
                    * 40.0;
                let entropy = high.len() as f64 / paths.len() as f64
                    * if self.sensor == SensorKind::Fanotify {
                        60.0
                    } else {
                        35.0
                    };
                let churn = if self.sensor == SensorKind::Notify {
                    selected
                        .iter()
                        .filter(|e| matches!(e.action, FileAction::Delete | FileAction::Rename))
                        .count() as f64
                        / selected.len() as f64
                        * 25.0
                } else {
                    0.0
                };
                let score = (mass + entropy + churn).min(100.0);
                if matches!(key, Group::Instance(_)) && !truncated {
                    outcome.instance_score =
                        Some(outcome.instance_score.map_or(score, |old| old.max(score)));
                }
                if score < window.detect_score {
                    continue;
                }
                if state
                    .last_emit
                    .get(&window.window_secs)
                    .is_some_and(|(last, previous)| {
                        now.saturating_sub(*last) < window_ms && score < previous + 15.0
                    })
                {
                    continue;
                }
                state.last_emit.insert(window.window_secs, (now, score));
                let pids: BTreeSet<_> = selected.iter().map(|e| e.pid).collect();
                let instances: BTreeSet<_> = selected
                    .iter()
                    .filter_map(|e| e.instance.as_ref())
                    .collect();
                let identities: Vec<_> = instances
                    .iter()
                    .take(20)
                    .map(|(pid, start, boot)| format!("{pid}/{start}/{boot}"))
                    .collect();
                let pid = match &key {
                    Group::Instance((pid, _, _)) => *pid,
                    _ => 0,
                };
                outcome.alerts.push(Detection { timestamp_ms: now, rule: key.rule().into(), score,
                    severity: super::BehaviorScorer::severity(score), pid,
                    summary: format!("{}초 집계 [{}]: 파일 {}개, PID {:?}, 신원 {:?}, 증거 제한={}, 집계 자동 차단={}", window.window_secs, key.label(), paths.len(), pids.iter().take(20).collect::<Vec<_>>(), identities, truncated || pids.len() > 20 || instances.len() > 20, if pid == 0 { "금지" } else { "개별 정책 평가" }),
                    paths: paths.into_iter().take(20).map(str::to_string).collect(),
                });
            }
        }
        outcome
    }
}
