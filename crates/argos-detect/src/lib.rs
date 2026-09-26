//! Argos Detect: 행위 기반 랜섬웨어 탐지 엔진 (룰 엔진 + 행위 점수).
//!
//! 요건서 8장: 행위 기반 탐지 우선, 점수 기반 룰, 1초 이내 1차 판단.

pub mod entropy;
mod multi_window;
pub mod scorer;

pub use entropy::{file_entropy, shannon_entropy, ContentSampler};
pub use scorer::{BehaviorScorer, Evaluation};

use argos_common::{
    config::{ApprovedChange, DetectionConfig, ResponseConfig, SensorKind},
    Detection, FileAction, FileEvent, Pid, Severity,
};
use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path},
};

const BEHAVIOR_RULE: &str = "behavior.ransomware_pattern";
const CANARY_RULE: &str = "behavior.canary_tamper";
type CanaryIdentity = (Pid, Option<(u64, String)>, String);

/// 탐지 엔진. 현재는 행위 스코어러 단일 구성이며,
/// Phase 2에서 정적 룰(YAML)·동적 룰을 같은 인터페이스로 추가한다.
pub struct DetectionEngine {
    scorer: BehaviorScorer,
    config: DetectionConfig,
    last_canary_emit: HashMap<CanaryIdentity, u64>,
    multi_window: multi_window::MultiWindowScorer,
}

impl DetectionEngine {
    pub fn new(config: DetectionConfig) -> Self {
        Self::with_sensor(config, SensorKind::Notify)
    }

    pub fn with_sensor(config: DetectionConfig, sensor: SensorKind) -> Self {
        Self {
            scorer: BehaviorScorer::with_sensor(config.clone(), sensor),
            multi_window: multi_window::MultiWindowScorer::new(config.clone(), sensor),
            config,
            last_canary_emit: HashMap::new(),
        }
    }

    /// 파일 이벤트 하나를 관찰하고, 위험 점수가 임계치를 넘으면 Detection을 반환한다.
    pub fn observe(&mut self, event: &FileEvent) -> Option<Detection> {
        self.evaluate(event).alert
    }

    /// 위험 점수와 대응 가능 여부를 매번 평가한다. 알림만 중복 억제한다.
    pub fn evaluate(&mut self, event: &FileEvent) -> Evaluation {
        let approval = self
            .config
            .approved_changes
            .iter()
            .find(|change| approved_event(change, event))
            .cloned();
        let mut assessment = if self.is_excluded(&event.path) {
            Evaluation {
                score: 0.0,
                pid: event.pid,
                eligible: false,
                alert: None,
                approved_change_id: None,
                additional_alerts: Vec::new(),
                evidence_truncated: false,
            }
        } else {
            let legacy = approval
                .as_ref()
                .filter(|change| {
                    change
                        .adjusted_rules
                        .iter()
                        .any(|rule| rule == BEHAVIOR_RULE)
                })
                .map(|change| change.id.clone());
            let mut assessment = self.scorer.evaluate_with_approval(event, legacy);
            let multi = self.multi_window.evaluate(
                event,
                approval
                    .as_ref()
                    .map_or(&[], |change| change.adjusted_rules.as_slice()),
            );
            if let Some(score) = multi.instance_score {
                assessment.score = assessment.score.max(score);
                assessment.eligible = true;
            }
            if multi.approval_applied {
                assessment.approved_change_id = approval.as_ref().map(|change| change.id.clone());
            }
            assessment.additional_alerts = multi.alerts;
            assessment.evidence_truncated |= multi.truncated;
            assessment
        };
        if matches!(
            event.action,
            FileAction::Modify | FileAction::Delete | FileAction::Rename
        ) && self
            .config
            .canary_paths
            .iter()
            .any(|path| path == Path::new(&event.path))
        {
            assessment.score = assessment.score.max(95.0);
            assessment.eligible = true;
            let identity = (
                event.pid,
                event
                    .process
                    .as_ref()
                    .filter(|p| p.boot_id.len() <= 128)
                    .map(|p| (p.start_time_ticks, p.boot_id.clone())),
                event.path.clone(),
            );
            let cooldown = self.last_canary_emit.get(&identity).is_some_and(|last| {
                event.timestamp_ms.saturating_sub(*last)
                    < self.config.window_secs.saturating_mul(1000)
            });
            if !cooldown && assessment.score >= self.config.detect_score {
                if !self.last_canary_emit.contains_key(&identity)
                    && self.last_canary_emit.len()
                        >= self.config.multi_window.max_groups.clamp(1, 16_384)
                {
                    if let Some(oldest) = self
                        .last_canary_emit
                        .iter()
                        .min_by_key(|(key, timestamp)| (**timestamp, *key))
                        .map(|(key, _)| key.clone())
                    {
                        self.last_canary_emit.remove(&oldest);
                    }
                    assessment.evidence_truncated = true;
                }
                self.last_canary_emit.insert(identity, event.timestamp_ms);
                assessment.alert = Some(Detection {
                    timestamp_ms: event.timestamp_ms,
                    rule: CANARY_RULE.into(),
                    score: assessment.score,
                    severity: Severity::Critical,
                    summary: format!("미끼 파일 변경 감지: {} ({:?})", event.path, event.action),
                    pid: event.pid,
                    paths: vec![event.path.clone()],
                });
            }
        }
        assessment
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.config
            .exclude_paths
            .iter()
            .any(|p| Path::new(path).starts_with(p))
    }
}

fn absolute_clean_path(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

fn approved_event(change: &ApprovedChange, event: &FileEvent) -> bool {
    let Some(process) = event.process.as_ref() else {
        return false;
    };
    event.pid != 0
        && process.start_time_ticks != 0
        && !process.boot_id.trim().is_empty()
        && event.timestamp_ms >= change.valid_from_ms
        && event.timestamp_ms < change.valid_until_ms
        && process.uid == change.uid
        && Path::new(&process.exe) == change.exe
        && absolute_clean_path(Path::new(&event.path))
        && change
            .paths
            .iter()
            .any(|path| Path::new(&event.path).starts_with(path))
}

/// 시작 시 및 정책 재생 전에 잘못된 설정과 센서별 대응 제약을 확인한다.
/// 성공 값에는 임계치 도달 불가 등 운영자가 확인할 경고가 담긴다.
pub fn validate_configuration(
    detection: &DetectionConfig,
    response: &ResponseConfig,
    sensor: SensorKind,
) -> Result<Vec<String>, String> {
    let mut errors = Vec::new();
    let mut approval_ids = HashSet::new();
    for change in &detection.approved_changes {
        if change.id.trim().is_empty() || !approval_ids.insert(change.id.as_str()) {
            errors.push("승인 작업 ID는 비어 있지 않고 중복되지 않아야 합니다");
        }
        if change.valid_until_ms <= change.valid_from_ms {
            errors.push("승인 작업의 종료 시각은 시작 시각보다 커야 합니다");
        }
        if change.paths.is_empty()
            || change.paths.iter().any(|path| !absolute_clean_path(path))
            || !absolute_clean_path(&change.exe)
            || change.exe.file_name().is_none()
        {
            errors.push("승인 작업의 경로와 실행 파일은 .. 없는 절대 경로여야 합니다");
        }
        if change.adjusted_rules.is_empty()
            || change
                .adjusted_rules
                .iter()
                .any(|rule| rule != BEHAVIOR_RULE && !multi_window::RULES.contains(&rule.as_str()))
        {
            errors.push("승인 작업은 지원하는 행위·다중 시간창 룰만 조정할 수 있습니다");
        }
    }
    let multi = &detection.multi_window;
    if multi.max_events == 0
        || multi.max_events > 100_000
        || multi.max_groups == 0
        || multi.max_groups > 16_384
        || !(64..=4096).contains(&multi.max_path_bytes)
    {
        errors.push("탐지 메모리 한도는 events 1~100000, groups 1~16384, path bytes 64~4096 범위여야 합니다");
    }
    if multi.enabled {
        let mut windows = HashSet::new();
        if multi.windows.is_empty()
            || multi.windows.len() > 8
            || multi.windows.iter().any(|window| {
                window.window_secs == 0
                    || window.window_secs > 86400
                    || !windows.insert(window.window_secs)
                    || window.min_changed_files == 0
                    || window.mass_change_threshold == 0
                    || !window.detect_score.is_finite()
                    || !(0.0..=100.0).contains(&window.detect_score)
            })
        {
            errors.push("다중 시간창은 중복 없는 1~86400초의 최대 8개 창과 양의 파일 수·유효 점수가 필요합니다");
        }
        if multi.protected_paths.len() > 128
            || multi.protected_paths.iter().any(|path| {
                !absolute_clean_path(path) || path.as_os_str().len() > multi.max_path_bytes
            })
        {
            errors.push("집계 보호 경로는 최대 128개의 길이 제한 내 절대 경로여야 합니다");
        }
    }
    let sampling = &detection.content_sampling;
    if sampling.enabled
        && (!(3..=entropy::MAX_SAMPLE_BYTES).contains(&sampling.total_bytes)
            || sampling.max_files == 0
            || sampling.max_files > 65_536
            || sampling.history_secs == 0
            || sampling.history_secs > 86400
            || !sampling.min_entropy_increase.is_finite()
            || !(0.0..=8.0).contains(&sampling.min_entropy_increase))
    {
        errors.push("내용 관찰은 총 3바이트~1MiB, 1~65536개 이력, 1~86400초와 0~8의 엔트로피 증가 기준이 필요합니다");
    }
    if detection
        .canary_paths
        .iter()
        .any(|path| !absolute_clean_path(path) || path.file_name().is_none())
    {
        errors.push("미끼 파일은 .. 없는 절대 파일 경로로 지정해야 합니다");
    }
    if detection.window_secs == 0 || detection.window_secs.checked_mul(1000).is_none() {
        errors.push("detection.window_secs는 밀리초로 변환 가능한 양수여야 합니다");
    }
    if detection.mass_change_threshold == 0 || detection.min_changed_files == 0 {
        errors.push("변경 파일 수 임계치는 1 이상이어야 합니다");
    }
    if !detection.entropy_threshold.is_finite()
        || !(0.0..=8.0).contains(&detection.entropy_threshold)
    {
        errors.push("detection.entropy_threshold는 0~8의 유한한 값이어야 합니다");
    }
    if !detection.detect_score.is_finite() || detection.detect_score <= 0.0 {
        errors.push("detection.detect_score는 유한한 양수여야 합니다");
    }
    if !response.block_score.is_finite() || response.block_score <= 0.0 {
        errors.push("response.block_score는 유한한 양수여야 합니다");
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }

    let mut warnings = Vec::new();
    let bytes = if detection.content_sampling.enabled {
        detection.content_sampling.total_bytes
    } else {
        detection.entropy_sample_bytes
    }
    .min(entropy::MAX_SAMPLE_BYTES);
    let entropy_possible =
        bytes > 0 && (bytes as f64).log2().min(8.0) >= detection.entropy_threshold;
    let base_max_score: f64 = match (sensor, !entropy_possible) {
        (SensorKind::Fanotify, true) => 40.0,
        (SensorKind::Notify, true) => 65.0,
        _ => 100.0,
    };
    let mut max_score = base_max_score;
    if !detection.canary_paths.is_empty() {
        max_score = max_score.max(95.0);
    }
    if detection.multi_window.enabled {
        for window in &detection.multi_window.windows {
            if window.detect_score > base_max_score {
                warnings.push(format!("{}초 시간창의 임계치 {}가 센서·표본 예산의 최대 점수 {base_max_score}보다 높습니다", window.window_secs, window.detect_score));
            }
        }
    }
    for (name, threshold) in [
        ("detection.detect_score", detection.detect_score),
        ("response.block_score", response.block_score),
    ] {
        if threshold > max_score {
            warnings.push(format!(
                "{sensor:?} 센서의 최대 위험 점수 {max_score:.0}에서 {name}={threshold}에 도달할 수 없습니다"
            ));
        }
    }
    if response.auto_block && sensor == SensorKind::Notify {
        warnings.push(
            "notify 센서는 PID를 제공하지 않아 자동 프로세스 차단을 실행할 수 없습니다".to_string(),
        );
    }
    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_common::{FileAction, FileProcessContext};

    fn approval_config() -> DetectionConfig {
        DetectionConfig {
            approved_changes: vec![ApprovedChange {
                id: "CHG-42".into(),
                valid_from_ms: 1000,
                valid_until_ms: 5000,
                paths: vec!["/data/deploy".into()],
                exe: "/usr/local/bin/deploy".into(),
                uid: 1001,
                adjusted_rules: vec![BEHAVIOR_RULE.into()],
            }],
            ..DetectionConfig::default()
        }
    }

    fn deploy_event(index: u64) -> FileEvent {
        FileEvent {
            timestamp_ms: 1000 + index,
            pid: 42,
            path: format!("/data/deploy/{index}"),
            action: FileAction::Modify,
            size: Some(100),
            entropy: Some(7.9),
            process: Some(FileProcessContext {
                uid: 1001,
                exe: "/usr/local/bin/deploy".into(),
                start_time_ticks: 100,
                boot_id: "boot-a".into(),
                ancestors: Vec::new(),
            }),
            content: None,
        }
    }

    #[test]
    fn approved_deployment_reduces_alerts_and_blocks_without_ignoring_attacks() {
        let mut original =
            DetectionEngine::with_sensor(DetectionConfig::default(), SensorKind::Fanotify);
        let mut approved = DetectionEngine::with_sensor(approval_config(), SensorKind::Fanotify);
        let (mut original_alerts, mut approved_alerts, mut original_blocks, mut approved_blocks) =
            (0, 0, 0, 0);
        for index in 0..30 {
            let e = deploy_event(index);
            let baseline = original.evaluate(&e);
            let adjusted = approved.evaluate(&e);
            original_alerts += usize::from(baseline.alert.is_some());
            approved_alerts += usize::from(adjusted.alert.is_some());
            original_blocks += usize::from(baseline.block_candidate(&ResponseConfig::default()));
            approved_blocks += usize::from(adjusted.block_candidate(&ResponseConfig::default()));
            assert_eq!(adjusted.approved_change_id.as_deref(), Some("CHG-42"));
        }
        assert_eq!((original_alerts, original_blocks), (3, 16));
        assert_eq!((approved_alerts, approved_blocks), (0, 0));
        for index in 30..60 {
            let mut attack = deploy_event(index);
            attack.process.as_mut().unwrap().exe = "/tmp/ransomware".into();
            let assessment = approved.evaluate(&attack);
            assert!(assessment.approved_change_id.is_none());
            if index >= 44 {
                assert!(assessment.block_candidate(&ResponseConfig::default()));
            }
        }
    }

    #[test]
    fn approval_requires_every_constraint_and_immutable_process_evidence() {
        for mismatch in [
            "time",
            "path",
            "account",
            "exe",
            "missing_context",
            "missing_identity",
            "parent_path",
        ] {
            let mut engine = DetectionEngine::with_sensor(approval_config(), SensorKind::Fanotify);
            for index in 0..30 {
                let mut e = deploy_event(index);
                match mismatch {
                    "time" => e.timestamp_ms = 5000 + index,
                    "path" => e.path = format!("/data/deploy-secret/{index}"),
                    "account" => e.process.as_mut().unwrap().uid = 1002,
                    "exe" => e.process.as_mut().unwrap().exe = "/tmp/deploy".into(),
                    "missing_context" => e.process = None,
                    "missing_identity" => e.process.as_mut().unwrap().boot_id.clear(),
                    "parent_path" => e.path = format!("/data/deploy/../private/{index}"),
                    _ => unreachable!(),
                }
                let assessment = engine.evaluate(&e);
                assert!(
                    assessment.approved_change_id.is_none(),
                    "불완전 매칭: {mismatch}"
                );
                if index >= 14 {
                    assert!(
                        assessment.block_candidate(&ResponseConfig::default()),
                        "미승인 탐지 유지: {mismatch}"
                    );
                }
            }
        }
    }

    #[test]
    fn approved_event_does_not_erase_prior_unapproved_evidence() {
        let mut engine = DetectionEngine::with_sensor(approval_config(), SensorKind::Fanotify);
        for index in 0..30 {
            let mut e = deploy_event(index);
            e.path = format!("/data/private/{index}");
            engine.evaluate(&e);
        }
        let assessment = engine.evaluate(&deploy_event(30));
        assert_eq!(assessment.approved_change_id.as_deref(), Some("CHG-42"));
        assert!(assessment.block_candidate(&ResponseConfig::default()));
    }

    #[test]
    fn pid_reuse_and_reboot_do_not_inherit_previous_process_risk() {
        let mut engine =
            DetectionEngine::with_sensor(DetectionConfig::default(), SensorKind::Fanotify);
        for index in 0..30 {
            engine.evaluate(&deploy_event(index));
        }
        let mut new_process = deploy_event(30);
        new_process.process.as_mut().unwrap().start_time_ticks = 200;
        assert!(!engine.evaluate(&new_process).eligible);
        for index in 31..60 {
            let mut e = deploy_event(index);
            e.process.as_mut().unwrap().start_time_ticks = 200;
            engine.evaluate(&e);
        }
        new_process.timestamp_ms += 100;
        new_process.process.as_mut().unwrap().boot_id = "boot-b".into();
        assert!(!engine.evaluate(&new_process).eligible);
    }

    #[test]
    fn canary_tamper_is_independent_of_minimum_files_approval_and_alert_cooldown() {
        let mut config = approval_config();
        config.canary_paths = vec!["/data/deploy/canary".into()];
        for action in [FileAction::Modify, FileAction::Delete, FileAction::Rename] {
            let mut engine = DetectionEngine::with_sensor(config.clone(), SensorKind::Fanotify);
            let mut e = deploy_event(0);
            e.path = "/data/deploy/canary".into();
            e.action = action;
            e.entropy = None;
            let first = engine.evaluate(&e);
            assert_eq!(first.score, 95.0);
            assert_eq!(first.alert.as_ref().unwrap().rule, CANARY_RULE);
            assert!(first.block_candidate(&ResponseConfig::default()));
            e.timestamp_ms += 1;
            let second = engine.evaluate(&e);
            assert!(second.alert.is_none());
            assert!(second.block_candidate(&ResponseConfig::default()));
        }
    }

    #[test]
    fn canary_creation_and_metadata_events_are_not_content_tamper() {
        let mut config = DetectionConfig::default();
        config.canary_paths = vec!["/data/deploy/canary".into()];
        for action in [FileAction::Create, FileAction::Chmod, FileAction::Chown] {
            let mut engine = DetectionEngine::with_sensor(config.clone(), SensorKind::Fanotify);
            let mut e = deploy_event(0);
            e.path = "/data/deploy/canary".into();
            e.action = action;
            let assessment = engine.evaluate(&e);
            assert!(assessment.alert.is_none());
            assert!(!assessment.block_candidate(&ResponseConfig::default()));
        }
    }

    #[test]
    fn invalid_approval_scopes_and_attempted_canary_override_are_rejected() {
        let mut config = approval_config();
        config.approved_changes[0].adjusted_rules = vec![CANARY_RULE.into()];
        assert!(
            validate_configuration(&config, &ResponseConfig::default(), SensorKind::Fanotify)
                .is_err()
        );
        config = approval_config();
        config.approved_changes[0].valid_until_ms = 1000;
        assert!(
            validate_configuration(&config, &ResponseConfig::default(), SensorKind::Fanotify)
                .is_err()
        );
        config = approval_config();
        config.approved_changes[0].paths = vec!["/data/deploy/../private".into()];
        assert!(
            validate_configuration(&config, &ResponseConfig::default(), SensorKind::Fanotify)
                .is_err()
        );
    }

    #[test]
    fn excluded_paths_use_directory_boundaries_and_suppress_response() {
        let config = DetectionConfig {
            min_changed_files: 1,
            mass_change_threshold: 1,
            exclude_paths: vec!["/data/backup".into()],
            ..DetectionConfig::default()
        };
        let mut engine = DetectionEngine::with_sensor(config, SensorKind::Fanotify);
        let mut e = FileEvent {
            timestamp_ms: 1,
            pid: 42,
            path: "/data/backup/file".into(),
            action: FileAction::Modify,
            entropy: Some(7.9),
            size: None,
            process: None,
            content: None,
        };
        let excluded = engine.evaluate(&e);
        assert!(!excluded.eligible);
        assert!(!excluded.block_candidate(&ResponseConfig::default()));
        e.path = "/data/backup-important/file".into();
        assert!(engine
            .evaluate(&e)
            .block_candidate(&ResponseConfig::default()));
    }

    #[test]
    fn validates_reachable_thresholds_for_sensor_and_entropy_settings() {
        let mut detection = DetectionConfig::default();
        let response = ResponseConfig::default();
        assert!(
            validate_configuration(&detection, &response, SensorKind::Fanotify)
                .unwrap()
                .is_empty()
        );
        detection.entropy_sample_bytes = 0;
        let warnings = validate_configuration(&detection, &response, SensorKind::Fanotify).unwrap();
        assert!(warnings
            .iter()
            .any(|w| w.contains("response.block_score=80")));
        detection.entropy_sample_bytes = 65536;
        detection.detect_score = 101.0;
        let warnings = validate_configuration(&detection, &response, SensorKind::Fanotify).unwrap();
        assert!(warnings
            .iter()
            .any(|w| w.contains("detection.detect_score=101")));
    }

    #[test]
    fn warns_when_sensor_cannot_identify_processes() {
        let response = ResponseConfig {
            auto_block: true,
            ..ResponseConfig::default()
        };
        let warnings =
            validate_configuration(&DetectionConfig::default(), &response, SensorKind::Notify)
                .unwrap();
        assert!(warnings.iter().any(|w| w.contains("PID")));
    }

    #[test]
    fn rejects_invalid_numeric_configuration() {
        let invalid = DetectionConfig {
            window_secs: u64::MAX,
            min_changed_files: 0,
            mass_change_threshold: 0,
            entropy_threshold: f64::NAN,
            detect_score: f64::NAN,
            ..DetectionConfig::default()
        };
        let response = ResponseConfig {
            block_score: f64::INFINITY,
            ..ResponseConfig::default()
        };
        let error = validate_configuration(&invalid, &response, SensorKind::Fanotify).unwrap_err();
        for expected in [
            "window_secs",
            "파일 수",
            "entropy_threshold",
            "detect_score",
            "block_score",
        ] {
            assert!(error.contains(expected), "누락된 검증: {expected}");
        }
    }

    #[test]
    fn validates_opt_in_window_and_sampling_bounds() {
        let response = ResponseConfig::default();
        let mut config = DetectionConfig::default();
        config.multi_window.enabled = true;
        config.content_sampling.enabled = true;
        assert!(validate_configuration(&config, &response, SensorKind::Fanotify).is_ok());
        config
            .multi_window
            .windows
            .push(config.multi_window.windows[0].clone());
        assert!(validate_configuration(&config, &response, SensorKind::Fanotify).is_err());
        config.multi_window.windows.pop();
        config.content_sampling.total_bytes = entropy::MAX_SAMPLE_BYTES + 1;
        assert!(validate_configuration(&config, &response, SensorKind::Fanotify).is_err());
        config.content_sampling.total_bytes = 128;
        let warnings = validate_configuration(&config, &response, SensorKind::Fanotify).unwrap();
        assert!(warnings
            .iter()
            .any(|message| message.contains("response.block_score")));
        assert!(warnings.iter().any(|message| message.contains("시간창")));
        config.multi_window.max_events = 0;
        assert!(validate_configuration(&config, &response, SensorKind::Fanotify).is_err());
    }
}
