//! 저장된 이벤트를 같은 탐지 엔진으로 재생하는 읽기 전용 정책 비교.

use crate::Policy;
use argos_common::{config::SensorKind, FileAction, Pid};
use argos_detect::{validate_configuration, DetectionEngine, Evaluation};
use argos_storage::{EventStore, FileEventRange, FileEventRow, StorageError};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct SimulationOptions {
    /// 양 끝을 포함한 평가 구간(epoch ms).
    pub from_ms: u64,
    pub to_ms: u64,
    /// 준비 구간 이벤트를 포함한 메모리 조회 상한.
    pub max_events: usize,
    /// 수집 당시 센서. DB에는 센서 종류가 없으므로 호출자가 지정한다.
    pub sensor: SensorKind,
}

#[derive(Debug, thiserror::Error)]
pub enum SimulationError {
    #[error("이벤트 조회 실패: {0}")]
    Storage(#[from] StorageError),
    #[error("정책 사전 검증 설정 오류: {0}")]
    InvalidOptions(String),
    #[error("{policy} 정책 오류: {reason}")]
    InvalidPolicy {
        policy: &'static str,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationCoverage {
    pub from_ms: u64,
    pub to_ms: u64,
    pub warmup_from_ms: u64,
    /// 준비 구간과 평가 구간에 저장된 전체 건수.
    pub available_events: u64,
    pub loaded_events: usize,
    pub warmup_events: usize,
    pub evaluated_events: usize,
    pub truncated: bool,
    pub first_loaded_ms: Option<u64>,
    pub last_loaded_ms: Option<u64>,
    /// 엔트로피가 저장되지 않은 수정 이벤트 수(준비 구간 포함).
    pub missing_entropy_events: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationTarget {
    pub pid: Pid,
    pub start_time_ticks: Option<u64>,
    pub boot_id: Option<String>,
    pub first_event_id: i64,
    pub first_timestamp_ms: u64,
    pub peak_score: f64,
    /// 대표 근거 최대 20건. 파일 내용은 조회하지 않는다.
    pub evidence_event_ids: Vec<i64>,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SimulationTargetKey {
    pub pid: Pid,
    pub start_time_ticks: Option<u64>,
    pub boot_id: Option<String>,
}

impl SimulationTarget {
    fn key(&self) -> SimulationTargetKey {
        SimulationTargetKey {
            pid: self.pid,
            start_time_ticks: self.start_time_ticks,
            boot_id: self.boot_id.clone(),
        }
    }
    fn has_identity(&self) -> bool {
        self.start_time_ticks.is_some_and(|ticks| ticks > 0)
            && self
                .boot_id
                .as_ref()
                .is_some_and(|id| !id.trim().is_empty())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicySimulation {
    pub policy: Policy,
    /// 중복 억제를 적용한 알림 수.
    pub alerts: usize,
    /// 경로·사용자·계보 집계 알림. 자동 차단 후보에는 포함되지 않는다.
    pub aggregate_alerts: usize,
    pub aggregation_evidence_truncated: bool,
    /// 개별 프로세스 임계치 통과 또는 추가 시간창 알림이 발생한 이벤트 수.
    pub detection_events: usize,
    /// 준비 구간에서 이어진 상태를 고려한 차단 임계치 진입 횟수.
    pub block_threshold_crossings: usize,
    /// 점수는 넘었지만 PID를 알 수 없어 차단할 수 없는 이벤트 수.
    pub unattributed_threshold_events: usize,
    /// 관찰 모드에서도 나타나는 차단 임계치 통과 대상(PID 0 제외).
    pub threshold_targets: Vec<SimulationTarget>,
    /// auto_block=true일 때만 채워지는 예상 자동 차단 대상.
    pub would_block_pids: Vec<Pid>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationDelta {
    pub alerts: i64,
    pub detection_events: i64,
    pub new_threshold_pids: Vec<Pid>,
    pub removed_threshold_pids: Vec<Pid>,
    pub new_block_pids: Vec<Pid>,
    pub removed_block_pids: Vec<Pid>,
    pub new_block_targets: Vec<SimulationTargetKey>,
    pub removed_block_targets: Vec<SimulationTargetKey>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationReport {
    pub sensor: SensorKind,
    pub coverage: SimulationCoverage,
    pub baseline: PolicySimulation,
    pub candidate: PolicySimulation,
    pub delta: SimulationDelta,
    pub warnings: Vec<String>,
}

/// 과거 증거만 재생한다. DB·정책을 변경하거나 프로세스를 종료하지 않는다.
/// 후보 정책은 서명 전에도 비교할 수 있지만 실제 배포에는 서명이 필요하다.
pub fn simulate(
    store: &EventStore,
    baseline: &Policy,
    candidate: &Policy,
    options: &SimulationOptions,
) -> Result<SimulationReport, SimulationError> {
    let range = load_simulation_range(store, baseline, candidate, options)?;
    simulate_range(&range, baseline, candidate, options)
}

/// 정책 비교와 예외 사용 재생이 공유하는 제한된 단일 읽기 스냅샷.
pub(crate) fn load_simulation_range(
    store: &EventStore,
    baseline: &Policy,
    candidate: &Policy,
    options: &SimulationOptions,
) -> Result<FileEventRange, SimulationError> {
    if options.from_ms > options.to_ms || options.to_ms > i64::MAX as u64 {
        return Err(SimulationError::InvalidOptions(
            "시작 ≤ 종료 ≤ i64::MAX여야 합니다".into(),
        ));
    }
    if options.max_events == 0 || options.max_events > 1_000_000 {
        return Err(SimulationError::InvalidOptions(
            "조회 제한은 1~1,000,000건이어야 합니다".into(),
        ));
    }
    // 대량 과거 자료를 읽기 전에 잘못된 정책을 거부한다.
    for (name, policy) in [("기존", baseline), ("후보", candidate)] {
        validate_configuration(&policy.detection, &policy.response, options.sensor).map_err(
            |reason| SimulationError::InvalidPolicy {
                policy: name,
                reason,
            },
        )?;
    }
    let warmup_ms = policy_window_secs(baseline)
        .max(policy_window_secs(candidate))
        .saturating_mul(1000);
    Ok(store.file_events_in_range(
        options.from_ms.saturating_sub(warmup_ms),
        options.to_ms,
        options.max_events,
    )?)
}

pub(crate) fn simulate_range(
    range: &FileEventRange,
    baseline: &Policy,
    candidate: &Policy,
    options: &SimulationOptions,
) -> Result<SimulationReport, SimulationError> {
    let mut warnings = vec![
        "저장된 이벤트의 비교 결과입니다. 실제 차단 이후의 이벤트 변화·차단 성공 여부는 예측하지 않습니다.".into(),
        "DB에 센서 종류가 없어 지정한 센서를 사용합니다. 프로세스 시작 시각·부팅 ID가 없는 이벤트는 PID 재사용을 구별하거나 자동 차단할 수 없습니다.".into(),
        "준비 구간으로 윈도우를 채우지만 더 오래된 알림 쿨다운·수집 누락은 복원할 수 없습니다. 알림 수는 재생 기준입니다.".into(),
    ];
    for (name, policy) in [("기존", baseline), ("후보", candidate)] {
        let validation =
            validate_configuration(&policy.detection, &policy.response, options.sensor).map_err(
                |reason| SimulationError::InvalidPolicy {
                    policy: name,
                    reason,
                },
            )?;
        warnings.extend(validation.into_iter().map(|w| format!("{name}: {w}")));
    }
    if baseline.detection.entropy_sample_bytes != candidate.detection.entropy_sample_bytes {
        warnings.push("엔트로피 샘플 크기 변경은 재현할 수 없습니다. 두 정책 모두 수집 당시 저장된 엔트로피만 사용합니다.".into());
    }
    let warmup_ms = policy_window_secs(baseline)
        .max(policy_window_secs(candidate))
        .saturating_mul(1000);
    let warmup_from_ms = options.from_ms.saturating_sub(warmup_ms);
    if baseline.detection.content_sampling.enabled || candidate.detection.content_sampling.enabled {
        if range.events.iter().any(|row| row.event.content.is_none()) {
            warnings.push("일부 과거 이벤트에 다중 위치 표본이 없습니다. 현재 파일로 보완하지 않으며 부분 암호화 비교 근거가 불완전합니다.".into());
        }
        if baseline.detection.content_sampling.enabled
            != candidate.detection.content_sampling.enabled
            || baseline.detection.content_sampling.total_bytes
                != candidate.detection.content_sampling.total_bytes
        {
            warnings.push("내용 표본 수집 설정이 달라도 저장된 당시 표본만 사용합니다. 새 위치·읽기 예산으로 다시 수집한 결과는 재현할 수 없습니다.".into());
        }
    }

    if (!baseline.detection.approved_changes.is_empty()
        || !candidate.detection.approved_changes.is_empty())
        && range.events.iter().any(|r| r.event.process.is_none())
    {
        warnings.push("프로세스 맥락이 없는 이벤트는 승인 작업과 일치하는지 확인할 수 없어 예외를 적용하지 않습니다.".into());
    }
    let warmup_events = range
        .events
        .iter()
        .filter(|r| r.event.timestamp_ms < options.from_ms)
        .count();
    let missing_entropy_events = range
        .events
        .iter()
        .filter(|r| r.event.action == FileAction::Modify && r.event.entropy.is_none())
        .count();
    if range.truncated {
        warnings.push(format!("조회 상한으로 {}건 중 {}건만 재생했습니다. 구간 전체 결과가 아니므로 확대 적용 판단에 사용하지 마세요.", range.total_events, range.events.len()));
    }
    if missing_entropy_events > 0 {
        warnings.push(format!("수정 이벤트 {missing_entropy_events}건의 엔트로피가 없습니다. 현재 파일에서 보충하지 않으며 위험 점수가 낮게 산출될 수 있습니다."));
    }
    let evaluated_events = range.events.len() - warmup_events;
    if evaluated_events == 0 {
        warnings.push(
            "평가 구간에서 재생한 이벤트가 없습니다. 안전성을 검증한 결과가 아닙니다.".into(),
        );
    }
    let coverage = SimulationCoverage {
        from_ms: options.from_ms,
        to_ms: options.to_ms,
        warmup_from_ms,
        available_events: range.total_events,
        loaded_events: range.events.len(),
        warmup_events,
        evaluated_events,
        truncated: range.truncated,
        first_loaded_ms: range.events.first().map(|r| r.event.timestamp_ms),
        last_loaded_ms: range.events.last().map(|r| r.event.timestamp_ms),
        missing_entropy_events,
    };
    let baseline_result = replay(&range.events, baseline, options);
    let candidate_result = replay(&range.events, candidate, options);
    if baseline_result.aggregation_evidence_truncated
        || candidate_result.aggregation_evidence_truncated
    {
        warnings.push("다중 시간창 집계의 메모리 한도로 일부 증거가 제외되었습니다. 집계 결과가 불완전할 수 있습니다.".into());
    }
    let baseline_threshold: BTreeSet<_> = baseline_result
        .threshold_targets
        .iter()
        .map(|t| t.pid)
        .collect();
    let candidate_threshold: BTreeSet<_> = candidate_result
        .threshold_targets
        .iter()
        .map(|t| t.pid)
        .collect();
    let baseline_blocks: BTreeSet<_> = baseline_result.would_block_pids.iter().copied().collect();
    let candidate_blocks: BTreeSet<_> = candidate_result.would_block_pids.iter().copied().collect();
    let baseline_keys: BTreeSet<_> = baseline_result
        .threshold_targets
        .iter()
        .filter(|t| baseline.response.auto_block && t.has_identity())
        .map(SimulationTarget::key)
        .collect();
    let candidate_keys: BTreeSet<_> = candidate_result
        .threshold_targets
        .iter()
        .filter(|t| candidate.response.auto_block && t.has_identity())
        .map(SimulationTarget::key)
        .collect();
    let delta = SimulationDelta {
        alerts: candidate_result.alerts as i64 - baseline_result.alerts as i64,
        detection_events: candidate_result.detection_events as i64
            - baseline_result.detection_events as i64,
        new_threshold_pids: candidate_threshold
            .difference(&baseline_threshold)
            .copied()
            .collect(),
        removed_threshold_pids: baseline_threshold
            .difference(&candidate_threshold)
            .copied()
            .collect(),
        new_block_pids: candidate_blocks
            .difference(&baseline_blocks)
            .copied()
            .collect(),
        removed_block_pids: baseline_blocks
            .difference(&candidate_blocks)
            .copied()
            .collect(),
        new_block_targets: candidate_keys.difference(&baseline_keys).cloned().collect(),
        removed_block_targets: baseline_keys.difference(&candidate_keys).cloned().collect(),
    };
    Ok(SimulationReport {
        sensor: options.sensor,
        coverage,
        baseline: baseline_result,
        candidate: candidate_result,
        delta,
        warnings,
    })
}

fn policy_window_secs(policy: &Policy) -> u64 {
    let aggregate = &policy.detection.multi_window;
    let maximum = if aggregate.enabled {
        aggregate
            .windows
            .iter()
            .map(|window| window.window_secs)
            .max()
            .unwrap_or(0)
    } else {
        0
    };
    policy.detection.window_secs.max(maximum)
}

fn replay(rows: &[FileEventRow], policy: &Policy, options: &SimulationOptions) -> PolicySimulation {
    let mut engine = DetectionEngine::with_sensor(policy.detection.clone(), options.sensor);
    let mut result = PolicySimulation {
        policy: policy.clone(),
        alerts: 0,
        aggregate_alerts: 0,
        aggregation_evidence_truncated: false,
        detection_events: 0,
        block_threshold_crossings: 0,
        unattributed_threshold_events: 0,
        threshold_targets: Vec::new(),
        would_block_pids: Vec::new(),
    };
    let mut above_threshold = BTreeMap::<SimulationTargetKey, (bool, u64)>::new();
    let mut targets = BTreeMap::<SimulationTargetKey, SimulationTarget>::new();
    for row in rows {
        let mut event = row.event.clone();
        if policy.detection.entropy_sample_bytes == 0 {
            event.entropy = None;
        }
        let evaluation: Evaluation = engine.evaluate(&event);
        result.aggregation_evidence_truncated |= evaluation.evidence_truncated;
        let key = SimulationTargetKey {
            pid: row.event.pid,
            start_time_ticks: row.event.process.as_ref().map(|p| p.start_time_ticks),
            boot_id: row.event.process.as_ref().map(|p| p.boot_id.clone()),
        };
        let above = evaluation.eligible && evaluation.score >= policy.response.block_score;
        let was_above = above_threshold
            .insert(key.clone(), (above, row.event.timestamp_ms))
            .is_some_and(|(was_above, previous_ms)| {
                was_above
                    && row.event.timestamp_ms.saturating_sub(previous_ms)
                        <= policy_window_secs(policy).saturating_mul(1000)
            });
        if row.event.timestamp_ms < options.from_ms {
            continue;
        }
        result.alerts +=
            usize::from(evaluation.alert.is_some()) + evaluation.additional_alerts.len();
        result.aggregate_alerts += evaluation
            .additional_alerts
            .iter()
            .filter(|alert| alert.pid == 0)
            .count();
        if (evaluation.eligible && evaluation.score >= policy.detection.detect_score)
            || !evaluation.additional_alerts.is_empty()
        {
            result.detection_events += 1;
        }
        if above && !was_above {
            result.block_threshold_crossings += 1;
        }
        if above && row.event.pid == 0 {
            result.unattributed_threshold_events += 1;
        }
        if !evaluation.block_candidate(&policy.response) {
            continue;
        }
        let target = targets
            .entry(key.clone())
            .or_insert_with(|| SimulationTarget {
                pid: row.event.pid,
                start_time_ticks: key.start_time_ticks,
                boot_id: key.boot_id,
                first_event_id: row.id,
                first_timestamp_ms: row.event.timestamp_ms,
                peak_score: evaluation.score,
                evidence_event_ids: Vec::new(),
                paths: Vec::new(),
            });
        target.peak_score = target.peak_score.max(evaluation.score);
        if target.evidence_event_ids.len() < 20 {
            target.evidence_event_ids.push(row.id);
        }
        if target.paths.len() < 20 && !target.paths.contains(&row.event.path) {
            target.paths.push(row.event.path.clone());
        }
    }
    result.threshold_targets = targets.into_values().collect();
    if policy.response.auto_block {
        result.would_block_pids = result
            .threshold_targets
            .iter()
            .filter(|t| t.has_identity())
            .map(|t| t.pid)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_common::FileEvent;

    fn with_store(label: &str, run: impl FnOnce(&EventStore)) {
        let dir =
            std::env::temp_dir().join(format!("argos-simulation-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = dir.join("events.db");
        let store = EventStore::open(&db).unwrap();
        run(&store);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn event(ts: u64, pid: Pid, n: usize, entropy: Option<f64>) -> FileEvent {
        FileEvent {
            timestamp_ms: ts,
            pid,
            path: format!("/nonexistent/argos-replay/file{n}"),
            action: FileAction::Modify,
            size: Some(10),
            entropy,
            content: None,
            process: Some(argos_common::FileProcessContext {
                uid: 1000,
                exe: "/bin/deploy".into(),
                start_time_ticks: 100,
                boot_id: "boot-a".into(),
                ancestors: vec![],
            }),
        }
    }

    fn options() -> SimulationOptions {
        SimulationOptions {
            from_ms: 0,
            to_ms: 100_000,
            max_events: 1000,
            sensor: SensorKind::Fanotify,
        }
    }

    #[test]
    fn aggregate_replay_warms_long_windows_without_inventing_block_targets() {
        with_store("aggregate-warmup", |store| {
            for (n, ts) in [100_000, 200_000, 300_000, 450_000].into_iter().enumerate() {
                store
                    .insert_file_event(&event(ts, 100 + n as u32, n, Some(7.9)))
                    .unwrap();
            }
            let baseline = Policy::default();
            let mut candidate = baseline.clone();
            candidate.response.auto_block = true;
            candidate.detection.multi_window.enabled = true;
            candidate.detection.multi_window.protected_paths =
                vec!["/nonexistent/argos-replay".into()];
            candidate.detection.multi_window.windows =
                vec![argos_common::config::DetectionWindow {
                    window_secs: 600,
                    min_changed_files: 4,
                    mass_change_threshold: 4,
                    detect_score: 90.0,
                }];
            let report = simulate(
                store,
                &baseline,
                &candidate,
                &SimulationOptions {
                    from_ms: 400_000,
                    to_ms: 500_000,
                    ..options()
                },
            )
            .unwrap();
            assert_eq!(report.coverage.warmup_from_ms, 0);
            assert_eq!(report.coverage.warmup_events, 3);
            assert_eq!(report.baseline.alerts, 0);
            assert!(report.candidate.aggregate_alerts > 0);
            assert!(report.candidate.would_block_pids.is_empty());
            assert!(report.candidate.threshold_targets.is_empty());
        });
    }

    #[test]
    fn compares_observation_with_enforcement_without_mutation_and_is_deterministic() {
        with_store("compare", |store| {
            for n in 0..30 {
                store
                    .insert_file_event(&event(1000 + n as u64, 42, n, Some(7.9)))
                    .unwrap();
            }
            let mut baseline = Policy::default();
            baseline.detection.detect_score = 72.0;
            let mut candidate = baseline.clone();
            candidate.version = 2;
            candidate.response.auto_block = true;
            let before = store.event_count().unwrap();
            let report = simulate(store, &baseline, &candidate, &options()).unwrap();
            assert!(report.baseline.would_block_pids.is_empty());
            assert_eq!(report.candidate.would_block_pids, [42]);
            assert_eq!(report.delta.new_block_pids, [42]);
            assert_eq!(report.delta.alerts, 0);
            assert!(report.candidate.detection_events > report.candidate.alerts);
            // 9개 파일에서 72점 알림 후 15개 파일에서 80점 차단: +15 미만이어도 반영.
            assert_eq!(report.candidate.threshold_targets[0].first_event_id, 15);
            assert_eq!(
                report.candidate.threshold_targets[0].first_timestamp_ms,
                1014
            );
            assert_eq!(report.candidate.threshold_targets[0].peak_score, 100.0);
            assert_eq!(report.candidate.block_threshold_crossings, 1);
            assert_eq!(store.event_count().unwrap(), before);
            assert_eq!(store.detection_count().unwrap(), 0);
            assert_eq!(
                serde_json::to_value(&report).unwrap(),
                serde_json::to_value(simulate(store, &baseline, &candidate, &options()).unwrap())
                    .unwrap()
            );
        });
    }

    #[test]
    fn warms_each_policy_window_before_counting_requested_events() {
        with_store("warmup", |store| {
            for n in 0..4 {
                store
                    .insert_file_event(&event(8500 + n as u64, 42, n, Some(7.9)))
                    .unwrap();
            }
            store
                .insert_file_event(&event(10000, 42, 4, Some(7.9)))
                .unwrap();
            let mut baseline = Policy::default();
            baseline.detection.mass_change_threshold = 5;
            baseline.response.auto_block = true;
            let mut candidate = baseline.clone();
            candidate.detection.window_secs = 1;
            let opts = SimulationOptions {
                from_ms: 10000,
                to_ms: 10000,
                ..options()
            };
            let report = simulate(store, &baseline, &candidate, &opts).unwrap();
            assert_eq!(report.coverage.warmup_events, 4);
            assert_eq!(report.coverage.evaluated_events, 1);
            assert_eq!(report.baseline.would_block_pids, [42]);
            assert!(report.candidate.would_block_pids.is_empty());
            assert_eq!(report.delta.removed_block_pids, [42]);
            assert_eq!(report.delta.removed_threshold_pids, [42]);
        });
    }

    #[test]
    fn partial_and_missing_entropy_results_are_explicit() {
        with_store("coverage", |store| {
            for n in 0..30 {
                store
                    .insert_file_event(&event(1000 + n as u64, 42, n, None))
                    .unwrap();
            }
            let mut policy = Policy::default();
            policy.response.auto_block = true;
            let opts = SimulationOptions {
                max_events: 7,
                ..options()
            };
            let report = simulate(store, &policy, &policy, &opts).unwrap();
            assert!(report.coverage.truncated);
            assert_eq!(report.coverage.available_events, 30);
            assert_eq!(report.coverage.evaluated_events, 7);
            assert_eq!(report.coverage.missing_entropy_events, 7);
            assert_eq!(report.coverage.last_loaded_ms, Some(1006));
            assert!(report.candidate.would_block_pids.is_empty());
            assert!(report.warnings.iter().any(|w| w.contains("구간 전체")));
            assert!(report
                .warnings
                .iter()
                .any(|w| w.contains("엔트로피가 없습니다")));
            let full = simulate(store, &policy, &policy, &options()).unwrap();
            assert!(!full.coverage.truncated);
            assert!(full.candidate.would_block_pids.is_empty());
        });
    }

    #[test]
    fn unknown_pid_is_never_reported_as_a_block_target() {
        with_store("pid-zero", |store| {
            for n in 0..30 {
                store
                    .insert_file_event(&event(1000 + n as u64, 0, n, Some(7.9)))
                    .unwrap();
            }
            let mut policy = Policy::default();
            policy.response.auto_block = true;
            policy.response.block_score = 70.0;
            let opts = SimulationOptions {
                sensor: SensorKind::Notify,
                ..options()
            };
            let report = simulate(store, &policy, &policy, &opts).unwrap();
            assert!(report.candidate.would_block_pids.is_empty());
            assert!(report.candidate.threshold_targets.is_empty());
            assert!(report.candidate.unattributed_threshold_events > 0);
        });
    }

    #[test]
    fn disabled_entropy_and_exclusions_change_expected_targets() {
        with_store("exclude", |store| {
            for n in 0..30 {
                store
                    .insert_file_event(&event(1000 + n as u64, 42, n, Some(7.9)))
                    .unwrap();
            }
            let mut baseline = Policy::default();
            baseline.response.auto_block = true;
            let mut candidate = baseline.clone();
            candidate.detection.entropy_sample_bytes = 0;
            let report = simulate(store, &baseline, &candidate, &options()).unwrap();
            assert_eq!(report.delta.removed_block_pids, [42]);
            assert!(report.warnings.iter().any(|w| w.contains("샘플 크기 변경")));
            candidate.detection.entropy_sample_bytes = baseline.detection.entropy_sample_bytes;
            candidate.detection.exclude_paths = vec!["/nonexistent/argos-replay".into()];
            let report = simulate(store, &baseline, &candidate, &options()).unwrap();
            assert_eq!(report.delta.removed_threshold_pids, [42]);
            assert_eq!(report.candidate.detection_events, 0);
        });
    }

    #[test]
    fn invalid_policies_and_options_are_rejected_before_replay() {
        with_store("invalid", |store| {
            let baseline = Policy::default();
            let mut candidate = baseline.clone();
            candidate.detection.window_secs = 0;
            assert!(matches!(
                simulate(store, &baseline, &candidate, &options()),
                Err(SimulationError::InvalidPolicy {
                    policy: "후보", ..
                })
            ));
            let opts = SimulationOptions {
                max_events: 0,
                ..options()
            };
            assert!(matches!(
                simulate(store, &baseline, &baseline, &opts),
                Err(SimulationError::InvalidOptions(_))
            ));
            let report = simulate(store, &baseline, &baseline, &options()).unwrap();
            assert_eq!(report.coverage.evaluated_events, 0);
            assert!(report
                .warnings
                .iter()
                .any(|w| w.contains("안전성을 검증한 결과가 아닙니다")));
        });
    }

    #[test]
    fn stored_approval_context_reduces_alerts_but_missing_identity_prevents_enforcement() {
        with_store("approval-context", |store| {
            for n in 0..30 {
                store
                    .insert_file_event(&event(1000 + n as u64, 42, n, Some(7.9)))
                    .unwrap();
            }
            let mut baseline = Policy::default();
            baseline.response.auto_block = true;
            let mut candidate = baseline.clone();
            candidate.detection.approved_changes = vec![argos_common::config::ApprovedChange {
                id: "deploy-1".into(),
                valid_from_ms: 1000,
                valid_until_ms: 2000,
                paths: vec!["/nonexistent/argos-replay".into()],
                exe: "/bin/deploy".into(),
                uid: 1000,
                adjusted_rules: vec!["behavior.ransomware_pattern".into()],
            }];
            let report = simulate(store, &baseline, &candidate, &options()).unwrap();
            assert_eq!(report.baseline.would_block_pids, [42]);
            assert!(report.candidate.would_block_pids.is_empty());
            assert!(report.delta.alerts < 0);
            assert_eq!(
                report.delta.removed_block_targets[0].start_time_ticks,
                Some(100)
            );
            for n in 0..30 {
                let mut unknown = event(5000 + n as u64, 99, n, Some(7.9));
                unknown.process = None;
                store.insert_file_event(&unknown).unwrap();
            }
            let opts = SimulationOptions {
                from_ms: 5000,
                ..options()
            };
            let report = simulate(store, &baseline, &candidate, &opts).unwrap();
            assert!(!report.candidate.threshold_targets.is_empty());
            assert!(report.candidate.would_block_pids.is_empty());
            assert!(report.warnings.iter().any(|w| w.contains("프로세스 맥락")));
        });
    }
}
