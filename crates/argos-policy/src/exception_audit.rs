//! 저장한 한 이벤트 스냅샷으로 승인 예외의 매칭과 제거 영향을 재생한다.
//! 배포 당시 실제 예외 적용 기록이나 실제 차단 결과를 재구성하는 감사 원장이 아니다.

use crate::{simulation, Policy, SimulationError, SimulationOptions, SimulationReport};
use argos_common::{config::ApprovedChange, FileAction, ProcessIdentity};
use argos_detect::DetectionEngine;
use argos_storage::EventStore;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

const RULES: [&str; 5] = [
    "behavior.ransomware_pattern",
    "behavior.multi_window.instance",
    "behavior.multi_window.user_path",
    "behavior.multi_window.protected_path",
    "behavior.multi_window.ancestor",
];
const DAY_MS: u64 = 86_400_000;

#[derive(Debug, Clone)]
pub struct ExceptionAuditOptions {
    pub simulation: SimulationOptions,
    /// 만료/임박 판단 기준. 과거 이벤트의 매칭 시각과 구별한다.
    pub now_ms: u64,
    pub expiring_within_ms: u64,
    /// 예외별 경로·프로세스·이벤트 ID의 대표 표본 상한(1~100).
    pub sample_limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExceptionPathUsage {
    pub path: String,
    /// 반환된 이 경로에 매칭된 평가 구간 이벤트 수. 여러 규칙 매칭도 한 번만 센다.
    pub matched_events: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExceptionRuleUsage {
    pub rule: String,
    /// 저장 근거를 현재 규칙에 재생했을 때 예외가 매칭 가능한 이벤트 수.
    pub matched_events: usize,
    pub warmup_matched_events: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExceptionUsage {
    pub definition: ApprovedChange,
    /// not_started / active / expiring / expired. report.now_ms 기준.
    pub time_status: &'static str,
    pub broad_scope_reasons: Vec<String>,
    /// matched_in_loaded_range / no_matches_in_loaded_range.
    /// 후자는 관측 기간 밖·조회 누락·신원 미확인을 포함할 수 있다.
    pub usage_status: &'static str,
    pub replay_matched_events: usize,
    pub warmup_matched_events: usize,
    pub first_matched_ms: Option<u64>,
    pub last_matched_ms: Option<u64>,
    pub rule_matches: Vec<ExceptionRuleUsage>,
    pub paths: Vec<ExceptionPathUsage>,
    pub path_samples_truncated: bool,
    pub process_samples: Vec<ProcessIdentity>,
    pub process_samples_truncated: bool,
    pub evidence_event_ids: Vec<i64>,
    pub evidence_samples_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExceptionAuditReport {
    pub basis: &'static str,
    pub now_ms: u64,
    pub expiring_within_ms: u64,
    pub sample_limit: usize,
    /// 평가 구간의 PID 0 / 누락·불완전 시작 신원 이벤트 수.
    pub missing_identity_events: usize,
    /// 평가 구간의 실행 파일 맥락도 없는 이벤트 수.
    pub missing_executable_events: usize,
    pub matching_evidence_truncated: bool,
    pub exceptions: Vec<ExceptionUsage>,
    /// baseline=입력 정책, candidate=모든 approved_changes를 제거한 정책.
    pub comparison: SimulationReport,
    pub warnings: Vec<String>,
}

/// 읽기 전용 조회와 재생만 수행한다. 원본 파일·프로세스·정책 상태를 변경하지 않는다.
pub fn audit_exceptions(
    store: &EventStore,
    policy: &Policy,
    options: &ExceptionAuditOptions,
) -> Result<ExceptionAuditReport, SimulationError> {
    validate_audit_options(policy, options)?;
    let mut without_exceptions = policy.clone();
    without_exceptions.detection.approved_changes.clear();
    let range =
        simulation::load_simulation_range(store, policy, &without_exceptions, &options.simulation)?;
    let comparison =
        simulation::simulate_range(&range, policy, &without_exceptions, &options.simulation)?;
    let mut exceptions: Vec<_> = policy
        .detection
        .approved_changes
        .iter()
        .map(|change| ExceptionUsage {
            definition: change.clone(),
            time_status: time_status(change, options),
            broad_scope_reasons: broad_scope_reasons(change),
            usage_status: "no_matches_in_loaded_range",
            replay_matched_events: 0,
            warmup_matched_events: 0,
            first_matched_ms: None,
            last_matched_ms: None,
            rule_matches: change
                .adjusted_rules
                .iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|rule| ExceptionRuleUsage {
                    rule: rule.clone(),
                    matched_events: 0,
                    warmup_matched_events: 0,
                })
                .collect(),
            paths: Vec::new(),
            path_samples_truncated: false,
            process_samples: Vec::new(),
            process_samples_truncated: false,
            evidence_event_ids: Vec::new(),
            evidence_samples_truncated: false,
        })
        .collect();
    let indices: BTreeMap<_, _> = exceptions
        .iter()
        .enumerate()
        .map(|(index, usage)| (usage.definition.id.clone(), index))
        .collect();
    // 엔진의 실제 승인 매칭을 재사용한다. 규칙별로 다른 예외의 순서는 유지하므로
    // 겹치는 예외도 운영 엔진과 같은 첫 매칭 우선순위를 따른다.
    // 한 이벤트가 여러 규칙에서 매칭되어도 예외별 총수와 표본은 중복시키지 않는다.
    let mut matched_rows: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); exceptions.len()];
    let mut matching_evidence_truncated = false;
    for rule in RULES {
        if !policy
            .detection
            .approved_changes
            .iter()
            .any(|change| change.adjusted_rules.iter().any(|item| item == rule))
        {
            continue;
        }
        let mut config = policy.detection.clone();
        for change in &mut config.approved_changes {
            change.adjusted_rules.retain(|item| item == rule);
        }
        // 이 내부 진단 투영에서 빈 adjusted_rules는 원래 첫 매칭의 가림 효과를
        // 유지한다. 투영한 설정은 활성화하거나 유효한 후보 정책으로 출력하지 않는다.
        let mut engine = DetectionEngine::with_sensor(config, options.simulation.sensor);
        for (row_index, row) in range.events.iter().enumerate() {
            let mut event = row.event.clone();
            if policy.detection.entropy_sample_bytes == 0 {
                event.entropy = None;
            }
            let evaluation = engine.evaluate(&event);
            matching_evidence_truncated |= evaluation.evidence_truncated;
            // 다중 시간창은 이 행위들만 증거로 삽입한다. 메타데이터만 바뀐
            // 이벤트의 그룹 키 매칭을 내용/행위 기여로 표시하지 않는다.
            if rule != RULES[0]
                && !matches!(
                    event.action,
                    FileAction::Create
                        | FileAction::Modify
                        | FileAction::Delete
                        | FileAction::Rename
                )
            {
                continue;
            }
            let Some(id) = evaluation.approved_change_id else {
                continue;
            };
            let Some(&index) = indices.get(&id) else {
                continue;
            };
            let usage = &mut exceptions[index];
            let Some(rule_usage) = usage.rule_matches.iter_mut().find(|item| item.rule == rule)
            else {
                continue;
            };
            if event.timestamp_ms < options.simulation.from_ms {
                rule_usage.warmup_matched_events += 1;
            } else {
                rule_usage.matched_events += 1;
            }
            matched_rows[index].insert(row_index);
        }
    }
    for (usage, rows) in exceptions.iter_mut().zip(matched_rows) {
        for row_index in rows {
            let row = &range.events[row_index];
            let event = &row.event;
            if event.timestamp_ms < options.simulation.from_ms {
                usage.warmup_matched_events += 1;
                continue;
            }
            usage.replay_matched_events += 1;
            usage.first_matched_ms.get_or_insert(event.timestamp_ms);
            usage.last_matched_ms = Some(event.timestamp_ms);
            if usage.evidence_event_ids.len() < options.sample_limit {
                usage.evidence_event_ids.push(row.id);
            } else {
                usage.evidence_samples_truncated = true;
            }
            if let Some(path) = usage.paths.iter_mut().find(|path| path.path == event.path) {
                path.matched_events += 1;
            } else if usage.paths.len() < options.sample_limit {
                usage.paths.push(ExceptionPathUsage {
                    path: event.path.clone(),
                    matched_events: 1,
                });
            } else {
                usage.path_samples_truncated = true;
            }
            if let Some(context) = &event.process {
                let identity = ProcessIdentity {
                    pid: event.pid,
                    start_time_ticks: context.start_time_ticks,
                    boot_id: context.boot_id.clone(),
                };
                if !usage.process_samples.contains(&identity) {
                    if usage.process_samples.len() < options.sample_limit {
                        usage.process_samples.push(identity);
                    } else {
                        usage.process_samples_truncated = true;
                    }
                }
            }
        }
        if usage.replay_matched_events > 0 {
            usage.usage_status = "matched_in_loaded_range";
        }
    }
    let evaluated = || {
        range
            .events
            .iter()
            .filter(|row| row.event.timestamp_ms >= options.simulation.from_ms)
    };
    let missing_identity_events = evaluated()
        .filter(|row| {
            row.event.pid == 0
                || row.event.process.as_ref().is_none_or(|context| {
                    context.start_time_ticks == 0 || context.boot_id.trim().is_empty()
                })
        })
        .count();
    let missing_executable_events = evaluated()
        .filter(|row| {
            row.event
                .process
                .as_ref()
                .is_none_or(|context| context.exe.trim().is_empty())
        })
        .count();
    let mut warnings = vec![
        "현재 입력 정책을 저장 이벤트에 재생한 예외 매칭 가능 기여수입니다. 배포 당시 실제 예외 적용·차단 감사 기록이 아닙니다.".into(),
        "comparison.baseline은 입력 정책, candidate는 모든 승인 예외를 제거한 정책입니다. 알림·임계치·차단 차이는 재생 예상이며 실제 차단 수가 아닙니다.".into(),
        "겹치는 승인 작업은 정책 배열의 첫 매칭이 우선합니다. 규칙 매칭 수는 점수 감소량이나 차단 방지 건수와 같지 않으며, 미끼 파일 신호는 예외 제거와 독립적으로 유지됩니다.".into(),
        "no_matches_in_loaded_range는 조회된 평가 구간에서 매칭이 없다는 뜻입니다. 준비 구간만의 사용·조회 잘림·센서 누락·불완전 신원·다른 배포 정책 때문에 미사용을 확정할 수 없습니다.".into(),
        "broad_scope_reasons는 경로 깊이·기간·경로 수의 검토용 휴리스틱입니다. 업무 필요성·악성 여부를 판정하거나 예외를 자동 삭제하지 않습니다.".into(),
    ];
    if comparison.coverage.truncated || matching_evidence_truncated {
        warnings.push("조회 또는 재생 근거 상한 때문에 예외 매칭 집계가 불완전할 수 있습니다. 예외의 안전성이나 미사용 여부를 이 결과만으로 단정하지 마세요.".into());
    }
    if missing_identity_events > 0 || missing_executable_events > 0 {
        warnings.push(format!(
            "평가 구간에 시작 신원 미확인 {missing_identity_events}건, 실행 파일 미확인 {missing_executable_events}건이 있어 해당 이벤트의 예외 매칭을 확인할 수 없습니다."
        ));
    }
    Ok(ExceptionAuditReport {
        basis: "stored_event_replay_with_supplied_policy",
        now_ms: options.now_ms,
        expiring_within_ms: options.expiring_within_ms,
        sample_limit: options.sample_limit,
        missing_identity_events,
        missing_executable_events,
        matching_evidence_truncated,
        exceptions,
        comparison,
        warnings,
    })
}

fn time_status(change: &ApprovedChange, options: &ExceptionAuditOptions) -> &'static str {
    if options.now_ms >= change.valid_until_ms {
        "expired"
    } else if options.now_ms < change.valid_from_ms {
        "not_started"
    } else if change.valid_until_ms.saturating_sub(options.now_ms) <= options.expiring_within_ms {
        "expiring"
    } else {
        "active"
    }
}

fn broad_scope_reasons(change: &ApprovedChange) -> Vec<String> {
    let mut reasons = Vec::new();
    if change.paths.iter().any(|path| {
        path.components()
            .filter(|part| matches!(part, Component::Normal(_)))
            .count()
            <= 1
    }) {
        reasons.push("루트 또는 최상위 디렉터리를 포함하는 경로 범위".into());
    }
    if change.valid_until_ms.saturating_sub(change.valid_from_ms) > DAY_MS {
        reasons.push("24시간을 초과하는 승인 기간".into());
    }
    if change.paths.len() > 16 {
        reasons.push("16개를 초과하는 승인 경로".into());
    }
    reasons
}

fn validate_audit_options(
    policy: &Policy,
    options: &ExceptionAuditOptions,
) -> Result<(), SimulationError> {
    let bad = |reason: &str| SimulationError::InvalidOptions(reason.into());
    if !(1..=100_000).contains(&options.simulation.max_events) {
        return Err(bad(
            "예외 감사의 준비 구간 포함 이벤트 상한은 1~100,000건입니다",
        ));
    }
    if !(1..=100).contains(&options.sample_limit) {
        return Err(bad("예외 감사 대표 표본 상한은 1~100건입니다"));
    }
    if options.now_ms > i64::MAX as u64 || options.expiring_within_ms > 366 * DAY_MS {
        return Err(bad(
            "감사 기준 시각은 i64::MAX 이하, 임박 범위는 366일 이하여야 합니다",
        ));
    }
    let changes = &policy.detection.approved_changes;
    if changes.len() > 128
        || changes.iter().any(|change| {
            change.id.len() > 256
                || change.paths.len() > 128
                || change.adjusted_rules.len() > RULES.len()
                || change
                    .paths
                    .iter()
                    .any(|path| path.as_os_str().len() > 4096)
                || Path::new(&change.exe).as_os_str().len() > 4096
        })
    {
        return Err(bad("예외 감사는 예외 128개, ID 256바이트, 예외당 경로 128개·규칙 5개, 경로 4096바이트까지 지원합니다"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_common::{config::SensorKind, FileEvent, FileProcessContext};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture {
        directory: std::path::PathBuf,
        store: EventStore,
    }
    impl Fixture {
        fn new(events: &[FileEvent]) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "argos-exception-audit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&directory).unwrap();
            let database = directory.join("events.db");
            let writer = EventStore::open(&database).unwrap();
            for event in events {
                writer.insert_file_event(event).unwrap();
            }
            drop(writer);
            Self {
                directory,
                store: EventStore::open_readonly(&database).unwrap(),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn event(timestamp_ms: u64, name: &str) -> FileEvent {
        FileEvent {
            timestamp_ms,
            pid: 42,
            path: format!("/srv/data/{name}"),
            action: FileAction::Modify,
            size: Some(100),
            entropy: Some(8.0),
            content: None,
            process: Some(FileProcessContext {
                uid: 1000,
                exe: "/usr/bin/deploy".into(),
                start_time_ticks: 123,
                boot_id: "boot-a".into(),
                ancestors: vec![],
            }),
        }
    }

    fn policy() -> Policy {
        let mut policy = Policy::default();
        policy.detection.min_changed_files = 1;
        policy.detection.mass_change_threshold = 1;
        policy.response.auto_block = true;
        policy.detection.approved_changes = vec![ApprovedChange {
            id: "deploy".into(),
            valid_from_ms: 100,
            valid_until_ms: 200,
            paths: vec!["/srv/data".into()],
            exe: "/usr/bin/deploy".into(),
            uid: 1000,
            adjusted_rules: vec![RULES[0].into()],
        }];
        policy
    }

    fn options() -> ExceptionAuditOptions {
        ExceptionAuditOptions {
            simulation: SimulationOptions {
                from_ms: 0,
                to_ms: 1000,
                max_events: 100_000,
                sensor: SensorKind::Fanotify,
            },
            now_ms: 200,
            expiring_within_ms: DAY_MS,
            sample_limit: 20,
        }
    }

    #[test]
    fn replay_without_exception_changes_expected_results_but_readonly_store_is_unchanged() {
        let fixture = Fixture::new(&[event(100, "a"), event(101, "b")]);
        let report = audit_exceptions(&fixture.store, &policy(), &options()).unwrap();
        let usage = &report.exceptions[0];
        assert_eq!(usage.replay_matched_events, 2);
        assert_eq!(usage.rule_matches[0].matched_events, 2);
        assert_eq!(usage.time_status, "expired");
        assert_eq!(usage.usage_status, "matched_in_loaded_range");
        assert_eq!(report.basis, "stored_event_replay_with_supplied_policy");
        assert_eq!(report.comparison.baseline.alerts, 0);
        assert!(report.comparison.candidate.alerts > 0);
        assert_eq!(report.comparison.delta.new_block_targets.len(), 1);
        assert_eq!(
            report.comparison.delta.new_block_targets[0].start_time_ticks,
            Some(123)
        );
        assert!(report
            .comparison
            .candidate
            .policy
            .detection
            .approved_changes
            .is_empty());
        assert_eq!(fixture.store.event_count().unwrap(), 2);
        assert_eq!(fixture.store.detection_count().unwrap(), 0);
        assert_eq!(fixture.store.outbox_stats("fixture").unwrap().pending, 0);
    }

    #[test]
    fn exact_time_scope_path_account_executable_and_complete_identity_are_required() {
        let mut events = vec![
            event(99, "a"),
            event(100, "b"),
            event(199, "c"),
            event(200, "d"),
        ];
        let mut missing = event(110, "missing");
        missing.process = None;
        events.push(missing);
        let mut unknown_pid = event(111, "unknown");
        unknown_pid.pid = 0;
        events.push(unknown_pid);
        let mut reused_unknown = event(112, "start");
        reused_unknown.process.as_mut().unwrap().start_time_ticks = 0;
        events.push(reused_unknown);
        let mut boot_unknown = event(113, "boot");
        boot_unknown.process.as_mut().unwrap().boot_id = " ".into();
        events.push(boot_unknown);
        let mut outside = event(114, "outside");
        outside.path = "/srv/database/f".into();
        events.push(outside);
        let mut exe = event(115, "exe");
        exe.process.as_mut().unwrap().exe = "/usr/bin/other".into();
        events.push(exe);
        let mut uid = event(116, "uid");
        uid.process.as_mut().unwrap().uid = 0;
        events.push(uid);
        let fixture = Fixture::new(&events);
        let report = audit_exceptions(&fixture.store, &policy(), &options()).unwrap();
        assert_eq!(report.exceptions[0].replay_matched_events, 2);
        assert_eq!(report.exceptions[0].first_matched_ms, Some(100));
        assert_eq!(report.exceptions[0].last_matched_ms, Some(199));
        assert_eq!(report.missing_identity_events, 4);
        assert_eq!(report.missing_executable_events, 1);
    }

    #[test]
    fn overlapping_exceptions_keep_first_match_precedence_and_disabled_rules_are_unused() {
        let fixture = Fixture::new(&[event(100, "a")]);
        let mut policy = policy();
        let mut second = policy.detection.approved_changes[0].clone();
        second.id = "shadowed".into();
        policy.detection.approved_changes.push(second);
        let report = audit_exceptions(&fixture.store, &policy, &options()).unwrap();
        assert_eq!(report.exceptions[0].replay_matched_events, 1);
        assert_eq!(report.exceptions[1].replay_matched_events, 0);
        // 첫 매칭의 집계 룰이 비활성이어도 다음 예외로 넘어가지 않는다.
        policy.detection.approved_changes[0].adjusted_rules = vec![RULES[2].into()];
        let report = audit_exceptions(&fixture.store, &policy, &options()).unwrap();
        assert!(report
            .exceptions
            .iter()
            .all(|item| item.replay_matched_events == 0));
        assert_eq!(
            report.comparison.baseline.alerts,
            report.comparison.candidate.alerts
        );
    }

    #[test]
    fn named_rule_counts_do_not_invent_ancestry_and_canary_remains_alerting() {
        let fixture = Fixture::new(&[event(100, "canary")]);
        let mut policy = policy();
        policy.detection.multi_window.enabled = true;
        policy.detection.multi_window.protected_paths = vec!["/srv/data".into()];
        policy.detection.approved_changes[0].adjusted_rules =
            vec![RULES[0].into(), RULES[2].into(), RULES[4].into()];
        policy.detection.canary_paths = vec!["/srv/data/canary".into()];
        let report = audit_exceptions(&fixture.store, &policy, &options()).unwrap();
        let usage = &report.exceptions[0];
        assert_eq!(usage.replay_matched_events, 1);
        for rule in [RULES[0], RULES[2]] {
            assert_eq!(
                usage
                    .rule_matches
                    .iter()
                    .find(|item| item.rule == rule)
                    .unwrap()
                    .matched_events,
                1
            );
        }
        assert_eq!(
            usage
                .rule_matches
                .iter()
                .find(|item| item.rule == RULES[4])
                .unwrap()
                .matched_events,
            0
        );
        assert_eq!(report.comparison.baseline.alerts, 1);
        assert_eq!(report.comparison.delta.new_block_targets.len(), 0);
        assert_eq!(report.comparison.baseline.would_block_pids, vec![42]);
    }

    #[test]
    fn reused_pid_has_distinct_process_samples_and_expected_block_targets() {
        let first = event(100, "first");
        let mut second = event(101, "second");
        second.process.as_mut().unwrap().start_time_ticks = 456;
        let fixture = Fixture::new(&[first, second]);
        let report = audit_exceptions(&fixture.store, &policy(), &options()).unwrap();
        assert_eq!(report.exceptions[0].process_samples.len(), 2);
        assert_eq!(report.comparison.delta.new_block_targets.len(), 2);
        assert_eq!(
            report.exceptions[0].process_samples[0].pid,
            report.exceptions[0].process_samples[1].pid
        );
        assert_ne!(
            report.exceptions[0].process_samples[0].start_time_ticks,
            report.exceptions[0].process_samples[1].start_time_ticks
        );
    }

    #[test]
    fn warmup_and_truncated_range_do_not_claim_confirmed_unused_exception() {
        let fixture = Fixture::new(&[event(100, "a"), event(160, "b"), event(170, "c")]);
        let mut options = options();
        options.simulation.from_ms = 150;
        options.simulation.max_events = 1;
        let report = audit_exceptions(&fixture.store, &policy(), &options).unwrap();
        assert_eq!(report.exceptions[0].warmup_matched_events, 1);
        assert_eq!(report.exceptions[0].replay_matched_events, 0);
        assert_eq!(
            report.exceptions[0].usage_status,
            "no_matches_in_loaded_range"
        );
        assert!(report.comparison.coverage.truncated);
        assert_eq!(report.comparison.coverage.available_events, 3);
        assert_eq!(report.comparison.coverage.evaluated_events, 0);
        assert!(report.warnings.iter().any(|text| text.contains("미사용")));
    }

    #[test]
    fn representative_paths_and_ids_are_bounded_but_counts_remain_complete_for_loaded_rows() {
        let fixture = Fixture::new(&[event(100, "a"), event(101, "b"), event(102, "a")]);
        let mut options = options();
        options.sample_limit = 1;
        let report = audit_exceptions(&fixture.store, &policy(), &options).unwrap();
        let usage = &report.exceptions[0];
        assert_eq!(usage.replay_matched_events, 3);
        assert_eq!(usage.paths.len(), 1);
        assert_eq!(usage.paths[0].matched_events, 2);
        assert!(usage.path_samples_truncated);
        assert_eq!(usage.evidence_event_ids.len(), 1);
        assert!(usage.evidence_samples_truncated);
    }

    #[test]
    fn timing_broad_scope_and_query_limits_are_explicit() {
        let fixture = Fixture::new(&[]);
        let mut policy = policy();
        let mut options = options();
        options.now_ms = 99;
        assert_eq!(
            audit_exceptions(&fixture.store, &policy, &options)
                .unwrap()
                .exceptions[0]
                .time_status,
            "not_started"
        );
        options.now_ms = 100;
        options.expiring_within_ms = 99;
        assert_eq!(
            audit_exceptions(&fixture.store, &policy, &options)
                .unwrap()
                .exceptions[0]
                .time_status,
            "active"
        );
        options.now_ms = 101;
        assert_eq!(
            audit_exceptions(&fixture.store, &policy, &options)
                .unwrap()
                .exceptions[0]
                .time_status,
            "expiring"
        );
        policy.detection.approved_changes[0].paths = vec!["/".into()];
        policy.detection.approved_changes[0].valid_until_ms = 2 * DAY_MS;
        let report = audit_exceptions(&fixture.store, &policy, &options).unwrap();
        assert_eq!(report.exceptions[0].broad_scope_reasons.len(), 2);
        options.simulation.max_events = 100_001;
        assert!(audit_exceptions(&fixture.store, &policy, &options).is_err());
        options.simulation.max_events = 100;
        options.sample_limit = 0;
        assert!(audit_exceptions(&fixture.store, &policy, &options).is_err());
    }
}
