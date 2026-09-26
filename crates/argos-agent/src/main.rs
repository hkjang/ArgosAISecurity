//! Argos Agent: 센서 → 탐지 → 저장/백업/대응/보고 파이프라인 데몬.
//!
//! 운영 환경에서는 systemd 서비스로 실행한다 (packaging/argos-agent.service).

mod backup_worker;
mod coverage_worker;
mod reporter;
mod semantic;

use argos_common::{AgentConfig, FileAction, FileEvent};
use argos_detect::DetectionEngine;
use argos_response::{make_responder, Responder, ResponseAction};
use argos_storage::EventStore;
use backup_worker::BackupWorker;
use clap::Parser;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(name = "argos-agent", about = "Argos AI Security 에이전트 데몬")]
struct Args {
    /// 설정 파일 경로 (없으면 기본값 사용)
    #[arg(short, long, default_value = "argos.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let mut config = AgentConfig::load(&args.config)?;

    // 서명된 정책 활성화는 검증/버전/설정/감사 기록을 하나의 트랜잭션으로 저장한다.
    // 구성된 정책이 거부되면 시작을 중단한다. 로컬 기본값으로 약화하지 않는다.
    let mut policy_runtime = None;
    if config.policy.is_enabled() {
        let activated =
            argos_policy::activate_file(&config.policy, &config.db_path, config.sensor)?;
        tracing::info!(
            version = activated.policy.version,
            policy_id = %activated.policy.policy_id,
            sha256 = %activated.sha256,
            outcome = %activated.outcome,
            "서명된 정책 검증·영속 적용 완료"
        );
        policy_runtime = Some(
            serde_json::json!({"version":activated.policy.version,"sha256":activated.sha256,"not_before_ms":activated.policy.not_before_ms,"expires_at_ms":activated.policy.expires_at_ms,"invalid":false}),
        );
        config.detection = activated.policy.detection;
        config.response = activated.policy.response;
    }

    for warning in
        argos_detect::validate_configuration(&config.detection, &config.response, config.sensor)?
    {
        tracing::warn!(warning, "탐지/대응 설정 경고");
    }
    tracing::info!(sensor = ?config.sensor, auto_block = config.response.auto_block, "에이전트 시작");

    let configured_watch_paths = config.watch_paths.clone();
    // 감시 경로가 없으면 만들어 둔다 (개발 환경 편의).
    for p in &mut config.watch_paths {
        if !p.exists() {
            std::fs::create_dir_all(&*p)?;
        }
        *p = p.canonicalize()?;
    }

    let store = EventStore::open(&config.db_path)?;
    let mut engine = DetectionEngine::with_sensor(config.detection.clone(), config.sensor);
    let responder = make_responder(config.response.auto_block);
    let mut semantic = semantic::SemanticMonitor::new(&config.semantic, &config.watch_paths)?;
    let sampling = &config.detection.content_sampling;
    let mut content_sampler = sampling.enabled.then(|| {
        argos_detect::ContentSampler::new(
            sampling.total_bytes,
            sampling.max_files,
            sampling.history_secs,
        )
    });

    // 백업은 별도 작업자에서 처리한다. 센서 경로 안에 저장소가 있으면 재귀 이벤트를 유발한다.
    let backup = if config.backup.enabled {
        std::fs::create_dir_all(&config.backup.dir)?;
        let backup_dir = config.backup.dir.canonicalize()?;
        for path in &config.watch_paths {
            if backup_dir.starts_with(path.canonicalize()?) {
                return Err("백업 디렉터리는 감시 경로 밖에 두어야 합니다".into());
            }
        }
        Some(BackupWorker::spawn(
            &config.backup,
            &config.watch_paths,
            &config.db_path,
        )?)
    } else {
        None
    };

    // 중앙 서버 보고 채널 (옵션). 전송은 별도 스레드에서 blocking HTTP로 처리.
    let reporter = reporter::spawn(&config.central, &config.db_path)?;

    // 센서 → 파이프라인 채널. 요건서 12장 처리량 대비 버퍼는 추후 튜닝.
    let (tx, mut rx) = mpsc::channel::<FileEvent>(8192);
    let sensor = argos_sensor::spawn_sensor(config.sensor, &config.watch_paths, tx)?;
    let coverage = if config.coverage.enabled {
        Some(coverage_worker::CoverageWorker::spawn_registered(
            &config.coverage,
            config.sensor,
            &configured_watch_paths,
            &config.watch_paths,
        )?)
    } else {
        None
    };

    // 프로세스 감시 (Linux 전용, /proc 폴링).
    let (proc_tx, mut proc_rx) = mpsc::channel::<argos_common::ProcessEvent>(1024);
    #[cfg(target_os = "linux")]
    let process_monitor = if config.process_monitor.enabled {
        Some(argos_sensor::spawn_proc_monitor(
            config.process_monitor.interval_ms,
            proc_tx.clone(),
        )?)
    } else {
        None
    };
    // 송신단을 살려 두어 비활성/비 Linux에서도 recv가 종료되지 않게 한다.
    let _proc_tx_keepalive = proc_tx;

    tracing::info!("이벤트 파이프라인 가동 (Ctrl+C로 종료)");

    let mut analysis_incomplete = false;
    let mut health_tick = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(mut event) = maybe_event else {
                    if let Some(reporter) = &reporter { reporter.set_sensor_healthy(false); }
                    tracing::error!("파일 센서 채널 중단 — 보호 상태 저하");
                    return Err("파일 센서가 중단되었습니다".into());
                };
                guard_policy_time(policy_runtime.as_mut(), &mut config.response, argos_common::now_ms());
                analysis_incomplete = process_event(
                    &mut event,
                    &config,
                    &store,
                    &mut engine,
                    responder.as_ref(),
                    backup.as_ref(),
                    reporter.as_ref(),
                    content_sampler.as_mut(),
                    Some(&mut semantic),
                    policy_runtime.as_mut(),
                );
            }
            maybe_pe = proc_rx.recv() => {
                if let Some(pe) = maybe_pe {
                    if let Err(e) = store.insert_process_event(&pe) {
                        tracing::error!(error = %e, "프로세스 이벤트 저장 실패");
                    }
                }
            }
            _ = health_tick.tick() => {
                guard_policy_time(policy_runtime.as_mut(), &mut config.response, argos_common::now_ms());
                let sensor_health = sensor.health();
                #[cfg(target_os = "linux")]
                let process_health = process_monitor.as_ref().map(|m| m.health());
                #[cfg(not(target_os = "linux"))]
                let process_health: Option<argos_sensor::SensorHealthSnapshot> = None;
                let retention_healthy = backup.as_ref().is_none_or(|w| {
                    use std::sync::atomic::Ordering::Relaxed;
                    w.metrics.pin_overflow.load(Relaxed)==0 && w.metrics.pin_worker_errors.load(Relaxed)==0
                });
                let (coverage_healthy, coverage_status) = coverage.as_ref().map(|c|c.status()).unwrap_or((true,serde_json::json!({"enabled":false,"assessment":"not_checked"})));
                let healthy = coverage_healthy && retention_healthy && !policy_runtime.as_ref().is_some_and(|p|p["invalid"]==true) && !analysis_incomplete && semantic.unavailable_count()==0 && sensor_health.alive && sensor_health.errors == 0 && sensor_health.dropped_events == 0 && sensor_health.kernel_overflows == 0
                    && process_health.as_ref().map_or(true, |h| h.alive && h.errors == 0 && h.dropped_events == 0);
                if let Some(reporter) = &reporter { reporter.set_sensor_healthy(healthy); }
                if !healthy { tracing::error!(?sensor_health, ?process_health, "센서 중단/이벤트 누락 — 보호 상태 저하"); }
                let backup_health = backup.as_ref().map(|worker| {
                    use std::sync::atomic::Ordering::Relaxed;
                    serde_json::json!({"queued":worker.metrics.queued.load(Relaxed),"dropped":worker.metrics.dropped.load(Relaxed),"failed":worker.metrics.failed.load(Relaxed),"oversized":worker.metrics.oversized.load(Relaxed),"completed":worker.metrics.completed.load(Relaxed),"delay_ms":worker.metrics.last_delay_ms.load(Relaxed),"pin_failed":worker.metrics.pin_failed.load(Relaxed),"pin_pending":worker.metrics.pin_pending.load(Relaxed),"pin_overflow":worker.metrics.pin_overflow.load(Relaxed),"pin_completed":worker.metrics.pin_completed.load(Relaxed),"pin_worker_errors":worker.metrics.pin_worker_errors.load(Relaxed)})
                });
                let status = serde_json::json!({"timestamp_ms":argos_common::now_ms(),"policy":policy_runtime,"coverage":coverage_status,"semantic_unavailable":semantic.unavailable_count(),"analysis_incomplete":analysis_incomplete,"retention_healthy":retention_healthy,"sensor_healthy":healthy,"sensor":sensor_health,"process_monitor":process_health,"sensor_queue":rx.len(),"backup":backup_health});
                if let Err(error) = persist_health(&config.db_path, &status) { tracing::warn!(%error, "보호 상태 저장 실패"); }
                if let Some(worker) = &backup {
                    use std::sync::atomic::Ordering::Relaxed;
                    tracing::info!(
                        sensor_queue = rx.len(),
                        backup_queue = worker.metrics.queued.load(Relaxed),
                        backup_dropped = worker.metrics.dropped.load(Relaxed),
                        backup_failed = worker.metrics.failed.load(Relaxed),
                        backup_oversized = worker.metrics.oversized.load(Relaxed),
                        backup_completed = worker.metrics.completed.load(Relaxed),
                        backup_delay_ms = worker.metrics.last_delay_ms.load(Relaxed),
                        "보호 상태 생존 신호"
                    );
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("종료 시그널 수신, 에이전트 정지");
                break;
            }
        }
    }

    Ok(())
}

fn guard_policy_time(
    policy: Option<&mut serde_json::Value>,
    response: &mut argos_common::config::ResponseConfig,
    now: u64,
) {
    if let Some(state) = policy {
        let invalid = state["invalid"] == true
            || now < state["not_before_ms"].as_u64().unwrap_or(u64::MAX)
            || now >= state["expires_at_ms"].as_u64().unwrap_or(0);
        if invalid {
            if state["invalid"] != true {
                tracing::error!(version=?state["version"],"서명 정책 유효기간 이탈 — 자동 대응 중단, 수집/탐지는 유지. 새 정책으로 재시작 필요");
            }
            state["invalid"] = true.into();
            response.auto_block = false;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn process_event(
    event: &mut FileEvent,
    config: &AgentConfig,
    store: &EventStore,
    engine: &mut DetectionEngine,
    responder: &dyn Responder,
    backup: Option<&BackupWorker>,
    reporter: Option<&reporter::Reporter>,
    content_sampler: Option<&mut argos_detect::ContentSampler>,
    semantic: Option<&mut semantic::SemanticMonitor>,
    policy_runtime: Option<&mut serde_json::Value>,
) -> bool {
    let mut sampling_failed = false;
    // 수정 이벤트는 내용 샘플의 엔트로피를 계산해 암호화 의심 여부를 본다.
    if content_sampler.is_none()
        && event.action == FileAction::Modify
        && config.detection.entropy_sample_bytes > 0
    {
        event.entropy = argos_detect::file_entropy(
            Path::new(&event.path),
            config.detection.entropy_sample_bytes,
        )
        .ok();
    }

    if matches!(event.action, FileAction::Create | FileAction::Modify) {
        if let Some(sampler) = content_sampler {
            match sampler.observe(Path::new(&event.path), argos_common::now_ms()) {
                Ok(content) => {
                    event.entropy = content.samples.first().map(|sample| sample.entropy);
                    event.content = Some(content);
                }
                Err(error) => {
                    sampling_failed = true;
                    event.content = None;
                    event.entropy = None;
                    tracing::warn!(path=%event.path,%error,"다중 위치 내용 표본 수집 실패 — 미수집");
                }
            }
        }
    }
    // 매 이벤트의 대응 평가는 알림 중복 억제와 독립적이다. DB/백업 I/O보다 먼저 실행한다.
    let mut evaluation = engine.evaluate(event);
    if evaluation.evidence_truncated {
        tracing::warn!("다중 시간 구간 근거 상한 도달 — 일부 집계 누락");
    }
    if let Some(monitor) = semantic {
        if let Some(alert) = monitor.observe(event) {
            evaluation.additional_alerts.push(alert);
        }
    }
    if let Some(change_id) = &evaluation.approved_change_id {
        tracing::info!(change_id, pid = event.pid, path = %event.path, "승인 작업 맥락 일치 — 해당 행위 규칙 조정");
    }
    let mut response_policy = config.response.clone();
    guard_policy_time(policy_runtime, &mut response_policy, argos_common::now_ms());
    let response_result = if evaluation.should_block(&response_policy) {
        if let Some(identity) = &event.process {
            let action = ResponseAction::KillProcessInstance {
                pid: evaluation.pid,
                start_time_ticks: identity.start_time_ticks,
                boot_id: identity.boot_id.clone(),
            };
            match responder.execute(&action) {
                Ok(()) => {
                    tracing::warn!(
                        pid = evaluation.pid,
                        score = evaluation.score,
                        "자동 차단 완료"
                    );
                    Some(("succeeded", None))
                }
                Err(e) => {
                    tracing::error!(error = %e, "자동 차단 실패/결과 확인 실패");
                    Some(("failed_or_unconfirmed", Some(e.to_string())))
                }
            }
        } else {
            tracing::error!(
                pid = evaluation.pid,
                "프로세스 시작 신원을 확인할 수 없어 자동 차단 거부"
            );
            Some(("rejected", Some("프로세스 시작 신원 미확인".to_string())))
        }
    } else if evaluation.block_candidate(&response_policy) {
        tracing::info!(
            pid = evaluation.pid,
            score = evaluation.score,
            "관찰 모드: 차단 임계치 대상"
        );
        Some(("observed_threshold", None))
    } else {
        None
    };
    if let Some((outcome, error)) = response_result {
        let identity = event.process.as_ref();
        let audit = argos_storage::ResponseAudit {
            timestamp_ms: argos_common::now_ms(),
            pid: evaluation.pid,
            start_time_ticks: identity.map(|i| i.start_time_ticks),
            boot_id: identity.map(|i| i.boot_id.clone()),
            score: evaluation.score,
            action: "kill_process".into(),
            outcome: outcome.into(),
            error,
        };
        if let Err(error) = store.insert_response_result(&audit) {
            tracing::error!(%error, "대응 결과 감사 저장 실패");
        }
    }
    if let Err(e) = store.insert_file_event(event) {
        tracing::error!(error = %e, "이벤트 저장 실패");
    }
    if let Some(worker) = backup {
        if matches!(event.action, FileAction::Create | FileAction::Modify) {
            worker.enqueue(event);
        }
    }
    for detection in evaluation
        .alert
        .into_iter()
        .chain(evaluation.additional_alerts)
    {
        tracing::warn!(score=detection.score,rule=%detection.rule,summary=%detection.summary,"위협/보호 상태 탐지");
        match store.record_detection(
            &detection,
            reporter.map(|r| r.agent_id()),
            backup.is_some() && detection.score > 0.0,
        ) {
            Ok(_id) => {
                if let Some(reporter) = reporter {
                    reporter.notify();
                }
            }
            Err(error) => tracing::error!(%error,"탐지/전송 대기열 저장 실패"),
        }
    }
    evaluation.evidence_truncated || sampling_failed
}

fn persist_health(
    db_path: &Path,
    status: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let destination = db_path.with_extension("health.json");
    let temporary = db_path.with_extension(format!(
        "health.{}.{}.tmp",
        std::process::id(),
        argos_common::now_ms()
    ));
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(serde_json::to_string(status)?.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, &destination)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct RecordingResponder {
        calls: AtomicUsize,
        db: PathBuf,
        expected_events: i64,
    }
    impl Responder for RecordingResponder {
        fn execute(&self, action: &ResponseAction) -> Result<(), argos_response::ResponseError> {
            assert!(matches!(
                action,
                ResponseAction::KillProcessInstance { pid: 4242, .. }
            ));
            // 현재 이벤트가 DB에 저장되기 전에 대응이 실행되어야 한다.
            assert_eq!(
                EventStore::open_readonly(&self.db)
                    .unwrap()
                    .event_count()
                    .unwrap(),
                self.expected_events
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    #[test]
    fn expired_policy_disables_response_without_restoring_on_clock_rewind() {
        let mut policy = Some(
            serde_json::json!({"version":1,"not_before_ms":10,"expires_at_ms":20,"invalid":false}),
        );
        let mut response = argos_common::config::ResponseConfig {
            auto_block: true,
            block_score: 80.0,
        };
        guard_policy_time(policy.as_mut(), &mut response, 19);
        assert!(response.auto_block);
        guard_policy_time(policy.as_mut(), &mut response, 20);
        assert!(!response.auto_block);
        guard_policy_time(policy.as_mut(), &mut response, 15);
        assert!(!response.auto_block);
        assert_eq!(policy.unwrap()["invalid"], true);
    }
    #[test]
    fn response_runs_before_persistence_even_when_alert_is_suppressed() {
        let dir = std::env::temp_dir().join(format!("argos-pipeline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = AgentConfig::default();
        config.sensor = argos_common::config::SensorKind::Fanotify;
        config.response.auto_block = true;
        config.db_path = dir.join("events.db");
        let store = EventStore::open(&config.db_path).unwrap();
        let mut engine = DetectionEngine::with_sensor(config.detection.clone(), config.sensor);
        // 5 files => 66.7 first alert, 15 files =>80 below next alert81.7.
        for i in 0..14 {
            engine.evaluate(&FileEvent {
                timestamp_ms: 1000 + i,
                pid: 4242,
                path: dir.join(format!("f{i}")).display().to_string(),
                action: FileAction::Modify,
                size: Some(256),
                entropy: Some(8.0),
                content: None,
                process: Some(argos_common::FileProcessContext {
                    uid: 1000,
                    exe: "/fixture".into(),
                    start_time_ticks: 123,
                    boot_id: "fixture-boot".into(),
                    ancestors: vec![],
                }),
            });
        }
        let path = dir.join("f14");
        std::fs::write(&path, (0..=255u8).collect::<Vec<_>>()).unwrap();
        let mut event = FileEvent {
            timestamp_ms: 1014,
            pid: 4242,
            path: path.display().to_string(),
            action: FileAction::Modify,
            size: Some(256),
            entropy: None,
            content: None,
            process: Some(argos_common::FileProcessContext {
                uid: 1000,
                exe: "/fixture".into(),
                start_time_ticks: 123,
                boot_id: "fixture-boot".into(),
                ancestors: vec![],
            }),
        };
        let responder = RecordingResponder {
            calls: AtomicUsize::new(0),
            db: config.db_path.clone(),
            expected_events: 0,
        };
        process_event(
            &mut event,
            &config,
            &store,
            &mut engine,
            &responder,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(responder.calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.detection_count().unwrap(), 0);
        assert_eq!(store.event_count().unwrap(), 1);
        // 관찰 모드에서는 responder 성공을 실제 차단 성공으로 기록하지 않는다.
        config.response.auto_block = false;
        event.timestamp_ms += 1;
        process_event(
            &mut event,
            &config,
            &store,
            &mut engine,
            &responder,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(responder.calls.load(Ordering::SeqCst), 1);
        config.response.auto_block = true;
        config.detection.min_changed_files = 1;
        config.detection.mass_change_threshold = 1;
        let mut unknown_identity_engine =
            DetectionEngine::with_sensor(config.detection.clone(), config.sensor);
        event.process = None;
        process_event(
            &mut event,
            &config,
            &store,
            &mut unknown_identity_engine,
            &responder,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(responder.calls.load(Ordering::SeqCst), 1);
        let audit = store
            .response_results(&argos_storage::EvidenceQuery {
                from_ms: 0,
                to_ms: argos_common::now_ms(),
                pid: Some(4242),
                limit: 10,
            })
            .unwrap();
        assert_eq!(
            audit
                .rows
                .iter()
                .map(|r| r.result.outcome.as_str())
                .collect::<Vec<_>>(),
            ["succeeded", "observed_threshold", "rejected"]
        );
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
}
