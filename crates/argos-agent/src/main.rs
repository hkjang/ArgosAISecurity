//! Argos Agent: 센서 → 탐지 → 저장/백업/대응/보고 파이프라인 데몬.
//!
//! 운영 환경에서는 systemd 서비스로 실행한다 (packaging/argos-agent.service).

mod backup_worker;
mod reporter;

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

    // 서명된 정책 적용 (요건서 11장): 검증 실패 시 정책을 적용하지 않고
    // argos.toml의 기존 설정으로 계속 동작한다.
    if config.policy.is_enabled() {
        match argos_policy::load_verified(&config.policy.path, &config.policy.pubkey) {
            Ok(policy) => {
                tracing::info!(version = policy.version, "서명 검증된 정책 적용");
                config.detection = policy.detection;
                config.response = policy.response;
            }
            Err(e) => {
                tracing::error!(error = %e, "정책 서명 검증 실패 — 정책 미적용, 기존 설정 유지");
            }
        }
    }

    for warning in
        argos_detect::validate_configuration(&config.detection, &config.response, config.sensor)?
    {
        tracing::warn!(warning, "탐지/대응 설정 경고");
    }
    tracing::info!(sensor = ?config.sensor, auto_block = config.response.auto_block, "에이전트 시작");

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

    // 백업은 별도 작업자에서 처리한다. 센서 경로 안에 저장소가 있으면 재귀 이벤트를 유발한다.
    let backup = if config.backup.enabled {
        std::fs::create_dir_all(&config.backup.dir)?;
        let backup_dir = config.backup.dir.canonicalize()?;
        for path in &config.watch_paths {
            if backup_dir.starts_with(path.canonicalize()?) {
                return Err("백업 디렉터리는 감시 경로 밖에 두어야 합니다".into());
            }
        }
        Some(BackupWorker::spawn(&config.backup, &config.watch_paths)?)
    } else {
        None
    };

    // 중앙 서버 보고 채널 (옵션). 전송은 별도 스레드에서 blocking HTTP로 처리.
    let reporter = reporter::spawn(&config.central, &config.db_path)?;

    // 센서 → 파이프라인 채널. 요건서 12장 처리량 대비 버퍼는 추후 튜닝.
    let (tx, mut rx) = mpsc::channel::<FileEvent>(8192);
    let sensor = argos_sensor::spawn_sensor(config.sensor, &config.watch_paths, tx)?;

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

    let mut health_tick = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(mut event) = maybe_event else {
                    if let Some(reporter) = &reporter { reporter.set_sensor_healthy(false); }
                    tracing::error!("파일 센서 채널 중단 — 보호 상태 저하");
                    return Err("파일 센서가 중단되었습니다".into());
                };
                process_event(
                    &mut event,
                    &config,
                    &store,
                    &mut engine,
                    responder.as_ref(),
                    backup.as_ref(),
                    reporter.as_ref(),
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
                let sensor_health = sensor.health();
                #[cfg(target_os = "linux")]
                let process_health = process_monitor.as_ref().map(|m| m.health());
                #[cfg(not(target_os = "linux"))]
                let process_health: Option<argos_sensor::SensorHealthSnapshot> = None;
                let healthy = sensor_health.alive && sensor_health.errors == 0 && sensor_health.dropped_events == 0 && sensor_health.kernel_overflows == 0
                    && process_health.as_ref().map_or(true, |h| h.alive && h.errors == 0 && h.dropped_events == 0);
                if let Some(reporter) = &reporter { reporter.set_sensor_healthy(healthy); }
                if !healthy { tracing::error!(?sensor_health, ?process_health, "센서 중단/이벤트 누락 — 보호 상태 저하"); }
                let backup_health = backup.as_ref().map(|worker| {
                    use std::sync::atomic::Ordering::Relaxed;
                    serde_json::json!({"queued":worker.metrics.queued.load(Relaxed),"dropped":worker.metrics.dropped.load(Relaxed),"failed":worker.metrics.failed.load(Relaxed),"oversized":worker.metrics.oversized.load(Relaxed),"completed":worker.metrics.completed.load(Relaxed),"delay_ms":worker.metrics.last_delay_ms.load(Relaxed)})
                });
                let status = serde_json::json!({"timestamp_ms":argos_common::now_ms(),"sensor_healthy":healthy,"sensor":sensor_health,"process_monitor":process_health,"sensor_queue":rx.len(),"backup":backup_health});
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

#[allow(clippy::too_many_arguments)]
fn process_event(
    event: &mut FileEvent,
    config: &AgentConfig,
    store: &EventStore,
    engine: &mut DetectionEngine,
    responder: &dyn Responder,
    backup: Option<&BackupWorker>,
    reporter: Option<&reporter::Reporter>,
) {
    // 수정 이벤트는 내용 샘플의 엔트로피를 계산해 암호화 의심 여부를 본다.
    if event.action == FileAction::Modify && config.detection.entropy_sample_bytes > 0 {
        event.entropy = argos_detect::file_entropy(
            Path::new(&event.path),
            config.detection.entropy_sample_bytes,
        )
        .ok();
    }

    // 매 이벤트의 대응 평가는 알림 중복 억제와 독립적이다. DB/백업 I/O보다 먼저 실행한다.
    let evaluation = engine.evaluate(event);
    if let Some(change_id) = &evaluation.approved_change_id {
        tracing::info!(change_id, pid = event.pid, path = %event.path, "승인 작업 맥락 일치 — 해당 행위 규칙 조정");
    }
    let response_result = if evaluation.should_block(&config.response) {
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
    } else if evaluation.block_candidate(&config.response) {
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
    let Some(detection) = evaluation.alert else {
        return;
    };

    tracing::warn!(
        score = detection.score,
        severity = detection.severity.as_str(),
        summary = %detection.summary,
        "위협 탐지"
    );
    let result = if let Some(reporter) = reporter {
        store.insert_detection_with_outbox(&detection, reporter.agent_id())
    } else {
        store.insert_detection(&detection)
    };
    if let Err(e) = result {
        tracing::error!(error = %e, "탐지/전송 대기열 저장 실패");
    } else if let Some(reporter) = reporter {
        reporter.notify();
    }
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
                process: Some(argos_common::FileProcessContext {
                    uid: 1000,
                    exe: "/fixture".into(),
                    start_time_ticks: 123,
                    boot_id: "fixture-boot".into(),
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
            process: Some(argos_common::FileProcessContext {
                uid: 1000,
                exe: "/fixture".into(),
                start_time_ticks: 123,
                boot_id: "fixture-boot".into(),
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
