//! Argos Agent: 센서 → 탐지 → 저장/백업/대응/보고 파이프라인 데몬.
//!
//! 운영 환경에서는 systemd 서비스로 실행한다 (packaging/argos-agent.service).

mod reporter;

use argos_common::{AgentConfig, Detection, FileAction, FileEvent};
use argos_detect::DetectionEngine;
use argos_recovery::BackupStore;
use argos_response::{make_responder, Responder, ResponseAction};
use argos_storage::EventStore;
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
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
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

    tracing::info!(?config, "에이전트 시작");

    // 감시 경로가 없으면 만들어 둔다 (개발 환경 편의).
    for p in &config.watch_paths {
        if !p.exists() {
            std::fs::create_dir_all(p)?;
        }
    }

    let store = EventStore::open(&config.db_path)?;
    let mut engine = DetectionEngine::new(config.detection.clone());
    let responder = make_responder(config.response.auto_block);

    // 백업 저장소 (요건서 10장). 백업 디렉터리는 탐지 제외 경로로도 등록해야
    // 백업 쓰기가 점수에 잡히지 않는다 — 감시 경로 밖에 두는 것이 원칙.
    let backup = if config.backup.enabled {
        let store = BackupStore::open(&config.backup.dir, config.backup.max_file_bytes)?;
        if config.backup.baseline_on_start {
            baseline_backup(&store, &config.watch_paths);
        }
        Some(store)
    } else {
        None
    };

    // 중앙 서버 보고 채널 (옵션). 전송은 별도 스레드에서 blocking HTTP로 처리.
    let report_tx = reporter::spawn(&config.central);

    // 센서 → 파이프라인 채널. 요건서 12장 처리량 대비 버퍼는 추후 튜닝.
    let (tx, mut rx) = mpsc::channel::<FileEvent>(8192);
    let _sensor = argos_sensor::spawn_sensor(config.sensor, &config.watch_paths, tx)?;

    // 프로세스 감시 (Linux 전용, /proc 폴링).
    let (proc_tx, mut proc_rx) = mpsc::channel::<argos_common::ProcessEvent>(1024);
    #[cfg(target_os = "linux")]
    if config.process_monitor.enabled {
        argos_sensor::spawn_proc_monitor(config.process_monitor.interval_ms, proc_tx.clone())?;
    }
    // 송신단을 살려 두어 비활성/비 Linux에서도 recv가 종료되지 않게 한다.
    let _proc_tx_keepalive = proc_tx;

    tracing::info!("이벤트 파이프라인 가동 (Ctrl+C로 종료)");

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(mut event) = maybe_event else { break };
                process_event(
                    &mut event,
                    &config,
                    &store,
                    &mut engine,
                    responder.as_ref(),
                    backup.as_ref(),
                    report_tx.as_ref(),
                );
            }
            maybe_pe = proc_rx.recv() => {
                if let Some(pe) = maybe_pe {
                    if let Err(e) = store.insert_process_event(&pe) {
                        tracing::error!(error = %e, "프로세스 이벤트 저장 실패");
                    }
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
    backup: Option<&BackupStore>,
    report_tx: Option<&std::sync::mpsc::Sender<Detection>>,
) {
    // 수정 이벤트는 내용 샘플의 엔트로피를 계산해 암호화 의심 여부를 본다.
    if event.action == FileAction::Modify {
        event.entropy = argos_detect::file_entropy(
            Path::new(&event.path),
            config.detection.entropy_sample_bytes,
        )
        .ok();
    }

    if let Err(e) = store.insert_file_event(event) {
        tracing::error!(error = %e, "이벤트 저장 실패");
    }

    // 변경된 내용을 버전으로 백업해 둔다 — 공격 전 버전이 복구 지점이 된다.
    if let Some(backup_store) = backup {
        if matches!(event.action, FileAction::Create | FileAction::Modify) {
            match backup_store.backup(Path::new(&event.path), event.timestamp_ms, event.pid) {
                Ok(_) => {}
                Err(argos_recovery::RecoveryError::TooLarge { .. }) => {}
                Err(e) => tracing::debug!(error = %e, path = %event.path, "백업 실패"),
            }
        }
    }

    let Some(detection) = engine.observe(event) else {
        return;
    };

    tracing::warn!(
        score = detection.score,
        severity = detection.severity.as_str(),
        summary = %detection.summary,
        "위협 탐지"
    );
    if let Err(e) = store.insert_detection(&detection) {
        tracing::error!(error = %e, "탐지 결과 저장 실패");
    }
    if let Some(tx) = report_tx {
        let _ = tx.send(detection.clone()); // 보고 실패는 탐지 파이프라인을 막지 않는다.
    }

    // 차단 점수 초과 + pid 식별 가능 시에만 자동 대응 (요건서 18. 단계적 차단).
    if detection.score >= config.response.block_score && detection.pid != 0 {
        let action = ResponseAction::KillProcess(detection.pid);
        match responder.execute(&action) {
            Ok(()) => tracing::warn!(pid = detection.pid, "자동 차단 완료"),
            Err(e) => tracing::error!(error = %e, "자동 차단 실패"),
        }
    }
}

/// 에이전트 시작 시 감시 경로의 기존 파일을 1회 백업한다.
/// 공격 이전 상태의 복구 지점을 확보하기 위함이다.
fn baseline_backup(store: &BackupStore, watch_paths: &[PathBuf]) {
    let started = std::time::Instant::now();
    let mut count = 0usize;
    let mut stack: Vec<PathBuf> = watch_paths.to_vec();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if store
                .backup(&p, argos_common::now_ms(), 0)
                .ok()
                .flatten()
                .is_some()
            {
                count += 1;
            }
        }
    }
    tracing::info!(
        files = count,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "베이스라인 백업 완료"
    );
}
