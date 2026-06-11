//! Argos Agent: 센서 → 탐지 → 저장/대응 파이프라인을 구동하는 데몬.
//!
//! 운영 환경에서는 systemd 서비스로 실행한다 (packaging/argos-agent.service).

use argos_common::{AgentConfig, FileAction, FileEvent};
use argos_detect::DetectionEngine;
use argos_response::{make_responder, Responder, ResponseAction};
use argos_storage::EventStore;
use clap::Parser;
use std::path::PathBuf;
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
    let config = AgentConfig::load(&args.config)?;
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

    // 센서 → 파이프라인 채널. 요건서 12장 처리량 대비 버퍼는 추후 튜닝.
    let (tx, mut rx) = mpsc::channel::<FileEvent>(8192);
    let _sensor = argos_sensor::spawn_fs_sensor(&config.watch_paths, tx)?;

    tracing::info!("이벤트 파이프라인 가동 (Ctrl+C로 종료)");

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(mut event) = maybe_event else { break };
                process_event(&mut event, &config, &store, &mut engine, responder.as_ref());
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("종료 시그널 수신, 에이전트 정지");
                break;
            }
        }
    }

    Ok(())
}

fn process_event(
    event: &mut FileEvent,
    config: &AgentConfig,
    store: &EventStore,
    engine: &mut DetectionEngine,
    responder: &dyn Responder,
) {
    // 수정 이벤트는 내용 샘플의 엔트로피를 계산해 암호화 의심 여부를 본다.
    if event.action == FileAction::Modify {
        event.entropy = argos_detect::file_entropy(
            std::path::Path::new(&event.path),
            config.detection.entropy_sample_bytes,
        )
        .ok();
    }

    if let Err(e) = store.insert_file_event(event) {
        tracing::error!(error = %e, "이벤트 저장 실패");
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

    // 차단 점수 초과 + pid 식별 가능 시에만 자동 대응 (요건서 18. 단계적 차단).
    if detection.score >= config.response.block_score && detection.pid != 0 {
        let action = ResponseAction::KillProcess(detection.pid);
        match responder.execute(&action) {
            Ok(()) => tracing::warn!(pid = detection.pid, "자동 차단 완료"),
            Err(e) => tracing::error!(error = %e, "자동 차단 실패"),
        }
    }
}
