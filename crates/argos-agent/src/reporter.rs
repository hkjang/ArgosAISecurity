//! 중앙관리 서버 보고 (요건서 15장 — Phase 2 1단계 연동).
//!
//! tokio 런타임 안에서 reqwest blocking 클라이언트를 쓸 수 없으므로
//! 전용 std 스레드 + std mpsc 채널로 분리한다. 전송 실패는 로그만 남기고
//! 탐지 파이프라인에는 영향을 주지 않는다 (큐 재전송은 Phase 4).

use argos_common::{config::CentralConfig, Detection};
use std::sync::mpsc::{self, Sender};

/// central.url이 설정되어 있으면 보고 스레드를 시작하고 송신 채널을 반환한다.
pub fn spawn(config: &CentralConfig) -> Option<Sender<Detection>> {
    if config.url.is_empty() {
        return None;
    }
    let url = config.url.trim_end_matches('/').to_string();
    let token = config.token.clone();
    let agent_id = if config.agent_id.is_empty() {
        hostname()
    } else {
        config.agent_id.clone()
    };

    let (tx, rx) = mpsc::channel::<Detection>();
    std::thread::Builder::new()
        .name("argos-reporter".into())
        .spawn(move || run(url, token, agent_id, rx))
        .ok()?;
    Some(tx)
}

fn run(url: String, token: String, agent_id: String, rx: mpsc::Receiver<Detection>) {
    let client = reqwest::blocking::Client::new();

    // 시작 시 등록.
    let register = serde_json::json!({
        "agent_id": agent_id,
        "hostname": hostname(),
        "tags": Vec::<String>::new(),
    });
    if let Err(e) = post(&client, &url, "/api/v1/agents/register", &token, &register) {
        tracing::warn!(error = %e, "중앙 서버 등록 실패 — 보고는 계속 시도");
    } else {
        tracing::info!(url = %url, agent_id = %agent_id, "중앙 서버 등록 완료");
    }

    while let Ok(detection) = rx.recv() {
        let body = serde_json::json!({
            "agent_id": agent_id,
            "timestamp_ms": detection.timestamp_ms,
            "rule": detection.rule,
            "score": detection.score,
            "severity": detection.severity.as_str(),
            "summary": detection.summary,
            "pid": detection.pid,
            "paths": detection.paths,
        });
        if let Err(e) = post(&client, &url, "/api/v1/detections", &token, &body) {
            tracing::warn!(error = %e, "탐지 보고 실패");
        }
    }
}

fn post(
    client: &reqwest::blocking::Client,
    base: &str,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> Result<(), reqwest::Error> {
    let mut req = client.post(format!("{base}{path}")).json(body);
    if !token.is_empty() {
        req = req.bearer_auth(token);
    }
    req.send()?.error_for_status()?;
    Ok(())
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}
