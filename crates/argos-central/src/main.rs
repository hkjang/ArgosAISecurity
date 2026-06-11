//! Argos Central: 중앙관리 서버 (요건서 15장) — Phase 2 골격.
//!
//! 구현: 에이전트 등록, 탐지 수집(ingest), 현황 조회 REST API.
//! Phase 4에서 mTLS 인증, 정책 배포, 대시보드가 추가된다.
//! 현재 인증은 공유 토큰(Authorization: Bearer) 1단계만 제공한다.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser, Debug)]
#[command(name = "argos-central", about = "Argos 중앙관리 서버")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8420")]
    listen: SocketAddr,
    #[arg(long, default_value = "./argos-central-data/central.db")]
    db: PathBuf,
    /// 에이전트 인증용 공유 토큰. 비우면 인증 없이 동작 (개발 전용).
    #[arg(long, env = "ARGOS_CENTRAL_TOKEN", default_value = "")]
    token: String,
}

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    token: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    agent_id: String,
    hostname: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct DetectionReport {
    agent_id: String,
    timestamp_ms: u64,
    rule: String,
    score: f64,
    severity: String,
    summary: String,
    pid: u32,
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Serialize)]
struct AgentInfo {
    agent_id: String,
    hostname: String,
    tags: Vec<String>,
    registered_at_ms: i64,
    last_seen_ms: i64,
    detection_count: i64,
}

#[derive(Serialize)]
struct DetectionInfo {
    agent_id: String,
    timestamp_ms: i64,
    rule: String,
    score: f64,
    severity: String,
    summary: String,
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    50
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
    if args.token.is_empty() {
        tracing::warn!("ARGOS_CENTRAL_TOKEN 미설정 — 인증 없이 동작합니다 (개발 전용)");
    }

    if let Some(parent) = args.db.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(&args.db)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS agents (
            agent_id         TEXT PRIMARY KEY,
            hostname         TEXT NOT NULL,
            tags_json        TEXT NOT NULL,
            registered_at_ms INTEGER NOT NULL,
            last_seen_ms     INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS detections (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id     TEXT NOT NULL,
            timestamp_ms INTEGER NOT NULL,
            rule         TEXT NOT NULL,
            score        REAL NOT NULL,
            severity     TEXT NOT NULL,
            summary      TEXT NOT NULL,
            pid          INTEGER NOT NULL,
            paths_json   TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_detections_agent ON detections(agent_id, timestamp_ms);",
    )?;

    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        token: args.token,
    };

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/v1/agents/register", post(register_agent))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/detections", post(ingest_detection))
        .route("/api/v1/detections", get(list_detections))
        .with_state(state);

    tracing::info!(listen = %args.listen, "Argos Central 시작");
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    if state.token.is_empty() {
        return Ok(());
    }
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if provided == state.token {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn register_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<StatusCode, StatusCode> {
    authorize(&state, &headers)?;
    let now = argos_common::now_ms() as i64;
    let tags = serde_json::to_string(&req.tags).unwrap_or_else(|_| "[]".into());
    let db = state.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "INSERT INTO agents (agent_id, hostname, tags_json, registered_at_ms, last_seen_ms)
         VALUES (?1, ?2, ?3, ?4, ?4)
         ON CONFLICT(agent_id) DO UPDATE SET
             hostname = excluded.hostname,
             tags_json = excluded.tags_json,
             last_seen_ms = excluded.last_seen_ms",
        params![req.agent_id, req.hostname, tags, now],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tracing::info!(agent_id = %req.agent_id, hostname = %req.hostname, "에이전트 등록");
    Ok(StatusCode::OK)
}

async fn ingest_detection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(report): Json<DetectionReport>,
) -> Result<StatusCode, StatusCode> {
    authorize(&state, &headers)?;
    let paths = serde_json::to_string(&report.paths).unwrap_or_else(|_| "[]".into());
    let now = argos_common::now_ms() as i64;
    let db = state.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "INSERT INTO detections (agent_id, timestamp_ms, rule, score, severity, summary, pid, paths_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            report.agent_id,
            report.timestamp_ms as i64,
            report.rule,
            report.score,
            report.severity,
            report.summary,
            report.pid,
            paths,
        ],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "UPDATE agents SET last_seen_ms = ?2 WHERE agent_id = ?1",
        params![report.agent_id, now],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AgentInfo>>, StatusCode> {
    authorize(&state, &headers)?;
    let db = state.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT a.agent_id, a.hostname, a.tags_json, a.registered_at_ms, a.last_seen_ms,
                    (SELECT COUNT(*) FROM detections d WHERE d.agent_id = a.agent_id)
             FROM agents a ORDER BY a.last_seen_ms DESC",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map([], |r| {
            let tags_json: String = r.get(2)?;
            Ok(AgentInfo {
                agent_id: r.get(0)?,
                hostname: r.get(1)?,
                tags: serde_json::from_str(&tags_json).unwrap_or_default(),
                registered_at_ms: r.get(3)?,
                last_seen_ms: r.get(4)?,
                detection_count: r.get(5)?,
            })
        })
        .and_then(|rows| rows.collect::<Result<Vec<_>, _>>())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}

async fn list_detections(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<DetectionInfo>>, StatusCode> {
    authorize(&state, &headers)?;
    let db = state.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT agent_id, timestamp_ms, rule, score, severity, summary
             FROM detections ORDER BY id DESC LIMIT ?1",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map(params![q.limit as i64], |r| {
            Ok(DetectionInfo {
                agent_id: r.get(0)?,
                timestamp_ms: r.get(1)?,
                rule: r.get(2)?,
                score: r.get(3)?,
                severity: r.get(4)?,
                summary: r.get(5)?,
            })
        })
        .and_then(|rows| rows.collect::<Result<Vec<_>, _>>())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}
