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
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "argos-central", about = "Argos 중앙관리 서버")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8420")]
    listen: SocketAddr,
    #[arg(long, default_value = "./argos-central-data/central.db")]
    db: PathBuf,
    /// 조회 전용 관리자 토큰. 운영 모드에서 필수.
    #[arg(long, env = "ARGOS_CENTRAL_TOKEN", default_value = "")]
    token: String,
    /// 에이전트 ID별 서로 다른 토큰을 담은 JSON 객체 파일.
    #[arg(long)]
    agent_tokens: Option<PathBuf>,
    /// 인증 없는 개발 모드. loopback listen 주소에서만 허용.
    #[arg(long)]
    development: bool,
}

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    token: String,
    agent_tokens: HashMap<String, String>,
    development: bool,
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
    /// 같은 전달의 재시도에는 같은 ID를 사용한다. 이전 에이전트는 생략 가능.
    #[serde(default)]
    delivery_id: Option<String>,
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
    status: &'static str,
    sensor_healthy: Option<bool>,
    outbox_pending: u64,
    failed_attempts: u64,
    last_heartbeat_ms: Option<i64>,
}

#[derive(Deserialize)]
struct HeartbeatRequest {
    agent_id: String,
    sensor_healthy: bool,
    outbox_pending: u64,
    failed_attempts: u64,
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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let agent_tokens: HashMap<String, String> = match &args.agent_tokens {
        Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
        None => HashMap::new(),
    };
    validate_auth_config(&args, &agent_tokens)?;
    if args.development {
        tracing::warn!("명시적 개발 모드 — loopback에서 인증 없이 동작");
    }

    if let Some(parent) = args.db.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(&args.db)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    initialize_database(&conn)?;

    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        token: args.token,
        agent_tokens,
        development: args.development,
    };

    let app = Router::new()
        .route(
            "/",
            get(|| async { axum::response::Html(include_str!("dashboard.html")) }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/v1/agents/register", post(register_agent))
        .route("/api/v1/agents/heartbeat", post(heartbeat))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/detections", post(ingest_detection))
        .route("/api/v1/detections", get(list_detections))
        .with_state(state);

    tracing::info!(listen = %args.listen, "Argos Central 시작");
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn initialize_database(conn: &Connection) -> rusqlite::Result<()> {
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

    for (table, column, declaration) in [
        ("detections", "delivery_id", "TEXT"),
        ("agents", "sensor_healthy", "INTEGER"),
        ("agents", "outbox_pending", "INTEGER NOT NULL DEFAULT 0"),
        ("agents", "failed_attempts", "INTEGER NOT NULL DEFAULT 0"),
        ("agents", "last_heartbeat_ms", "INTEGER"),
    ] {
        let columns = conn
            .prepare(&format!("PRAGMA table_info({table})"))?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if !columns.iter().any(|name| name == column) {
            conn.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN {column} {declaration}"
            ))?;
        }
    }
    conn.execute_batch("CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_delivery ON detections(agent_id,delivery_id) WHERE delivery_id IS NOT NULL")?;
    Ok(())
}

fn validate_auth_config(args: &Args, tokens: &HashMap<String, String>) -> Result<(), String> {
    if args.development {
        if !args.listen.ip().is_loopback() {
            return Err("개발 모드는 loopback 주소에서만 실행할 수 있습니다".into());
        }
        if !args.token.is_empty() || !tokens.is_empty() {
            return Err("개발 모드와 인증 설정을 함께 사용하지 마세요".into());
        }
        return Ok(());
    }
    if args.token.trim().is_empty() || tokens.is_empty() {
        return Err("운영 모드는 관리자 토큰과 --agent-tokens JSON 파일이 필요합니다; 로컬 개발은 --development --listen 127.0.0.1:8420".into());
    }
    let mut seen = HashSet::new();
    seen.insert(args.token.as_str());
    for (id, token) in tokens {
        if id.trim().is_empty() || token.trim().is_empty() || !seen.insert(token.as_str()) {
            return Err(
                "에이전트 ID/토큰은 비어 있을 수 없고 관리자/에이전트별 토큰은 모두 달라야 합니다"
                    .into(),
            );
        }
    }
    Ok(())
}

fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    if state.development || (!state.token.is_empty() && bearer(headers) == state.token) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn authorize_agent(
    state: &AppState,
    headers: &HeaderMap,
    agent_id: &str,
) -> Result<(), StatusCode> {
    if agent_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if state.development {
        return Ok(());
    }
    match state.agent_tokens.get(agent_id) {
        Some(token) if !token.is_empty() && bearer(headers) == token => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn register_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<StatusCode, StatusCode> {
    authorize_agent(&state, &headers, &req.agent_id)?;
    let now = argos_common::now_ms() as i64;
    let tags = serde_json::to_string(&req.tags).unwrap_or_else(|_| "[]".into());
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    authorize_agent(&state, &headers, &report.agent_id)?;
    if report.timestamp_ms > i64::MAX as u64
        || !report.score.is_finite()
        || !(0.0..=100.0).contains(&report.score)
        || report
            .delivery_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 128)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let paths = serde_json::to_string(&report.paths).unwrap_or_else(|_| "[]".into());
    let now = argos_common::now_ms() as i64;
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let registered: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id=?1)",
            params![report.agent_id],
            |r| r.get(0),
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !registered {
        return Err(StatusCode::NOT_FOUND);
    }
    let tx = db
        .unchecked_transaction()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tx.execute(
        "INSERT INTO detections (agent_id, timestamp_ms, rule, score, severity, summary, pid, paths_json, delivery_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT DO NOTHING",
        params![
            report.agent_id,
            report.timestamp_ms as i64,
            report.rule,
            report.score,
            report.severity,
            report.summary,
            report.pid,
            paths,
            report.delivery_id,
        ],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tx.execute(
        "UPDATE agents SET last_seen_ms = ?2 WHERE agent_id = ?1",
        params![report.agent_id, now],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tx.commit().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<StatusCode, StatusCode> {
    authorize_agent(&state, &headers, &req.agent_id)?;
    if req.outbox_pending > i64::MAX as u64 || req.failed_attempts > i64::MAX as u64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let now = argos_common::now_ms() as i64;
    let updated=db.execute("UPDATE agents SET last_seen_ms=?2,last_heartbeat_ms=?2,sensor_healthy=?3,outbox_pending=?4,failed_attempts=?5 WHERE agent_id=?1",
        params![req.agent_id,now,req.sensor_healthy,req.outbox_pending,req.failed_attempts]).map_err(|_|StatusCode::INTERNAL_SERVER_ERROR)?;
    if updated == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(StatusCode::OK)
}

fn agent_status(last_seen_ms: i64, now_ms: i64) -> &'static str {
    match now_ms.saturating_sub(last_seen_ms).max(0) {
        0..=60_000 => "online",
        60_001..=120_000 => "stale",
        _ => "offline",
    }
}

async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AgentInfo>>, StatusCode> {
    authorize(&state, &headers)?;
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let now = argos_common::now_ms() as i64;
    let mut stmt = db
        .prepare(
            "SELECT a.agent_id, a.hostname, a.tags_json, a.registered_at_ms, a.last_seen_ms,
                    (SELECT COUNT(*) FROM detections d WHERE d.agent_id = a.agent_id),
                    a.sensor_healthy,a.outbox_pending,a.failed_attempts,a.last_heartbeat_ms
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
                status: agent_status(r.get(4)?, now),
                sensor_healthy: r.get(6)?,
                outbox_pending: r.get(7)?,
                failed_attempts: r.get(8)?,
                last_heartbeat_ms: r.get(9)?,
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
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT agent_id, timestamp_ms, rule, score, severity, summary
             FROM detections ORDER BY id DESC LIMIT ?1",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map(params![q.limit.clamp(1, 1000) as i64], |r| {
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

#[cfg(test)]
mod tests {
    use super::*;
    fn test_state() -> AppState {
        let db = Connection::open_in_memory().unwrap();
        initialize_database(&db).unwrap();
        // 재시작 시 같은 마이그레이션을 반복해도 안전하다.
        initialize_database(&db).unwrap();
        AppState {
            db: Arc::new(Mutex::new(db)),
            token: "admin".into(),
            development: false,
            agent_tokens: HashMap::from([
                ("host-a".into(), "agent-a".into()),
                ("host-b".into(), "agent-b".into()),
            ]),
        }
    }
    fn report(agent_id: &str, id: &str) -> DetectionReport {
        DetectionReport {
            agent_id: agent_id.into(),
            delivery_id: Some(id.into()),
            timestamp_ms: 1,
            rule: "test".into(),
            score: 90.0,
            severity: "critical".into(),
            summary: "test".into(),
            pid: 42,
            paths: vec!["/data/a".into()],
        }
    }
    #[tokio::test]
    async fn duplicate_delivery_is_counted_once_and_scoped_to_agent() {
        let state = test_state();
        assert_eq!(
            ingest_detection(
                State(state.clone()),
                headers("agent-a"),
                Json(report("host-a", "delivery-1"))
            )
            .await,
            Err(StatusCode::NOT_FOUND)
        );
        for (id, token) in [("host-a", "agent-a"), ("host-b", "agent-b")] {
            register_agent(
                State(state.clone()),
                headers(token),
                Json(RegisterRequest {
                    agent_id: id.into(),
                    hostname: id.into(),
                    tags: vec![],
                }),
            )
            .await
            .unwrap();
            for _ in 0..2 {
                ingest_detection(
                    State(state.clone()),
                    headers(token),
                    Json(report(id, "delivery-1")),
                )
                .await
                .unwrap();
            }
        }
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM detections", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        let Json(agents) = list_agents(State(state.clone()), headers("admin"))
            .await
            .unwrap();
        assert!(agents.iter().all(|a| a.detection_count == 1));
        assert_eq!(
            ingest_detection(
                State(state),
                headers("agent-a"),
                Json(report("host-b", "delivery-2"))
            )
            .await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }
    #[tokio::test]
    async fn heartbeat_updates_health_without_detection_and_enforces_auth() {
        let state = test_state();
        register_agent(
            State(state.clone()),
            headers("agent-a"),
            Json(RegisterRequest {
                agent_id: "host-a".into(),
                hostname: "host-a".into(),
                tags: vec![],
            }),
        )
        .await
        .unwrap();
        let request = || HeartbeatRequest {
            agent_id: "host-a".into(),
            sensor_healthy: false,
            outbox_pending: 7,
            failed_attempts: 3,
        };
        assert_eq!(
            heartbeat(State(state.clone()), headers("agent-b"), Json(request())).await,
            Err(StatusCode::UNAUTHORIZED)
        );
        heartbeat(State(state.clone()), headers("agent-a"), Json(request()))
            .await
            .unwrap();
        let Json(agents) = list_agents(State(state), headers("admin")).await.unwrap();
        assert_eq!(agents[0].status, "online");
        assert_eq!(agents[0].sensor_healthy, Some(false));
        assert_eq!(agents[0].outbox_pending, 7);
        assert_eq!(agents[0].failed_attempts, 3);
        assert_eq!(agents[0].detection_count, 0);
        assert!(agents[0].last_heartbeat_ms.is_some());
        assert_eq!(agent_status(0, 60_000), "online");
        assert_eq!(agent_status(0, 60_001), "stale");
        assert_eq!(agent_status(0, 120_001), "offline");
    }
    fn args() -> Args {
        Args {
            listen: "0.0.0.0:8420".parse().unwrap(),
            db: PathBuf::from("unused"),
            token: String::new(),
            agent_tokens: None,
            development: false,
        }
    }
    fn headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers
    }
    #[test]
    fn production_auth_is_mandatory_and_development_is_loopback_only() {
        let mut a = args();
        assert!(validate_auth_config(&a, &HashMap::new()).is_err());
        a.development = true;
        assert!(validate_auth_config(&a, &HashMap::new()).is_err());
        a.listen = "127.0.0.1:8420".parse().unwrap();
        assert!(validate_auth_config(&a, &HashMap::new()).is_ok());
        a.development = false;
        a.token = "admin".into();
        assert!(
            validate_auth_config(&a, &HashMap::from([("host-a".into(), "admin".into())])).is_err()
        );
        assert!(
            validate_auth_config(&a, &HashMap::from([("host-a".into(), "agent-a".into())])).is_ok()
        );
    }
    #[test]
    fn agent_cannot_impersonate_or_read_other_agents() {
        let state = AppState {
            db: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            token: "admin".into(),
            development: false,
            agent_tokens: HashMap::from([
                ("host-a".into(), "agent-a".into()),
                ("host-b".into(), "agent-b".into()),
            ]),
        };
        assert!(authorize_agent(&state, &headers("agent-a"), "host-a").is_ok());
        assert_eq!(
            authorize_agent(&state, &headers("agent-a"), "host-b"),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            authorize_agent(&state, &headers("admin"), "host-a"),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert!(authorize(&state, &headers("agent-a")).is_err());
        assert!(authorize(&state, &headers("admin")).is_ok());
        assert!(authorize(&state, &HeaderMap::new()).is_err());
    }
}
