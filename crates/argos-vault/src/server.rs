use crate::quota::{CapacityConfig, CapacityRejection, CapacityState};
use crate::*;
use axum::{
    body::{to_bytes, Body},
    extract::{Path as UrlPath, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub dir: PathBuf,
    pub signing_key_file: PathBuf,
    pub key_id: String,
    pub retention_secs: u64,
    pub max_object_bytes: usize,
    pub admin_token: String,
    pub agent_tokens: BTreeMap<String, String>,
    /// 비 loopback의 평문 수신은 명시적으로 선택한다. 운영은 TLS 프록시 사용 권장.
    pub allow_plain_http: bool,
    /// 신규 객체의 논리 용량과 파일시스템 여유공간 보호.
    pub capacity: CapacityConfig,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:9080".parse().unwrap(),
            dir: "/var/lib/argos-vault".into(),
            signing_key_file: "/etc/argos-vault/signing.key".into(),
            key_id: "vault-1".into(),
            retention_secs: 30 * 86400,
            max_object_bytes: MAX_OBJECT_BYTES,
            admin_token: String::new(),
            agent_tokens: BTreeMap::new(),
            allow_plain_http: false,
            capacity: CapacityConfig::default(),
        }
    }
}
impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("bind", &self.bind)
            .field("dir", &self.dir)
            .field("key_id", &self.key_id)
            .field("tokens", &"[REDACTED]")
            .finish()
    }
}
/// 토큰이 들어 있는 설정도 전용 디렉터리의 제한된 일반 파일로 읽는다.
pub fn load_server_config(path: &Path) -> Result<ServerConfig> {
    validate_private_directory(path.parent().ok_or("설정 부모 경로가 없습니다")?)?;
    let bytes = read_storage_file(path, 1024 * 1024)?;
    toml::from_str(std::str::from_utf8(&bytes).map_err(|_| "보관 서버 설정 UTF-8 오류")?)
        .map_err(|_| "보관 서버 설정 파싱 실패".into())
}

struct Storage {
    config: ServerConfig,
    key: SigningKey,
    capacity: CapacityState,
}
#[derive(Clone)]
struct AppState {
    storage: Arc<Mutex<Storage>>,
    config: Arc<ServerConfig>,
    permits: Arc<tokio::sync::Semaphore>,
}

/// 저장소/키 경계와 토큰을 검증한 뒤 라우터를 만든다. 서버 설정을 로그에 쓰지 않는다.
pub fn router(config: ServerConfig) -> Result<Router> {
    if !config.bind.ip().is_loopback() && !config.allow_plain_http {
        return Err("비 loopback HTTP 수신에는 allow_plain_http=true 또는 loopback TLS 프록시 구성이 필요합니다".into());
    }
    if !valid_id(&config.key_id)
        || config.agent_tokens.is_empty()
        || !(1..=MAX_OBJECT_BYTES).contains(&config.max_object_bytes)
        || config.retention_secs == 0
        || config.retention_secs > 10 * 366 * 86400
    {
        return Err("보관 서버 설정의 키 ID·에이전트·크기·보존 기간이 유효하지 않습니다".into());
    }
    let mut tokens = BTreeSet::new();
    for token in std::iter::once(&config.admin_token).chain(config.agent_tokens.values()) {
        if token.trim() != token
            || token.len() < 16
            || token.len() > 4096
            || token.bytes().any(|byte| {
                !byte.is_ascii() || byte.is_ascii_control() || byte.is_ascii_whitespace()
            })
            || !tokens.insert(token)
        {
            return Err(
                "관리자/에이전트 토큰은 서로 다른 16~4096바이트 비공백 값이어야 합니다".into(),
            );
        }
    }
    if config.agent_tokens.keys().any(|id| !valid_id(id)) {
        return Err("에이전트 ID는 1~128자의 영문·숫자·하이픈·밑줄만 허용합니다".into());
    }
    validate_private_directory(&config.dir)?;
    let key = load_key(&config.signing_key_file)?;
    let capacity = CapacityState::open(
        &config.dir,
        config.capacity.clone(),
        config.agent_tokens.keys().cloned(),
        &key,
        &config.key_id,
    )?;
    let state = AppState {
        storage: Arc::new(Mutex::new(Storage {
            config: config.clone(),
            key,
            capacity,
        })),
        config: Arc::new(config),
        permits: Arc::new(tokio::sync::Semaphore::new(4)),
    };
    Ok(Router::new()
        .route("/v1/objects/:hash", post(upload))
        .route("/v1/objects/:agent/:hash", get(download))
        .route("/v1/receipts/:agent/:hash", get(receipt))
        .route("/v1/usage", get(usage))
        .with_state(state))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    if headers.get_all("authorization").iter().count() != 1 {
        return None;
    }
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
fn upload_agent<'a>(config: &'a ServerConfig, headers: &HeaderMap) -> Option<&'a str> {
    let token = bearer(headers)?;
    config
        .agent_tokens
        .iter()
        .find(|(_, expected)| token == expected.as_str())
        .map(|(id, _)| id.as_str())
}
fn admin(config: &ServerConfig, headers: &HeaderMap) -> bool {
    bearer(headers).is_some_and(|token| token == config.admin_token)
}
fn failure(status: StatusCode, message: &'static str) -> Response {
    (status, message).into_response()
}

async fn upload(
    State(state): State<AppState>,
    UrlPath(hash): UrlPath<String>,
    request: Request,
) -> Response {
    let Some(agent) = upload_agent(&state.config, request.headers()).map(str::to_owned) else {
        return failure(StatusCode::UNAUTHORIZED, "수집 토큰 인증 실패");
    };
    // 에이전트 ID는 요청 본문/헤더가 아닌 토큰에서만 결정한다.
    if request.headers().contains_key("x-argos-agent-id") {
        return failure(
            StatusCode::BAD_REQUEST,
            "에이전트 ID 헤더는 허용하지 않습니다",
        );
    }
    let Some(kind) = request
        .headers()
        .get("x-argos-kind")
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_kind(v))
        .map(str::to_owned)
    else {
        return failure(StatusCode::BAD_REQUEST, "유효한 X-Argos-Kind가 필요합니다");
    };
    if !valid_hash(&hash) {
        return failure(StatusCode::BAD_REQUEST, "SHA-256 형식 오류");
    }
    let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "동시 보관 요청 상한");
    };
    let body = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        to_bytes(request.into_body(), state.config.max_object_bytes),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => return failure(StatusCode::PAYLOAD_TOO_LARGE, "본문 수집/크기 상한 오류"),
        Err(_) => return failure(StatusCode::REQUEST_TIMEOUT, "본문 수집 시간 초과"),
    };
    if sha256(&body) != hash {
        return failure(StatusCode::UNPROCESSABLE_ENTITY, "본문 해시 불일치");
    }
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut storage = state.storage.lock().map_err(|_| "저장소 잠금 오류")?;
        storage.put(&agent, &hash, &kind, &body)
    })
    .await;
    match result {
        Ok(Ok(receipt)) => Json(receipt).into_response(),
        Ok(Err(error)) if error.downcast_ref::<CapacityRejection>().is_some() => failure(
            StatusCode::INSUFFICIENT_STORAGE,
            "신규 객체 보관 한도/여유공간/계수 상태로 거부됨",
        ),
        // 내부 경로·키·토큰·오류 원문은 외부에 반환하지 않는다.
        _ => failure(StatusCode::CONFLICT, "보관 상태 충돌 또는 영속 저장 실패"),
    }
}

async fn download(
    State(state): State<AppState>,
    UrlPath((agent, hash)): UrlPath<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !admin(&state.config, &headers) {
        return failure(StatusCode::UNAUTHORIZED, "조회 토큰 인증 실패");
    }
    if !valid_id(&agent) || !valid_hash(&hash) {
        return failure(StatusCode::BAD_REQUEST, "경로 형식 오류");
    }
    let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "동시 요청 상한");
    };
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let _permit = permit;
        let storage = state.storage.lock().map_err(|_| "저장소 잠금 오류")?;
        let (receipt, bytes) = storage.get(&agent, &hash)?;
        verify_body(&bytes, &receipt)?;
        Ok(bytes)
    })
    .await;
    match result {
        Ok(Ok(bytes)) => (
            [("content-type", "application/octet-stream")],
            Body::from(bytes),
        )
            .into_response(),
        _ => failure(StatusCode::NOT_FOUND, "검증 가능한 보관 객체가 없습니다"),
    }
}
async fn receipt(
    State(state): State<AppState>,
    UrlPath((agent, hash)): UrlPath<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !admin(&state.config, &headers) {
        return failure(StatusCode::UNAUTHORIZED, "조회 토큰 인증 실패");
    }
    if !valid_id(&agent) || !valid_hash(&hash) {
        return failure(StatusCode::BAD_REQUEST, "경로 형식 오류");
    }
    let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "동시 요청 상한");
    };
    let result = tokio::task::spawn_blocking(move || -> Result<SignedReceipt> {
        let _permit = permit;
        let storage = state.storage.lock().map_err(|_| "저장소 잠금 오류")?;
        storage.get(&agent, &hash).map(|(receipt, _)| receipt)
    })
    .await;
    match result {
        Ok(Ok(receipt)) => Json(receipt).into_response(),
        _ => failure(StatusCode::NOT_FOUND, "검증 가능한 수신증명이 없습니다"),
    }
}
/// 전체 스캔 없이 메모리 계수와 현재 파일시스템 여유공간만 조회한다.
async fn usage(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !admin(&state.config, &headers) {
        return failure(StatusCode::UNAUTHORIZED, "조회 토큰 인증 실패");
    }
    let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "동시 요청 상한");
    };
    let result = tokio::task::spawn_blocking(move || -> Result<_> {
        let _permit = permit;
        let storage = state.storage.lock().map_err(|_| "저장소 잠금 오류")?;
        Ok(storage.capacity.usage())
    })
    .await;
    match result {
        Ok(Ok(usage)) => Json(usage).into_response(),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "보관 사용량 조회 실패"),
    }
}
impl Storage {
    fn directory(&self, agent: &str) -> Result<PathBuf> {
        let directory = self.config.dir.join(agent);
        if !directory.exists() {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&directory)?;
            sync_directory(&self.config.dir)?;
        }
        validate_private_directory(&directory)?;
        self.capacity.validate_directory(&directory)?;
        Ok(directory)
    }
    fn paths(&self, agent: &str, hash: &str) -> (PathBuf, PathBuf) {
        let dir = self.config.dir.join(agent);
        (
            dir.join(format!("{hash}.blob")),
            dir.join(format!("{hash}.receipt.json")),
        )
    }
    fn put(&mut self, agent: &str, hash: &str, kind: &str, bytes: &[u8]) -> Result<SignedReceipt> {
        let (object_path, receipt_path) = self.paths(agent, hash);
        // 이미 검증된 객체의 재전송은 사용량/여유공간이 가득 차도 유지한다.
        if receipt_path.exists() {
            let (existing, _) = match self.get(agent, hash) {
                Ok(existing) => existing,
                Err(error) => {
                    self.capacity.write_failed();
                    return Err(error);
                }
            };
            if existing.receipt.kind != kind || existing.receipt.size_bytes != bytes.len() as u64 {
                return Err("기존 수신증명 메타데이터와 충돌합니다".into());
            }
            if let Err(error) = sync_directory(receipt_path.parent().ok_or("보관 부모 없음")?)
            {
                self.capacity.write_failed();
                return Err(error);
            }
            return Ok(existing);
        }
        // 시작 후 관리 경로에 추가된 미완료 객체도 조용히 덮거나 수락하지 않는다.
        if object_path.symlink_metadata().is_ok() || receipt_path.symlink_metadata().is_ok() {
            self.capacity.write_failed();
            return Err(Box::new(CapacityRejection("incomplete_existing_object")));
        }
        self.capacity.reserve(agent, bytes.len() as u64)?;
        let result = (|| -> Result<SignedReceipt> {
            let directory = self.directory(agent)?;
            write_new(&object_path, bytes)?;
            let received_at_ms = now_ms();
            let receipt = sign(
                Receipt {
                    format: FORMAT.into(),
                    key_id: self.config.key_id.clone(),
                    agent_id: agent.into(),
                    kind: kind.into(),
                    sha256: hash.into(),
                    size_bytes: bytes.len() as u64,
                    received_at_ms,
                    retention_until_ms: received_at_ms
                        .checked_add(self.config.retention_secs * 1000)
                        .ok_or("보존 시각 초과")?,
                },
                &self.key,
            )?;
            write_receipt_new(&receipt_path, &receipt)?;
            sync_directory(&directory)?;
            Ok(receipt)
        })();
        match result {
            Ok(receipt) => {
                self.capacity.mark_receipted(agent);
                Ok(receipt)
            }
            Err(error) => {
                // 게시 실패 시 예약 계수를 되돌리지 않는다. 재시작 검증 전 신규 쓰기를
                // 막아 부분 게시/동기화 결과를 과소 계수하지 않는다. 기존 조회는 유지한다.
                self.capacity.write_failed();
                Err(error)
            }
        }
    }
    fn get(&self, agent: &str, hash: &str) -> Result<(SignedReceipt, Vec<u8>)> {
        // 읽기 API는 없는 디렉터리를 생성하지 않는다.
        validate_private_directory(&self.config.dir.join(agent))?;
        let (object_path, receipt_path) = self.paths(agent, hash);
        let receipt: SignedReceipt =
            serde_json::from_slice(&read_storage_file(&receipt_path, MAX_RECEIPT_BYTES)?)?;
        verify_receipt(&receipt, &hex::encode(self.key.verifying_key().to_bytes()))?;
        if receipt.receipt.agent_id != agent
            || receipt.receipt.sha256 != hash
            || receipt.receipt.key_id != self.config.key_id
        {
            return Err("저장된 증명의 신원이 다릅니다".into());
        }
        let bytes = read_storage_file(&object_path, self.config.max_object_bytes)?;
        verify_body(&bytes, &receipt)?;
        Ok((receipt, bytes))
    }
}
fn read_storage_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err("보관 파일은 현재 계정 소유 0600 단일 링크여야 합니다".into());
        }
    }
    read_bounded(path, maximum)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "quota_tests.rs"]
mod quota_tests;
