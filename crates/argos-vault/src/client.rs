use crate::*;

// 외부 오류는 보관하지 않는다. 원격 본문·URL·토큰이 Debug/source에도 남지 않게 한다.
#[derive(Debug, Clone, Copy)]
enum ClientError {
    Authentication(u16),
    Capacity,
    RateLimit,
    ServerTransient(u16),
    RequestRejected(u16),
    Transport,
    Connect,
    Timeout,
    ResponseIntegrity,
    ClientSettings,
    SnapshotRead,
}
impl ClientError {
    fn code(self) -> &'static str {
        match self {
            Self::Authentication(_) => "authentication",
            Self::Capacity => "capacity",
            Self::RateLimit => "rate_limit",
            Self::ServerTransient(_) => "server_transient",
            Self::RequestRejected(_) => "request_rejected",
            Self::Transport => "transport",
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::ResponseIntegrity => "response_integrity",
            Self::ClientSettings => "client_settings",
            Self::SnapshotRead => "snapshot_read",
        }
    }
}
impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "보관 클라이언트 오류: {}", self.code())?;
        match self {
            Self::Authentication(status)
            | Self::ServerTransient(status)
            | Self::RequestRejected(status) => write!(f, " (HTTP {status})"),
            Self::Capacity => write!(f, " (HTTP 507)"),
            Self::RateLimit => write!(f, " (HTTP 429)"),
            _ => Ok(()),
        }
    }
}
impl std::error::Error for ClientError {}

pub(crate) fn error_code(error: &(dyn std::error::Error + Send + Sync + 'static)) -> &'static str {
    error
        .downcast_ref::<ClientError>()
        .map_or("unknown", |error| error.code())
}

fn request_error(error: &reqwest::Error) -> ClientError {
    if error.is_timeout() {
        ClientError::Timeout
    } else if error.is_connect() {
        ClientError::Connect
    } else {
        ClientError::Transport
    }
}

pub(crate) fn transport_error(error: reqwest::Error) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(request_error(&error))
}

fn body_error(error: std::io::Error) -> ClientError {
    if error.kind() == std::io::ErrorKind::TimedOut {
        ClientError::Timeout
    } else if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<reqwest::Error>())
    {
        request_error(error)
    } else {
        ClientError::Transport
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VaultConfig {
    pub endpoint: String,
    pub agent_id: String,
    pub upload_token: String,
    pub admin_token: String,
    pub pinned_pubkey: String,
    pub key_id: String,
    pub allow_http_loopback: bool,
    /// 사설 PKI를 위한 명시적 PEM 신뢰 목록. 지정하면 내장 CA 대신 이 목록만 사용한다.
    pub tls_ca_pem: Option<String>,
    pub max_object_bytes: usize,
    pub timeout_secs: u64,
}
impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            agent_id: String::new(),
            upload_token: String::new(),
            admin_token: String::new(),
            pinned_pubkey: String::new(),
            key_id: "vault-1".into(),
            allow_http_loopback: false,
            tls_ca_pem: None,
            max_object_bytes: MAX_OBJECT_BYTES,
            timeout_secs: 30,
        }
    }
}
impl std::fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("agent_id", &self.agent_id)
            .field("key_id", &self.key_id)
            .field("endpoint_and_tokens", &"[REDACTED]")
            .finish()
    }
}
pub(crate) fn validated_endpoint(config: &VaultConfig) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(&config.endpoint).map_err(|_| ClientError::ClientSettings)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ClientError::ClientSettings.into());
    }
    let loopback = url
        .host_str()
        .and_then(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|ip| ip.is_loopback());
    if url.scheme() != "https"
        && !(url.scheme() == "http" && config.allow_http_loopback && loopback)
    {
        return Err(ClientError::ClientSettings.into());
    }
    if config.tls_ca_pem.is_some() && url.scheme() != "https" {
        return Err(ClientError::ClientSettings.into());
    }
    tls_certificates(config)?;
    public_key(&config.pinned_pubkey).map_err(|_| ClientError::ClientSettings)?;
    if !valid_id(&config.key_id)
        || !(1..=MAX_OBJECT_BYTES).contains(&config.max_object_bytes)
        || config.timeout_secs == 0
        || config.timeout_secs > 300
    {
        return Err(ClientError::ClientSettings.into());
    }
    Ok(url)
}

fn tls_certificates(config: &VaultConfig) -> Result<Vec<reqwest::Certificate>> {
    let Some(pem) = &config.tls_ca_pem else {
        return Ok(Vec::new());
    };
    if pem.is_empty() || pem.len() > 64 * 1024 {
        return Err(ClientError::ClientSettings.into());
    }
    let certificates = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
        .map_err(|_| ClientError::ClientSettings)?;
    if certificates.is_empty() || certificates.len() > 16 {
        return Err(ClientError::ClientSettings.into());
    }
    Ok(certificates)
}

/// 임대/재시도 중 TLS 신뢰 대상을 바꾸어 토큰과 스냅샷을 다른 서버에 보내지 않는다.
pub(crate) fn tls_ca_sha256(config: &VaultConfig) -> Result<Option<String>> {
    tls_certificates(config)?;
    Ok(config.tls_ca_pem.as_ref().map(|pem| sha256(pem.as_bytes())))
}
pub(crate) fn connection(
    config: &VaultConfig,
) -> Result<(reqwest::blocking::Client, reqwest::Url)> {
    let url = validated_endpoint(config)?;
    let mut builder = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(config.timeout_secs));
    if config.tls_ca_pem.is_some() {
        builder = builder.tls_built_in_root_certs(false);
        for certificate in tls_certificates(config)? {
            builder = builder.add_root_certificate(certificate);
        }
    }
    // 명시적 loopback HTTP가 환경변수 프록시를 통해 외부로 전달되지 않게 한다.
    if url.scheme() == "http" {
        builder = builder.no_proxy();
    }
    let client = builder.build().map_err(|_| ClientError::ClientSettings)?;
    Ok((client, url))
}
pub(crate) fn token(value: &str) -> Result<&str> {
    if value.trim() != value
        || value.len() < 16
        || value.len() > 4096
        || value
            .bytes()
            .any(|b| !b.is_ascii() || b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(ClientError::ClientSettings.into());
    }
    Ok(value)
}
pub(crate) fn read_response(
    response: reqwest::blocking::Response,
    maximum: usize,
) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        // 원격 오류 본문이나 요청 자격 증명은 오류 문자열로 확산하지 않는다.
        let status = response.status().as_u16();
        let error = match status {
            401 | 403 => ClientError::Authentication(status),
            507 => ClientError::Capacity,
            429 => ClientError::RateLimit,
            500..=599 => ClientError::ServerTransient(status),
            _ => ClientError::RequestRejected(status),
        };
        return Err(error.into());
    }
    if response
        .content_length()
        .is_some_and(|size| size > maximum as u64)
    {
        return Err(ClientError::ResponseIntegrity.into());
    }
    let mut bytes = Vec::new();
    response
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(body_error)?;
    if bytes.len() > maximum {
        return Err(ClientError::ResponseIntegrity.into());
    }
    Ok(bytes)
}
fn expected(receipt: &SignedReceipt, config: &VaultConfig, agent: &str, hash: &str) -> Result<()> {
    verify_receipt(receipt, &config.pinned_pubkey).map_err(|_| ClientError::ResponseIntegrity)?;
    if receipt.receipt.key_id != config.key_id
        || receipt.receipt.agent_id != agent
        || receipt.receipt.sha256 != hash
    {
        return Err(ClientError::ResponseIntegrity.into());
    }
    Ok(())
}

/// 한 번 읽어 검증한 같은 바이트를 해시하고 전송한다.
pub fn upload_file(config: &VaultConfig, path: &Path, kind: &str) -> Result<SignedReceipt> {
    // 설정 검사를 먼저 수행하고, 한 번 읽어 안정성을 검사한 같은 바이트를 넘긴다.
    let (client, endpoint) = connection(config)?;
    let bytes =
        read_bounded(path, config.max_object_bytes).map_err(|_| ClientError::SnapshotRead)?;
    upload_connected(config, bytes, kind, client, endpoint)
}

/// 호출자가 스냅샷 해시를 확인한 바로 그 바이트를 전송한다. 경로를 다시 읽지 않는다.
pub(crate) fn upload_bytes(
    config: &VaultConfig,
    bytes: Vec<u8>,
    kind: &str,
) -> Result<SignedReceipt> {
    let (client, endpoint) = connection(config)?;
    upload_connected(config, bytes, kind, client, endpoint)
}

fn upload_connected(
    config: &VaultConfig,
    bytes: Vec<u8>,
    kind: &str,
    client: reqwest::blocking::Client,
    endpoint: reqwest::Url,
) -> Result<SignedReceipt> {
    if !valid_id(&config.agent_id) || !valid_kind(kind) || bytes.len() > config.max_object_bytes {
        return Err(ClientError::ClientSettings.into());
    }
    let hash = sha256(&bytes);
    let size = bytes.len() as u64;
    let response = client
        .post(
            endpoint
                .join(&format!("v1/objects/{hash}"))
                .map_err(|_| ClientError::ClientSettings)?,
        )
        .bearer_auth(token(&config.upload_token)?)
        .header("X-Argos-Kind", kind)
        .header("Content-Type", "application/octet-stream")
        .body(bytes)
        .send()
        .map_err(|error| request_error(&error))?;
    let receipt: SignedReceipt =
        serde_json::from_slice(&read_response(response, MAX_RECEIPT_BYTES)?)
            .map_err(|_| ClientError::ResponseIntegrity)?;
    expected(&receipt, config, &config.agent_id, &hash)?;
    if receipt.receipt.kind != kind || receipt.receipt.size_bytes != size {
        return Err(ClientError::ResponseIntegrity.into());
    }
    Ok(receipt)
}

/// 관리자 조회 토큰으로 받아 고정 키/본문을 검증한 뒤 새 파일로만 복원한다.
pub fn fetch_file(
    config: &VaultConfig,
    agent_id: &str,
    hash: &str,
    destination: &Path,
) -> Result<SignedReceipt> {
    let (client, endpoint) = connection(config)?;
    if !valid_id(agent_id) || !valid_hash(hash) {
        return Err(ClientError::ClientSettings.into());
    }
    if destination.symlink_metadata().is_ok() {
        return Err("출력 파일이 이미 존재합니다".into());
    }
    let receipt_response = client
        .get(
            endpoint
                .join(&format!("v1/receipts/{agent_id}/{hash}"))
                .map_err(|_| ClientError::ClientSettings)?,
        )
        .bearer_auth(token(&config.admin_token)?)
        .send()
        .map_err(|error| request_error(&error))?;
    let receipt: SignedReceipt =
        serde_json::from_slice(&read_response(receipt_response, MAX_RECEIPT_BYTES)?)
            .map_err(|_| ClientError::ResponseIntegrity)?;
    expected(&receipt, config, agent_id, hash)?;
    if receipt.receipt.size_bytes > config.max_object_bytes as u64 {
        return Err(ClientError::ResponseIntegrity.into());
    }
    let response = client
        .get(
            endpoint
                .join(&format!("v1/objects/{agent_id}/{hash}"))
                .map_err(|_| ClientError::ClientSettings)?,
        )
        .bearer_auth(token(&config.admin_token)?)
        .send()
        .map_err(|error| request_error(&error))?;
    let bytes = read_response(response, config.max_object_bytes)?;
    verify_body(&bytes, &receipt).map_err(|_| ClientError::ResponseIntegrity)?;
    write_new(destination, &bytes)?;
    Ok(receipt)
}

/// 관리자용 용량 조회. TLS/대상 설정은 업로드와 같고 응답은 서명 수신증명이 아니다.
pub fn fetch_usage(config: &VaultConfig) -> Result<CapacityUsage> {
    let (client, endpoint) = connection(config)?;
    let response = client
        .get(
            endpoint
                .join("v1/usage")
                .map_err(|_| ClientError::ClientSettings)?,
        )
        .bearer_auth(token(&config.admin_token)?)
        .send()
        .map_err(|error| request_error(&error))?;
    Ok(
        serde_json::from_slice(&read_response(response, 8 * 1024 * 1024)?)
            .map_err(|_| ClientError::ResponseIntegrity)?,
    )
}

#[cfg(test)]
mod tests;
