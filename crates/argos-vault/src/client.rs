use crate::*;

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
pub(crate) fn connection(
    config: &VaultConfig,
) -> Result<(reqwest::blocking::Client, reqwest::Url)> {
    let url = reqwest::Url::parse(&config.endpoint)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err("보관 주소에는 자격 증명·경로·질의·fragment를 넣을 수 없습니다".into());
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
        return Err(
            "HTTPS가 필요합니다. 시험용 HTTP는 명시적으로 허용한 숫자 loopback 주소만 지원합니다"
                .into(),
        );
    }
    public_key(&config.pinned_pubkey)?;
    if !valid_id(&config.key_id)
        || !(1..=MAX_OBJECT_BYTES).contains(&config.max_object_bytes)
        || config.timeout_secs == 0
        || config.timeout_secs > 300
    {
        return Err("클라이언트 키 ID·크기·시간 제한 설정 오류".into());
    }
    let mut builder = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(config.timeout_secs));
    // 명시적 loopback HTTP가 환경변수 프록시를 통해 외부로 전달되지 않게 한다.
    if url.scheme() == "http" {
        builder = builder.no_proxy();
    }
    let client = builder.build()?;
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
        return Err("인증 토큰은 16~4096바이트 비공백 값이어야 합니다".into());
    }
    Ok(value)
}
fn read_response(response: reqwest::blocking::Response, maximum: usize) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        // 원격 오류 본문이나 요청 자격 증명은 오류 문자열로 확산하지 않는다.
        return Err(format!("보관 서버 HTTP 상태: {}", response.status().as_u16()).into());
    }
    if response
        .content_length()
        .is_some_and(|size| size > maximum as u64)
    {
        return Err("서버 응답 크기 상한 초과".into());
    }
    let mut bytes = Vec::new();
    response.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("서버 응답 크기 상한 초과".into());
    }
    Ok(bytes)
}
fn expected(receipt: &SignedReceipt, config: &VaultConfig, agent: &str, hash: &str) -> Result<()> {
    verify_receipt(receipt, &config.pinned_pubkey)?;
    if receipt.receipt.key_id != config.key_id
        || receipt.receipt.agent_id != agent
        || receipt.receipt.sha256 != hash
    {
        return Err("보관 수신증명의 키 ID·에이전트·해시가 요청과 다릅니다".into());
    }
    Ok(())
}

/// 한 번 읽어 검증한 같은 바이트를 해시하고 전송한다.
pub fn upload_file(config: &VaultConfig, path: &Path, kind: &str) -> Result<SignedReceipt> {
    // 설정 검사를 먼저 수행하고, 한 번 읽어 안정성을 검사한 같은 바이트를 넘긴다.
    connection(config)?;
    let bytes = read_bounded(path, config.max_object_bytes)?;
    upload_bytes(config, bytes, kind)
}

/// 호출자가 스냅샷 해시를 확인한 바로 그 바이트를 전송한다. 경로를 다시 읽지 않는다.
pub(crate) fn upload_bytes(
    config: &VaultConfig,
    bytes: Vec<u8>,
    kind: &str,
) -> Result<SignedReceipt> {
    let (client, endpoint) = connection(config)?;
    if !valid_id(&config.agent_id) || !valid_kind(kind) || bytes.len() > config.max_object_bytes {
        return Err("에이전트 ID/보관 종류/본문 크기 오류".into());
    }
    let hash = sha256(&bytes);
    let size = bytes.len() as u64;
    let response = client
        .post(endpoint.join(&format!("v1/objects/{hash}"))?)
        .bearer_auth(token(&config.upload_token)?)
        .header("X-Argos-Kind", kind)
        .header("Content-Type", "application/octet-stream")
        .body(bytes)
        .send()?;
    let receipt: SignedReceipt =
        serde_json::from_slice(&read_response(response, MAX_RECEIPT_BYTES)?)?;
    expected(&receipt, config, &config.agent_id, &hash)?;
    if receipt.receipt.kind != kind || receipt.receipt.size_bytes != size {
        return Err("수신증명의 종류·크기가 전송한 내용과 다릅니다".into());
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
        return Err("에이전트 ID/해시 형식 오류".into());
    }
    if destination.symlink_metadata().is_ok() {
        return Err("출력 파일이 이미 존재합니다".into());
    }
    let receipt_response = client
        .get(endpoint.join(&format!("v1/receipts/{agent_id}/{hash}"))?)
        .bearer_auth(token(&config.admin_token)?)
        .send()?;
    let receipt: SignedReceipt =
        serde_json::from_slice(&read_response(receipt_response, MAX_RECEIPT_BYTES)?)?;
    expected(&receipt, config, agent_id, hash)?;
    if receipt.receipt.size_bytes > config.max_object_bytes as u64 {
        return Err("수신증명 크기가 클라이언트 상한을 초과합니다".into());
    }
    let response = client
        .get(endpoint.join(&format!("v1/objects/{agent_id}/{hash}"))?)
        .bearer_auth(token(&config.admin_token)?)
        .send()?;
    let bytes = read_response(response, config.max_object_bytes)?;
    verify_body(&bytes, &receipt)?;
    write_new(destination, &bytes)?;
    Ok(receipt)
}

/// 관리자용 용량 조회. TLS/대상 설정은 업로드와 같고 응답은 서명 수신증명이 아니다.
pub fn fetch_usage(config: &VaultConfig) -> Result<CapacityUsage> {
    let (client, endpoint) = connection(config)?;
    let response = client
        .get(endpoint.join("v1/usage")?)
        .bearer_auth(token(&config.admin_token)?)
        .send()?;
    Ok(serde_json::from_slice(&read_response(
        response,
        8 * 1024 * 1024,
    )?)?)
}
