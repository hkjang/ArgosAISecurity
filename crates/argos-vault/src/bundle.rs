//! 원본 호스트 없이 조회·재조립하는 분할 복구 번들. 정상 판정은 원격 관리자 이력만 사용한다.
use crate::*;

mod client;
pub use client::{
    complete, fetch, get, list, prepare, read_manifest, register_manifest, review, upload_prepared,
};

pub const CHUNK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub(crate) const MAX_REVIEWS: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BundleMetadata {
    pub original_path: String,
    pub version: Option<i64>,
    /// 원본 서버의 주장이다. 원격 정상 판정으로 승격하지 않는다.
    pub review_history: serde_json::Value,
    pub recovery_plan: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub sha256: String,
    pub size_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub format: String,
    pub bundle_id: String,
    pub created_at_ms: u64,
    pub metadata: BundleMetadata,
    pub sha256: String,
    pub size_bytes: u64,
    pub chunks: Vec<Chunk>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Good,
    Revoked,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequest {
    pub request_id: String,
    pub decision: ReviewDecision,
    pub actor: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    pub format: String,
    pub key_id: String,
    pub agent_id: String,
    pub bundle_id: String,
    pub manifest_sha256: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub completed_at_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReviewEvent {
    pub format: String,
    pub key_id: String,
    pub agent_id: String,
    pub bundle_id: String,
    pub manifest_sha256: String,
    pub completion_sha256: String,
    pub sequence: u32,
    pub previous_sha256: Option<String>,
    pub reviewed_at_ms: u64,
    pub request: ReviewRequest,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub value: T,
    pub signature_hex: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRecord {
    pub agent_id: String,
    pub manifest: BundleManifest,
    pub manifest_receipt: SignedReceipt,
    pub completion: Option<Signed<Completion>>,
    pub reviews: Vec<Signed<ReviewEvent>>,
    pub current_review: String,
    pub recommended: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSummary {
    pub bundle_id: String,
    pub original_path: String,
    pub version: Option<i64>,
    pub sha256: String,
    pub size_bytes: u64,
    pub complete: bool,
    pub current_review: String,
    pub recommended: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleList {
    pub agent_id: String,
    pub items: Vec<BundleSummary>,
    pub next_cursor: Option<String>,
}

pub(crate) fn valid_bundle_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn validate(manifest: &BundleManifest) -> Result<()> {
    let bytes = serde_json::to_vec(manifest)?;
    if manifest.format != "argos-recovery-bundle-v1"
        || !valid_bundle_id(&manifest.bundle_id)
        || !valid_hash(&manifest.sha256)
        || manifest.size_bytes == 0
        || manifest.size_bytes > MAX_BUNDLE_BYTES
        || manifest.metadata.original_path.is_empty()
        || manifest.metadata.original_path.len() > 4096
        || !Path::new(&manifest.metadata.original_path).is_absolute()
        || manifest
            .metadata
            .recovery_plan
            .as_ref()
            .is_some_and(|p| p.len() > 65536)
        || manifest.chunks.is_empty()
        || manifest.chunks.len() > 64
        || bytes.len() > MAX_MANIFEST_BYTES
    {
        return Err("복구 번들 형식/크기/원본 경로 오류".into());
    }
    let mut total = 0u64;
    for (i, chunk) in manifest.chunks.iter().enumerate() {
        if !valid_hash(&chunk.sha256)
            || chunk.size_bytes == 0
            || chunk.size_bytes > CHUNK_BYTES as u64
            || (i + 1 < manifest.chunks.len() && chunk.size_bytes != CHUNK_BYTES as u64)
        {
            return Err("번들 청크 크기/해시 오류".into());
        }
        total = total
            .checked_add(chunk.size_bytes)
            .ok_or("번들 크기 초과")?;
    }
    if total != manifest.size_bytes {
        return Err("번들 전체 크기 불일치".into());
    }
    Ok(())
}
pub(crate) fn sign_value<T: Serialize>(value: T, key: &SigningKey) -> Result<Signed<T>> {
    let signature_hex = hex::encode(key.sign(&serde_json::to_vec(&value)?).to_bytes());
    Ok(Signed {
        value,
        signature_hex,
    })
}
fn verify_value<T: Serialize>(value: &Signed<T>, key: &str) -> Result<()> {
    let signature: [u8; 64] = hex::decode(&value.signature_hex)?
        .try_into()
        .map_err(|_| "번들 서명 길이 오류")?;
    public_key(key)?.verify(
        &serde_json::to_vec(&value.value)?,
        &Signature::from_bytes(&signature),
    )?;
    Ok(())
}
pub(crate) fn validate_review(request: &ReviewRequest) -> Result<()> {
    if !valid_id(&request.request_id)
        || request.actor.trim().is_empty()
        || request.actor.len() > 256
        || request.reason.trim().is_empty()
        || request.reason.len() > 4096
    {
        return Err("검토 요청 ID/담당자/근거 오류".into());
    }
    Ok(())
}
/// 서명·원본 결합·순서와 파생 상태를 대조한다. 최신성은 인증된 서버의 현재 조회에 의존한다.
pub fn verify_record(record: &BundleRecord, key: &str, key_id: &str) -> Result<()> {
    validate(&record.manifest)?;
    if !valid_id(&record.agent_id) || record.reviews.len() > MAX_REVIEWS {
        return Err("번들 범위/검토 상한 오류".into());
    }
    let manifest_bytes = serde_json::to_vec(&record.manifest)?;
    let manifest_hash = sha256(&manifest_bytes);
    verify_receipt(&record.manifest_receipt, key)?;
    let r = &record.manifest_receipt.receipt;
    if r.agent_id != record.agent_id
        || r.sha256 != manifest_hash
        || r.key_id != key_id
        || r.kind != "bundle-manifest"
        || r.size_bytes != manifest_bytes.len() as u64
    {
        return Err("번들 manifest 수신증명 불일치".into());
    }
    let mut state = "unknown";
    if let Some(completion) = &record.completion {
        verify_value(completion, key)?;
        let c = &completion.value;
        if c.format != "argos-bundle-completion-v1"
            || c.key_id != key_id
            || c.agent_id != record.agent_id
            || c.bundle_id != record.manifest.bundle_id
            || c.manifest_sha256 != manifest_hash
            || c.sha256 != record.manifest.sha256
            || c.size_bytes != record.manifest.size_bytes
        {
            return Err("번들 완료 증명 불일치".into());
        }
        let completion_hash = sha256(&serde_json::to_vec(completion)?);
        let mut previous = None;
        for (i, event) in record.reviews.iter().enumerate() {
            verify_value(event, key)?;
            let e = &event.value;
            validate_review(&e.request)?;
            if e.format != "argos-bundle-review-v1"
                || e.key_id != key_id
                || e.agent_id != record.agent_id
                || e.bundle_id != record.manifest.bundle_id
                || e.manifest_sha256 != manifest_hash
                || e.completion_sha256 != completion_hash
                || e.sequence != i as u32 + 1
                || e.previous_sha256 != previous
            {
                return Err("번들 검토 이력 결합/순서 오류".into());
            }
            previous = Some(sha256(&serde_json::to_vec(event)?));
            state = match e.request.decision {
                ReviewDecision::Good => "good",
                ReviewDecision::Revoked => "revoked",
            };
        }
    } else if !record.reviews.is_empty() {
        return Err("미완료 번들의 정상 판정은 허용하지 않습니다".into());
    }
    if record.current_review != state
        || record.recommended != (state == "good" && record.completion.is_some())
    {
        return Err("번들 추천/정상 판정 상태 불일치".into());
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
