use super::*;
use rand_core::{OsRng, RngCore};

fn private_new_dir(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, std::path::Component::ParentDir))
    {
        return Err("새 번들 경로는 .. 없는 절대 경로여야 합니다".into());
    }
    validate_private_directory(path.parent().ok_or("번들 부모 경로 없음")?)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    sync_directory(path.parent().unwrap())?;
    Ok(())
}
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    let stable =
        a.is_file() && b.is_file() && a.len() == b.len() && a.modified().ok() == b.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        stable
            && a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        stable
    }
}
fn parse_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| "번들 JSON 형식 오류".into())
}
pub fn read_manifest(path: &Path) -> Result<BundleManifest> {
    let manifest: BundleManifest = parse_json(&read_bounded(path, MAX_MANIFEST_BYTES)?)?;
    validate(&manifest)?;
    Ok(manifest)
}
/// 입력을 한 번 스트리밍하고 끝에 파일/경로 신원을 재검사한다. 실패 시 manifest는 게시하지 않는다.
pub fn prepare(source: &Path, stage: &Path, metadata: BundleMetadata) -> Result<BundleManifest> {
    let before_path = fs::symlink_metadata(source)?;
    if before_path.file_type().is_symlink() {
        return Err("입력 symlink 거부".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut input = options.open(source)?;
    let before = input.metadata()?;
    if !same(&before, &before_path) || before.len() == 0 || before.len() > MAX_BUNDLE_BYTES {
        return Err("번들 입력 신원/크기 오류(1바이트~1GiB)".into());
    }
    let mut random = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| "번들 ID 생성 실패")?;
    let mut manifest = BundleManifest {
        format: "argos-recovery-bundle-v1".into(),
        bundle_id: hex::encode(random),
        created_at_ms: now_ms(),
        metadata,
        sha256: "0".repeat(64),
        size_bytes: before.len(),
        chunks: vec![Chunk {
            sha256: "0".repeat(64),
            size_bytes: 1,
        }],
    };
    // 큰 입력을 쓰기 전에 메타데이터 상한부터 확인한다.
    if serde_json::to_vec(&manifest)?.len() > MAX_MANIFEST_BYTES
        || manifest
            .metadata
            .recovery_plan
            .as_ref()
            .is_some_and(|p| p.len() > 65536)
        || !Path::new(&manifest.metadata.original_path).is_absolute()
    {
        return Err("번들 메타데이터 오류".into());
    }
    private_new_dir(stage)?;
    private_new_dir(&stage.join("chunks"))?;
    let mut full = Sha256::new();
    let mut total = 0u64;
    manifest.chunks.clear();
    loop {
        let mut bytes = Vec::with_capacity(CHUNK_BYTES);
        (&mut input)
            .take(CHUNK_BYTES as u64)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() {
            break;
        }
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or("번들 크기 초과")?;
        if total > MAX_BUNDLE_BYTES || total > before.len() {
            return Err("입력이 읽는 중 커졌습니다".into());
        }
        full.update(&bytes);
        let hash = sha256(&bytes);
        let path = stage.join("chunks").join(format!("{hash}.bin"));
        if !path.exists() {
            write_new(&path, &bytes)?;
        }
        manifest.chunks.push(Chunk {
            sha256: hash,
            size_bytes: bytes.len() as u64,
        });
    }
    let after = input.metadata()?;
    let path_after = fs::symlink_metadata(source)?;
    if total != before.len()
        || !same(&before, &after)
        || !same(&before, &path_after)
        || path_after.file_type().is_symlink()
    {
        return Err("읽는 동안 입력 파일/경로 변경".into());
    }
    manifest.sha256 = hex::encode(full.finalize());
    validate(&manifest)?;
    write_new(
        &stage.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}
fn record_response(
    config: &VaultConfig,
    agent: &str,
    id: &str,
    response: reqwest::blocking::Response,
) -> Result<BundleRecord> {
    let record: BundleRecord =
        parse_json(&crate::client::read_response(response, 2 * 1024 * 1024)?)?;
    verify_record(&record, &config.pinned_pubkey, &config.key_id)?;
    if record.agent_id != agent || record.manifest.bundle_id != id {
        return Err("서버가 다른 번들을 반환했습니다".into());
    }
    Ok(record)
}
pub fn register_manifest(config: &VaultConfig, manifest: &BundleManifest) -> Result<BundleRecord> {
    validate(manifest)?;
    if !valid_id(&config.agent_id) {
        return Err("에이전트 ID 오류".into());
    }
    let (client, url) = crate::client::connection(config)?;
    let record = record_response(
        config,
        &config.agent_id,
        &manifest.bundle_id,
        client
            .post(url.join("v1/bundles")?)
            .bearer_auth(crate::client::token(&config.upload_token)?)
            .json(manifest)
            .send()
            .map_err(crate::client::transport_error)?,
    )?;
    if record.manifest != *manifest {
        return Err("등록 응답 manifest가 요청과 다릅니다".into());
    }
    Ok(record)
}
pub fn complete(config: &VaultConfig, bundle_id: &str) -> Result<BundleRecord> {
    if !valid_bundle_id(bundle_id) || !valid_id(&config.agent_id) {
        return Err("번들/에이전트 ID 오류".into());
    }
    let (client, url) = crate::client::connection(config)?;
    let record = record_response(
        config,
        &config.agent_id,
        bundle_id,
        client
            .post(url.join(&format!("v1/bundles/{bundle_id}/complete"))?)
            .bearer_auth(crate::client::token(&config.upload_token)?)
            .send()
            .map_err(crate::client::transport_error)?,
    )?;
    if record.completion.is_none() {
        return Err("서버가 번들 완료를 확인하지 않았습니다".into());
    }
    Ok(record)
}
pub fn upload_prepared(config: &VaultConfig, stage: &Path) -> Result<BundleRecord> {
    validate_private_directory(stage)?;
    validate_private_directory(&stage.join("chunks"))?;
    let manifest = read_manifest(&stage.join("manifest.json"))?;
    register_manifest(config, &manifest)?;
    for chunk in &manifest.chunks {
        let bytes = read_bounded(
            &stage.join("chunks").join(format!("{}.bin", chunk.sha256)),
            CHUNK_BYTES,
        )?;
        if bytes.len() as u64 != chunk.size_bytes || sha256(&bytes) != chunk.sha256 {
            return Err("준비된 청크 내용 불일치".into());
        }
        crate::client::upload_bytes(config, bytes, "backup")?;
    }
    let record = complete(config, &manifest.bundle_id)?;
    if record.manifest != manifest {
        return Err("완료 응답 manifest가 준비한 번들과 다릅니다".into());
    }
    Ok(record)
}
pub fn get(config: &VaultConfig, agent: &str, bundle_id: &str) -> Result<BundleRecord> {
    if !valid_id(agent) || !valid_bundle_id(bundle_id) {
        return Err("번들/에이전트 ID 오류".into());
    }
    let (client, url) = crate::client::connection(config)?;
    record_response(
        config,
        agent,
        bundle_id,
        client
            .get(url.join(&format!("v1/bundles/{agent}/{bundle_id}"))?)
            .bearer_auth(crate::client::token(&config.admin_token)?)
            .send()
            .map_err(crate::client::transport_error)?,
    )
}
pub fn list(
    config: &VaultConfig,
    agent: &str,
    after: Option<&str>,
    limit: usize,
) -> Result<BundleList> {
    if !valid_id(agent)
        || !(1..=100).contains(&limit)
        || after.is_some_and(|id| !valid_bundle_id(id))
    {
        return Err("번들 목록 범위 오류".into());
    }
    let (client, mut url) = crate::client::connection(config)?;
    url = url.join(&format!("v1/bundles/{agent}"))?;
    url.query_pairs_mut()
        .append_pair("limit", &limit.to_string());
    if let Some(after) = after {
        url.query_pairs_mut().append_pair("after", after);
    }
    let page: BundleList = parse_json(&crate::client::read_response(
        client
            .get(url)
            .bearer_auth(crate::client::token(&config.admin_token)?)
            .send()
            .map_err(crate::client::transport_error)?,
        2 * 1024 * 1024,
    )?)?;
    validate_page(&page, agent, after, limit)?;
    Ok(page)
}

fn validate_page(page: &BundleList, agent: &str, after: Option<&str>, limit: usize) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    for id in page
        .items
        .iter()
        .map(|item| &item.bundle_id)
        .chain(page.unavailable.iter().map(|item| &item.bundle_id))
    {
        if !valid_bundle_id(id)
            || after.is_some_and(|cursor| id.as_str() <= cursor)
            || !ids.insert(id.as_str())
        {
            return Err("번들 목록 ID/범위/중복 오류".into());
        }
    }
    if page.agent_id != agent
        || ids.len() > limit
        || page
            .unavailable
            .iter()
            .any(|item| item.reason != "bundle_state_unavailable")
        || page.items.iter().any(|item| {
            !valid_hash(&item.sha256)
                || !(1..=MAX_BUNDLE_BYTES).contains(&item.size_bytes)
                || !matches!(item.current_review.as_str(), "unknown" | "good" | "revoked")
                || item.recommended != (item.complete && item.current_review == "good")
        })
        || page
            .next_cursor
            .as_deref()
            .is_some_and(|cursor| !valid_bundle_id(cursor) || ids.last().copied() != Some(cursor))
    {
        return Err("번들 목록 응답 범위/상태 오류".into());
    }
    Ok(())
}

#[cfg(test)]
mod page_tests {
    use super::*;

    #[test]
    fn unavailable_entries_share_the_page_budget_and_cannot_repeat_or_rewind() {
        let id = "a".repeat(32);
        let mut page = BundleList {
            agent_id: "agent".into(),
            items: vec![],
            next_cursor: Some(id.clone()),
            unavailable: vec![UnavailableBundle {
                bundle_id: id.clone(),
                reason: "bundle_state_unavailable".into(),
            }],
        };
        assert!(validate_page(&page, "agent", None, 1).is_ok());
        assert!(validate_page(&page, "agent", Some(&id), 1).is_err());
        assert!(validate_page(&page, "agent", None, 0).is_err());
        page.unavailable.push(page.unavailable[0].clone());
        assert!(validate_page(&page, "agent", None, 2).is_err());
        page.unavailable.pop();
        page.next_cursor = Some("b".repeat(32));
        assert!(validate_page(&page, "agent", None, 1).is_err());
        page.next_cursor = None;
        page.unavailable[0].reason = "remote-untrusted-detail".into();
        assert!(validate_page(&page, "agent", None, 1).is_err());
    }
}
pub fn review(
    config: &VaultConfig,
    agent: &str,
    bundle_id: &str,
    request: &ReviewRequest,
) -> Result<BundleRecord> {
    validate_review(request)?;
    if !valid_id(agent) || !valid_bundle_id(bundle_id) {
        return Err("번들/에이전트 ID 오류".into());
    }
    let (client, url) = crate::client::connection(config)?;
    let record = record_response(
        config,
        agent,
        bundle_id,
        client
            .post(url.join(&format!("v1/bundles/{agent}/{bundle_id}/reviews"))?)
            .bearer_auth(crate::client::token(&config.admin_token)?)
            .json(request)
            .send()
            .map_err(crate::client::transport_error)?,
    )?;
    if !record.reviews.iter().any(|r| r.value.request == *request) {
        return Err("검토 요청 적용 증명이 없습니다".into());
    }
    Ok(record)
}
/// 새 0700 부모의 새 0600 파일로만 게시한다. 원본 경로는 목적지로 사용하지 않는다.
pub fn fetch(
    config: &VaultConfig,
    agent: &str,
    bundle_id: &str,
    destination: &Path,
    evidence_only: bool,
) -> Result<BundleRecord> {
    let record = get(config, agent, bundle_id)?;
    if record.completion.is_none() || (!evidence_only && !record.recommended) {
        return Err("완료된 원격 정상 판정이 없어 복구를 보류합니다".into());
    }
    let parent = destination.parent().ok_or("복구 부모 경로 없음")?;
    validate_private_directory(parent)?;
    if fs::symlink_metadata(destination).is_ok() {
        return Err("복구 파일은 새 경로여야 합니다".into());
    }
    let mut random = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| "임시 이름 생성 실패")?;
    let temporary = parent.join(format!(".argos-bundle-{}.tmp", hex::encode(random)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut out = options.open(&temporary)?;
    let result = (|| -> Result<BundleRecord> {
        let (client, url) = crate::client::connection(config)?;
        let token = crate::client::token(&config.admin_token)?;
        let mut full = Sha256::new();
        let mut total = 0u64;
        for chunk in &record.manifest.chunks {
            let receipt: SignedReceipt = parse_json(&crate::client::read_response(
                client
                    .get(url.join(&format!("v1/receipts/{agent}/{}", chunk.sha256))?)
                    .bearer_auth(token)
                    .send()
                    .map_err(crate::client::transport_error)?,
                MAX_RECEIPT_BYTES,
            )?)?;
            verify_receipt(&receipt, &config.pinned_pubkey)?;
            if receipt.receipt.agent_id != agent
                || receipt.receipt.key_id != config.key_id
                || receipt.receipt.kind != "backup"
                || receipt.receipt.sha256 != chunk.sha256
                || receipt.receipt.size_bytes != chunk.size_bytes
            {
                return Err("청크 수신증명 불일치".into());
            }
            let bytes = crate::client::read_response(
                client
                    .get(url.join(&format!("v1/objects/{agent}/{}", chunk.sha256))?)
                    .bearer_auth(token)
                    .send()
                    .map_err(crate::client::transport_error)?,
                CHUNK_BYTES,
            )?;
            verify_body(&bytes, &receipt)?;
            full.update(&bytes);
            total += bytes.len() as u64;
            out.write_all(&bytes)?;
        }
        if total != record.manifest.size_bytes
            || hex::encode(full.finalize()) != record.manifest.sha256
        {
            return Err("재조립 전체 해시/크기 불일치".into());
        }
        // 전송 중 판정 취소·카탈로그 공백이 생기면 최종 경로 게시를 보류한다.
        let latest = get(config, agent, bundle_id)?;
        if latest.manifest != record.manifest
            || latest.completion != record.completion
            || (!evidence_only && !latest.recommended)
        {
            return Err("복구 전송 중 정상 판정/완료 상태 변경".into());
        }
        out.sync_all()?;
        fs::hard_link(&temporary, destination)?;
        fs::remove_file(&temporary)?;
        sync_directory(parent)?;
        Ok(latest)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
