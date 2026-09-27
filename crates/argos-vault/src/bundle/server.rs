//! 기존 단일 작성자 잠금과 객체 quota 안에서 manifest·완료·검토를 추가 게시한다.
use super::*;
use crate::bundle::*;
use axum::extract::Query;
use rusqlite::{params, Connection, OptionalExtension};

const CATALOG: &str = ".argos-bundles.sqlite3";
const MARKER: &str = ".argos-bundles.ready";
const MAX_BUNDLES: u64 = 10000;
struct Catalog(Connection);
impl Catalog {
    fn open(storage: &Storage, create: bool) -> Result<Option<Self>> {
        let db = storage.config.dir.join(CATALOG);
        let marker = storage.config.dir.join(MARKER);
        let exists = fs::symlink_metadata(&db).is_ok();
        let marked = fs::symlink_metadata(&marker).is_ok();
        if !exists && !marked {
            let usage = storage.capacity.usage();
            if storage.capacity.bundle_control_objects > 0
                || !usage.reconstruction_complete
                || !usage.storage_consistent
            {
                return Err("번들 제어 객체와 카탈로그 상태 불일치: 자동 초기화 거부".into());
            }
            if !create {
                return Ok(None);
            }
            write_new(&db, &[])?;
            let conn = Connection::open(&db)?;
            conn.pragma_update(None, "journal_mode", "DELETE")?;
            conn.pragma_update(None, "synchronous", "FULL")?;
            conn.execute_batch("BEGIN IMMEDIATE;
CREATE TABLE bundles(agent TEXT NOT NULL,id TEXT NOT NULL,manifest_hash TEXT NOT NULL,completion_hash TEXT,PRIMARY KEY(agent,id));
CREATE TABLE reviews(agent TEXT NOT NULL,bundle TEXT NOT NULL,sequence INTEGER NOT NULL,hash TEXT NOT NULL,request_id TEXT NOT NULL,PRIMARY KEY(agent,bundle,sequence),UNIQUE(agent,bundle,request_id));
CREATE TABLE intents(agent TEXT NOT NULL,bundle TEXT NOT NULL,operation TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(agent,bundle,operation));
PRAGMA user_version=1;
COMMIT;")?;
            write_new(&marker, b"argos-bundle-catalog-v1")?;
            return Ok(Some(Self(conn)));
        }
        if !exists || !marked {
            return Err("번들 카탈로그 초기화/유실 흔적: 수동 점검 필요".into());
        }
        if read_storage_file(&marker, 64)? != b"argos-bundle-catalog-v1" {
            return Err("번들 카탈로그 표식 오류".into());
        }
        // DB 전체를 메모리에 읽지 않고 파일 경계와 SQLite 구조를 검사한다.
        let meta = fs::symlink_metadata(&db)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o777 != 0o600
                || meta.nlink() != 1
            {
                return Err("카탈로그 파일 권한 오류".into());
            }
        }
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("카탈로그 일반 파일 필요".into());
        }
        let conn = Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.busy_timeout(std::time::Duration::from_secs(2))?;
        let version: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let check: String = conn.query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
        if version != 1 || check != "ok" {
            return Err("카탈로그 형식/무결성 오류".into());
        }
        conn.prepare("SELECT agent,id,manifest_hash,completion_hash FROM bundles LIMIT 0")?;
        conn.prepare("SELECT agent,bundle,sequence,hash,request_id FROM reviews LIMIT 0")?;
        conn.prepare("SELECT agent,bundle,operation,payload FROM intents LIMIT 0")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(Some(Self(conn)))
    }
    fn intent(&self, agent: &str, id: &str, operation: &str, proposed: Vec<u8>) -> Result<Vec<u8>> {
        let old: Option<String> = self
            .0
            .query_row(
                "SELECT payload FROM intents WHERE agent=?1 AND bundle=?2 AND operation=?3",
                params![agent, id, operation],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            if old.len() > MAX_MANIFEST_BYTES {
                return Err("게시 의도 크기 오류".into());
            }
            return Ok(old.into_bytes());
        }
        let text = String::from_utf8(proposed)?;
        self.0.execute(
            "INSERT INTO intents(agent,bundle,operation,payload) VALUES(?1,?2,?3,?4)",
            params![agent, id, operation, text],
        )?;
        Ok(text.into_bytes())
    }
    fn coverage(&self, storage: &Storage) -> Result<()> {
        let refs:u64=self.0.query_row("SELECT (SELECT COUNT(*)+COUNT(completion_hash) FROM bundles)+(SELECT COUNT(*) FROM reviews)",[],|r|r.get(0))?;
        let usage = storage.capacity.usage();
        if refs != storage.capacity.bundle_control_objects
            || !usage.reconstruction_complete
            || !usage.storage_consistent
        {
            return Err("번들 제어 객체/카탈로그 불일치: 완료/정상 판정 조회 보류".into());
        }
        Ok(())
    }
    fn record(&self, storage: &Storage, agent: &str, id: &str) -> Result<BundleRecord> {
        let pending: Option<String> = self
            .0
            .query_row(
                "SELECT payload FROM intents WHERE agent=?1 AND bundle=?2 AND operation='review'",
                params![agent, id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(pending) = pending {
            let event: Signed<ReviewEvent> = serde_json::from_str(&pending)?;
            if event.value.request.decision == ReviewDecision::Revoked {
                return Err("정상 판정 취소가 게시 대기 중이므로 복구/추천을 보류합니다".into());
            }
        }
        self.record_raw(storage, agent, id)
    }
    fn record_raw(&self, storage: &Storage, agent: &str, id: &str) -> Result<BundleRecord> {
        let (manifest_hash, completion_hash): (String, Option<String>) = self.0.query_row(
            "SELECT manifest_hash,completion_hash FROM bundles WHERE agent=?1 AND id=?2",
            params![agent, id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (manifest_receipt, bytes) = storage.get(agent, &manifest_hash)?;
        let manifest: BundleManifest = serde_json::from_slice(&bytes)?;
        if manifest.bundle_id != id {
            return Err("manifest 카탈로그 ID 불일치".into());
        }
        let completion = completion_hash
            .map(|hash| -> Result<Signed<Completion>> {
                let (r, bytes) = storage.get(agent, &hash)?;
                if r.receipt.kind != "bundle-completion" {
                    return Err("완료 객체 종류 오류".into());
                }
                Ok(serde_json::from_slice(&bytes)?)
            })
            .transpose()?;
        let mut stmt=self.0.prepare("SELECT sequence,hash,request_id FROM reviews WHERE agent=?1 AND bundle=?2 ORDER BY sequence LIMIT 101")?;
        let hashes = stmt
            .query_map(params![agent, id], |r| {
                Ok((
                    r.get::<_, u32>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut reviews = Vec::new();
        for (sequence, hash, request_id) in hashes {
            let (r, bytes) = storage.get(agent, &hash)?;
            let event: Signed<ReviewEvent> = serde_json::from_slice(&bytes)?;
            if r.receipt.kind != "bundle-review"
                || event.value.sequence != sequence
                || event.value.request.request_id != request_id
            {
                return Err("검토 객체 카탈로그 불일치".into());
            }
            reviews.push(event);
        }
        let current_review = reviews
            .last()
            .map(|e| match e.value.request.decision {
                ReviewDecision::Good => "good",
                ReviewDecision::Revoked => "revoked",
            })
            .unwrap_or("unknown")
            .to_owned();
        let record = BundleRecord {
            agent_id: agent.into(),
            manifest,
            manifest_receipt,
            recommended: current_review == "good" && completion.is_some(),
            completion,
            reviews,
            current_review,
        };
        verify_record(
            &record,
            &hex::encode(storage.key.verifying_key().to_bytes()),
            &storage.config.key_id,
        )?;
        Ok(record)
    }
}

fn register_inner(
    storage: &mut Storage,
    agent: &str,
    manifest: BundleManifest,
) -> Result<BundleRecord> {
    validate(&manifest)?;
    let catalog = Catalog::open(storage, true)?.ok_or("카탈로그 없음")?;
    let bytes = serde_json::to_vec(&manifest)?;
    let hash = sha256(&bytes);
    let existing: Option<String> = catalog
        .0
        .query_row(
            "SELECT manifest_hash FROM bundles WHERE agent=?1 AND id=?2",
            params![agent, manifest.bundle_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        if existing != hash {
            return Err("동일 번들 ID의 manifest 변경 거부".into());
        }
        let pending:bool=catalog.0.query_row("SELECT EXISTS(SELECT 1 FROM intents WHERE agent=?1 AND bundle=?2 AND operation='complete')",params![agent,manifest.bundle_id],|r|r.get(0))?;
        if pending {
            // 이전 완료 게시가 끊긴 동일 manifest 등록은 그 완료 의도부터 재시도한다.
            drop(catalog);
            return complete_inner(storage, agent, &manifest.bundle_id);
        }
    } else {
        let count: u64 = catalog
            .0
            .query_row("SELECT COUNT(*) FROM bundles", [], |r| r.get(0))?;
        let agent_count: u64 = catalog.0.query_row(
            "SELECT COUNT(*) FROM bundles WHERE agent=?1",
            [agent],
            |r| r.get(0),
        )?;
        if agent_count >= 1000 {
            return Err("에이전트별 번들 1000개 상한".into());
        }
        if count >= MAX_BUNDLES {
            return Err("번들 카탈로그 10000개 상한".into());
        }
        storage.put(agent, &hash, "bundle-manifest", &bytes)?;
        catalog.0.execute(
            "INSERT INTO bundles(agent,id,manifest_hash) VALUES(?1,?2,?3)",
            params![agent, manifest.bundle_id, hash],
        )?;
    }
    catalog.coverage(storage)?;
    catalog.record(storage, agent, &manifest.bundle_id)
}
fn complete_inner(storage: &mut Storage, agent: &str, id: &str) -> Result<BundleRecord> {
    let catalog = Catalog::open(storage, false)?.ok_or("카탈로그 없음")?;
    let record = catalog.record(storage, agent, id)?;
    if record.completion.is_none() {
        let mut full = Sha256::new();
        for chunk in &record.manifest.chunks {
            let (receipt, bytes) = storage.get(agent, &chunk.sha256)?;
            if receipt.receipt.kind != "backup" || bytes.len() as u64 != chunk.size_bytes {
                return Err("번들 청크/수신증명 불일치".into());
            }
            full.update(bytes);
        }
        if hex::encode(full.finalize()) != record.manifest.sha256 {
            return Err("번들 전체 해시 불일치".into());
        }
        // 객체 게시 전 서명 바이트를 FULL 트랜잭션 의도로 남겨 중단 후 동일하게 재시도한다.
        let completion = sign_value(
            Completion {
                format: "argos-bundle-completion-v1".into(),
                key_id: storage.config.key_id.clone(),
                agent_id: agent.into(),
                bundle_id: id.into(),
                manifest_sha256: record.manifest_receipt.receipt.sha256.clone(),
                sha256: record.manifest.sha256.clone(),
                size_bytes: record.manifest.size_bytes,
                completed_at_ms: now_ms(),
            },
            &storage.key,
        )?;
        let bytes = catalog.intent(agent, id, "complete", serde_json::to_vec(&completion)?)?;
        let stored: Signed<Completion> = serde_json::from_slice(&bytes)?;
        let mut check = record.clone();
        check.completion = Some(stored);
        verify_record(
            &check,
            &hex::encode(storage.key.verifying_key().to_bytes()),
            &storage.config.key_id,
        )?;
        let hash = sha256(&bytes);
        storage.put(agent, &hash, "bundle-completion", &bytes)?;
        let tx = catalog.0.unchecked_transaction()?;
        tx.execute("UPDATE bundles SET completion_hash=?1 WHERE agent=?2 AND id=?3 AND completion_hash IS NULL",params![hash,agent,id])?;
        tx.execute(
            "DELETE FROM intents WHERE agent=?1 AND bundle=?2 AND operation='complete'",
            params![agent, id],
        )?;
        tx.commit()?;
    }
    catalog.coverage(storage)?;
    catalog.record(storage, agent, id)
}
fn review_inner(
    storage: &mut Storage,
    agent: &str,
    id: &str,
    request: ReviewRequest,
) -> Result<BundleRecord> {
    validate_review(&request)?;
    let catalog = Catalog::open(storage, false)?.ok_or("카탈로그 없음")?;
    let record = catalog.record_raw(storage, agent, id)?;
    let completion = record
        .completion
        .as_ref()
        .ok_or("미완료 번들의 검토는 보류합니다")?;
    if let Some(existing) = record
        .reviews
        .iter()
        .find(|r| r.value.request.request_id == request.request_id)
    {
        if existing.value.request != request {
            return Err("검토 요청 ID 재사용 내용 불일치".into());
        }
    } else {
        if record.reviews.len() >= MAX_REVIEWS
            || (record.reviews.len() + 1 == MAX_REVIEWS
                && request.decision != ReviewDecision::Revoked)
        {
            return Err("번들 검토 이력 100개 상한(마지막 슬롯은 취소 전용)".into());
        }
        let sequence = record.reviews.len() as u32 + 1;
        // 검토 시각은 호출마다 새 값이므로 저장 후 ACK 유실에는 요청 ID로 기존 결과를 찾는다.
        let event = sign_value(
            ReviewEvent {
                format: "argos-bundle-review-v1".into(),
                key_id: storage.config.key_id.clone(),
                agent_id: agent.into(),
                bundle_id: id.into(),
                manifest_sha256: record.manifest_receipt.receipt.sha256.clone(),
                completion_sha256: sha256(&serde_json::to_vec(completion)?),
                sequence,
                previous_sha256: record
                    .reviews
                    .last()
                    .map(|r| serde_json::to_vec(r).map(|b| sha256(&b)))
                    .transpose()?,
                reviewed_at_ms: now_ms(),
                request,
            },
            &storage.key,
        )?;
        let bytes = catalog.intent(agent, id, "review", serde_json::to_vec(&event)?)?;
        let stored: Signed<ReviewEvent> = serde_json::from_slice(&bytes)?;
        if stored.value.request != event.value.request {
            return Err("기존 미완료 검토 요청을 먼저 같은 ID/내용으로 재시도하세요".into());
        }
        let mut check = record.clone();
        check.current_review = match stored.value.request.decision {
            ReviewDecision::Good => "good",
            ReviewDecision::Revoked => "revoked",
        }
        .into();
        check.recommended = check.current_review == "good";
        check.reviews.push(stored);
        verify_record(
            &check,
            &hex::encode(storage.key.verifying_key().to_bytes()),
            &storage.config.key_id,
        )?;
        let hash = sha256(&bytes);
        storage.put(agent, &hash, "bundle-review", &bytes)?;
        let tx = catalog.0.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO reviews(agent,bundle,sequence,hash,request_id) VALUES(?1,?2,?3,?4,?5)",
            params![agent, id, sequence, hash, event.value.request.request_id],
        )?;
        tx.execute(
            "DELETE FROM intents WHERE agent=?1 AND bundle=?2 AND operation='review'",
            params![agent, id],
        )?;
        tx.commit()?;
    }
    catalog.coverage(storage)?;
    catalog.record(storage, agent, id)
}

fn response(result: std::result::Result<Result<BundleRecord>, tokio::task::JoinError>) -> Response {
    match result {
        Ok(Ok(record)) => Json(record).into_response(),
        Ok(Err(error)) if error.downcast_ref::<CapacityRejection>().is_some() => failure(
            StatusCode::INSUFFICIENT_STORAGE,
            "번들 게시/검토 미적용: 용량 또는 저장 상태 거부",
        ),
        _ => failure(StatusCode::CONFLICT, "번들 불완전/결합/저장 상태 오류"),
    }
}
async fn body(request: Request) -> std::result::Result<Vec<u8>, Response> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        to_bytes(request.into_body(), MAX_MANIFEST_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => Ok(bytes.to_vec()),
        _ => Err(failure(StatusCode::BAD_REQUEST, "번들 요청 크기/시간 제한")),
    }
}
pub(super) async fn register(State(state): State<AppState>, request: Request) -> Response {
    let Some(agent) = upload_agent(&state.config, request.headers()).map(str::to_owned) else {
        return failure(StatusCode::UNAUTHORIZED, "수집 토큰 인증 실패");
    };
    let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "동시 요청 상한");
    };
    let bytes = match body(request).await {
        Ok(bytes) => bytes,
        Err(r) => return r,
    };
    let manifest = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "manifest 형식 오류"),
    };
    response(
        tokio::task::spawn_blocking(move || {
            let _p = permit;
            let mut storage = state.storage.lock().map_err(|_| "저장소 잠금 오류")?;
            register_inner(&mut storage, &agent, manifest)
        })
        .await,
    )
}
pub(super) async fn complete(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    let Some(agent) = upload_agent(&state.config, &headers).map(str::to_owned) else {
        return failure(StatusCode::UNAUTHORIZED, "수집 토큰 인증 실패");
    };
    if !valid_bundle_id(&id) {
        return failure(StatusCode::BAD_REQUEST, "번들 ID 오류");
    }
    let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "동시 요청 상한");
    };
    response(
        tokio::task::spawn_blocking(move || {
            let _p = permit;
            let mut storage = state.storage.lock().map_err(|_| "저장소 잠금 오류")?;
            complete_inner(&mut storage, &agent, &id)
        })
        .await,
    )
}
pub(super) async fn get(
    State(state): State<AppState>,
    UrlPath((agent, id)): UrlPath<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !admin(&state.config, &headers) {
        return failure(StatusCode::UNAUTHORIZED, "관리자 토큰 인증 실패");
    }
    if !valid_id(&agent) || !valid_bundle_id(&id) {
        return failure(StatusCode::BAD_REQUEST, "번들 경로 오류");
    }
    let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "동시 요청 상한");
    };
    response(
        tokio::task::spawn_blocking(move || {
            let _p = permit;
            let storage = state.storage.lock().map_err(|_| "저장소 잠금 오류")?;
            let catalog = Catalog::open(&storage, false)?.ok_or("카탈로그 없음")?;
            catalog.coverage(&storage)?;
            catalog.record(&storage, &agent, &id)
        })
        .await,
    )
}
pub(super) async fn review(
    State(state): State<AppState>,
    UrlPath((agent, id)): UrlPath<(String, String)>,
    request: Request,
) -> Response {
    if !admin(&state.config, request.headers()) {
        return failure(StatusCode::UNAUTHORIZED, "관리자 검토 토큰 인증 실패");
    }
    if !valid_id(&agent) || !valid_bundle_id(&id) {
        return failure(StatusCode::BAD_REQUEST, "번들 경로 오류");
    }
    let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "동시 요청 상한");
    };
    let bytes = match body(request).await {
        Ok(bytes) => bytes,
        Err(r) => return r,
    };
    let request = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "검토 요청 형식 오류"),
    };
    response(
        tokio::task::spawn_blocking(move || {
            let _p = permit;
            let mut storage = state.storage.lock().map_err(|_| "저장소 잠금 오류")?;
            review_inner(&mut storage, &agent, &id, request)
        })
        .await,
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    after: Option<String>,
    limit: Option<usize>,
}
pub(super) async fn list(
    State(state): State<AppState>,
    UrlPath(agent): UrlPath<String>,
    Query(page): Query<Page>,
    headers: HeaderMap,
) -> Response {
    if !admin(&state.config, &headers) {
        return failure(StatusCode::UNAUTHORIZED, "관리자 토큰 인증 실패");
    }
    let limit = page.limit.unwrap_or(20);
    if !valid_id(&agent)
        || !(1..=100).contains(&limit)
        || page.after.as_ref().is_some_and(|id| !valid_bundle_id(id))
    {
        return failure(StatusCode::BAD_REQUEST, "목록 범위/상한 오류");
    }
    let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "동시 요청 상한");
    };
    let result = tokio::task::spawn_blocking(move || -> Result<BundleList> {
        let _p = permit;
        let storage = state.storage.lock().map_err(|_| "저장소 잠금 오류")?;
        let Some(catalog) = Catalog::open(&storage, false)? else {
            return Ok(BundleList {
                agent_id: agent,
                items: vec![],
                next_cursor: None,
            });
        };
        catalog.coverage(&storage)?;
        let mut stmt = catalog
            .0
            .prepare("SELECT id FROM bundles WHERE agent=?1 AND id>?2 ORDER BY id LIMIT ?3")?;
        let ids = stmt
            .query_map(
                params![agent, page.after.unwrap_or_default(), limit + 1],
                |r| r.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let more = ids.len() > limit;
        let mut items = Vec::new();
        for id in ids.into_iter().take(limit) {
            let r = catalog.record(&storage, &agent, &id)?;
            items.push(BundleSummary {
                bundle_id: id,
                original_path: r.manifest.metadata.original_path,
                version: r.manifest.metadata.version,
                sha256: r.manifest.sha256,
                size_bytes: r.manifest.size_bytes,
                complete: r.completion.is_some(),
                current_review: r.current_review,
                recommended: r.recommended,
            });
        }
        let next_cursor = if more {
            items.last().map(|i| i.bundle_id.clone())
        } else {
            None
        };
        Ok(BundleList {
            agent_id: agent,
            items,
            next_cursor,
        })
    })
    .await;
    match result {
        Ok(Ok(page)) => Json(page).into_response(),
        _ => failure(StatusCode::CONFLICT, "번들 카탈로그/증명 확인 실패"),
    }
}
