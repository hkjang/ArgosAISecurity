//! 번들의 구성 목록·객체 참조·완료 의도를 큐와 함께 영속화한다.
use super::*;
use crate::bundle::{self, BundleManifest, BundleRecord, Completion, Signed};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_BUNDLE_JOBS: u64 = 1000;
const JOB_COLUMNS:&str="bundle_id,manifest_json,manifest_sha256,state,phase,created_at_ms,attempts,next_retry_ms,last_error,lease_expires_ms,completed_at_ms,manifest_receipt_json,completion_json";
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleChunkRef {
    pub item_id: String,
    pub sha256: String,
    pub size_bytes: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct BundleJob {
    pub bundle_id: String,
    pub manifest_sha256: String,
    pub manifest: BundleManifest,
    pub chunk_items: Vec<BundleChunkRef>,
    pub state: String,
    pub phase: String,
    pub created_at_ms: u64,
    pub attempts: u32,
    pub next_retry_ms: u64,
    pub last_error: Option<String>,
    pub lease_expires_ms: Option<u64>,
    pub completed_at_ms: Option<u64>,
    pub manifest_receipt: Option<SignedReceipt>,
    pub completion: Option<Signed<Completion>>,
    /// 보관 완료는 정상본 판정이 아니다. 현재 원격 판정은 별도 조회한다.
    pub recommended: bool,
}
#[derive(Debug, Serialize)]
pub struct BundleJobSummary {
    pub bundle_id: String,
    pub manifest_sha256: String,
    pub state: String,
    pub phase: String,
    pub chunk_count: usize,
    pub unique_chunks: usize,
    pub completed_chunks: u64,
    pub created_at_ms: u64,
    pub attempts: u32,
    pub next_retry_ms: u64,
    pub last_error: Option<String>,
    pub lease_expires_ms: Option<u64>,
    pub completed_at_ms: Option<u64>,
    pub recommended: bool,
}
#[derive(Debug, Serialize)]
pub struct BundleJobsStatus {
    pub total: u64,
    pub pending: u64,
    pub complete: u64,
    pub leased: u64,
    pub capacity: u64,
    pub earliest_retry_ms: Option<u64>,
    pub items: Vec<BundleJobSummary>,
    pub items_truncated: bool,
}
#[derive(Debug, Serialize)]
pub struct BundleJobOutcome {
    pub bundle_id: String,
    pub phase: String,
    pub completed: bool,
    pub error: Option<String>,
}

pub(super) fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE TABLE bundle_jobs(bundle_id TEXT PRIMARY KEY,manifest_json TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','complete')),phase TEXT NOT NULL CHECK(phase IN ('register','complete','done')),created_at_ms INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_retry_ms INTEGER NOT NULL,last_error TEXT,lease_token TEXT,lease_expires_ms INTEGER,completed_at_ms INTEGER,manifest_receipt_json TEXT,completion_json TEXT);
CREATE TABLE bundle_refs(bundle_id TEXT NOT NULL,item_id TEXT NOT NULL,sha256 TEXT NOT NULL,size_bytes INTEGER NOT NULL,PRIMARY KEY(bundle_id,sha256));
CREATE INDEX bundle_due ON bundle_jobs(state,next_retry_ms,created_at_ms);
CREATE INDEX bundle_ref_item ON bundle_refs(item_id);")?;
    Ok(())
}
pub(super) fn validate_schema(conn: &Connection) -> Result<()> {
    conn.prepare(&format!(
        "SELECT {JOB_COLUMNS},lease_token FROM bundle_jobs LIMIT 0"
    ))?;
    conn.prepare("SELECT bundle_id,item_id,sha256,size_bytes FROM bundle_refs LIMIT 0")?;
    let count: u64 = conn.query_row("SELECT COUNT(*) FROM bundle_jobs", [], |r| r.get(0))?;
    if count > MAX_BUNDLE_JOBS {
        return Err("번들 작업 1000개 상한 초과".into());
    }
    let bad:u64=conn.query_row("SELECT COUNT(*) FROM bundle_jobs WHERE length(manifest_json)>262144 OR ((lease_token IS NULL)!=(lease_expires_ms IS NULL)) OR (state='pending' AND (phase NOT IN ('register','complete') OR completed_at_ms IS NOT NULL OR completion_json IS NOT NULL)) OR (state='complete' AND (phase!='done' OR completed_at_ms IS NULL OR completion_json IS NULL OR manifest_receipt_json IS NULL OR lease_token IS NOT NULL)) OR (phase='complete' AND manifest_receipt_json IS NULL)",[],|r|r.get(0))?;
    let refs: u64 = conn.query_row("SELECT COUNT(*) FROM bundle_refs", [], |r| r.get(0))?;
    let bad_refs:u64=conn.query_row("SELECT COUNT(*) FROM bundle_refs r WHERE NOT EXISTS(SELECT 1 FROM bundle_jobs j WHERE j.bundle_id=r.bundle_id) OR NOT (EXISTS(SELECT 1 FROM queue_items q WHERE q.id=r.item_id AND q.kind='backup' AND q.sha256=r.sha256 AND q.size_bytes=r.size_bytes) OR EXISTS(SELECT 1 FROM receipt_archive a WHERE a.id=r.item_id AND a.kind='backup' AND a.sha256=r.sha256 AND a.size_bytes=r.size_bytes))",[],|r|r.get(0))?;
    let bad_counts:u64=conn.query_row("SELECT COUNT(*) FROM bundle_jobs j WHERE (SELECT COUNT(*) FROM bundle_refs r WHERE r.bundle_id=j.bundle_id) NOT BETWEEN 1 AND 64",[],|r|r.get(0))?;
    if bad != 0 || refs > MAX_BUNDLE_JOBS * 64 || bad_refs != 0 || bad_counts != 0 {
        return Err("번들 작업/청크 참조 상태 오류: 자동 초기화하지 않습니다".into());
    }
    Ok(())
}
fn decode_json<T: serde::de::DeserializeOwned>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<T> {
    let text: String = row.get(index)?;
    serde_json::from_str(&text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(e))
    })
}
fn decode_optional<T: serde::de::DeserializeOwned>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<T>> {
    let text: Option<String> = row.get(index)?;
    text.map(|text| {
        serde_json::from_str(&text).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(e),
            )
        })
    })
    .transpose()
}
fn decode_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<BundleJob> {
    Ok(BundleJob {
        bundle_id: row.get(0)?,
        manifest: decode_json(row, 1)?,
        manifest_sha256: row.get(2)?,
        state: row.get(3)?,
        phase: row.get(4)?,
        created_at_ms: row.get(5)?,
        attempts: row.get(6)?,
        next_retry_ms: row.get(7)?,
        last_error: row.get(8)?,
        lease_expires_ms: row.get(9)?,
        completed_at_ms: row.get(10)?,
        manifest_receipt: decode_optional(row, 11)?,
        completion: decode_optional(row, 12)?,
        chunk_items: vec![],
        recommended: false,
    })
}
fn unique_chunks(manifest: &BundleManifest) -> Result<BTreeMap<String, u64>> {
    bundle::validate(manifest)?;
    let mut refs = BTreeMap::new();
    for chunk in &manifest.chunks {
        if refs
            .insert(chunk.sha256.clone(), chunk.size_bytes)
            .is_some_and(|prior| prior != chunk.size_bytes)
        {
            return Err("동일 청크 해시의 크기가 다릅니다".into());
        }
    }
    Ok(refs)
}
fn proof(job: &BundleJob, target: &QueueTarget) -> Result<()> {
    bundle::validate(&job.manifest)?;
    if job.bundle_id != job.manifest.bundle_id
        || job.manifest_sha256 != sha256(&serde_json::to_vec(&job.manifest)?)
    {
        return Err("영속 번들 구성 목록의 ID/해시 불일치".into());
    }
    let expected = unique_chunks(&job.manifest)?;
    let actual: BTreeMap<_, _> = job
        .chunk_items
        .iter()
        .map(|r| (r.sha256.clone(), r.size_bytes))
        .collect();
    if expected != actual
        || actual.len() != job.chunk_items.len()
        || job.chunk_items.iter().any(|r| !id_ok(&r.item_id))
    {
        return Err("영속 번들 구성 목록과 청크 참조 불일치".into());
    }
    if let Some(receipt) = &job.manifest_receipt {
        let record = BundleRecord {
            agent_id: target.agent_id.clone(),
            manifest: job.manifest.clone(),
            manifest_receipt: receipt.clone(),
            completion: job.completion.clone(),
            reviews: vec![],
            current_review: "unknown".into(),
            recommended: false,
        };
        bundle::verify_record(&record, &target.pinned_pubkey, &target.key_id)?;
    } else if job.completion.is_some() || job.phase != "register" {
        return Err("구성 목록 수신증명 없는 번들 완료 상태".into());
    }
    if (job.state == "complete") != (job.completion.is_some()) {
        return Err("번들 완료 증명/상태 불일치".into());
    }
    Ok(())
}
fn load(conn: &Connection, id: &str) -> Result<BundleJob> {
    let mut job = conn
        .query_row(
            &format!("SELECT {JOB_COLUMNS} FROM bundle_jobs WHERE bundle_id=?1"),
            [id],
            decode_job,
        )
        .optional()?
        .ok_or("번들 작업을 찾을 수 없습니다")?;
    let mut stmt = conn.prepare(
        "SELECT item_id,sha256,size_bytes FROM bundle_refs WHERE bundle_id=?1 ORDER BY sha256",
    )?;
    job.chunk_items = stmt
        .query_map([id], |r| {
            Ok(BundleChunkRef {
                item_id: r.get(0)?,
                sha256: r.get(1)?,
                size_bytes: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    proof(&job, &metadata(conn)?.ok_or("큐 대상 없음")?.0)?;
    Ok(job)
}
pub fn bundle_job(directory: &Path, id: &str) -> Result<BundleJob> {
    if !id_ok(id) {
        return Err("번들 작업 ID는 32자리 소문자 hex입니다".into());
    }
    let conn = open_readonly(directory)?;
    let version: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version < 3 {
        return Err("이전 큐 형식에는 영속 번들 작업이 없습니다".into());
    }
    let tx = conn.unchecked_transaction()?;
    let job = load(&tx, id)?;
    tx.commit()?;
    Ok(job)
}
pub fn bundle_jobs(directory: &Path) -> Result<BundleJobsStatus> {
    let conn = open_readonly(directory)?;
    let tx = conn.unchecked_transaction()?;
    let result = status_with_conn(&tx)?;
    tx.commit()?;
    Ok(result)
}
pub(super) fn status_with_conn(conn: &Connection) -> Result<BundleJobsStatus> {
    let mut report = BundleJobsStatus {
        total: 0,
        pending: 0,
        complete: 0,
        leased: 0,
        capacity: MAX_BUNDLE_JOBS,
        earliest_retry_ms: None,
        items: vec![],
        items_truncated: false,
    };
    let version: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version < 3 {
        return Ok(report);
    }
    let (total,pending,complete,leased,next):(u64,u64,u64,u64,Option<u64>)=conn.query_row("SELECT COUNT(*),COALESCE(SUM(state='pending'),0),COALESCE(SUM(state='complete'),0),COALESCE(SUM(lease_expires_ms>?1),0),MIN(CASE WHEN state='pending' THEN MAX(next_retry_ms,COALESCE(lease_expires_ms,0)) END) FROM bundle_jobs",[crate::now_ms()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    report.total = total;
    report.pending = pending;
    report.complete = complete;
    report.leased = leased;
    report.earliest_retry_ms = next;
    let ids = {
        let mut stmt=conn.prepare("SELECT bundle_id FROM bundle_jobs ORDER BY created_at_ms DESC,bundle_id DESC LIMIT 100")?;
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids
    };
    for id in ids {
        let job = load(conn, &id)?;
        let completed_chunks:u64=conn.query_row("SELECT COUNT(*) FROM bundle_refs r JOIN receipt_archive a ON a.id=r.item_id WHERE r.bundle_id=?1",[&id],|r|r.get(0))?;
        report.items.push(BundleJobSummary {
            bundle_id: id,
            manifest_sha256: job.manifest_sha256,
            state: job.state,
            phase: job.phase,
            chunk_count: job.manifest.chunks.len(),
            unique_chunks: job.chunk_items.len(),
            completed_chunks,
            created_at_ms: job.created_at_ms,
            attempts: job.attempts,
            next_retry_ms: job.next_retry_ms,
            last_error: job.last_error,
            lease_expires_ms: job.lease_expires_ms,
            completed_at_ms: job.completed_at_ms,
            recommended: false,
        });
    }
    report.items_truncated = total > report.items.len() as u64;
    Ok(report)
}
struct Spool(PathBuf);
impl Drop for Spool {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        if let Some(parent) = self.0.parent() {
            let _ = crate::sync_directory(parent);
        }
    }
}
fn lookup(conn: &Connection, hash: &str) -> Result<Option<QueueItem>> {
    Ok(conn.query_row(&format!("SELECT {ITEM_COLUMNS} FROM queue_items WHERE kind='backup' AND sha256=?1 UNION ALL SELECT {ITEM_COLUMNS} FROM receipt_archive WHERE kind='backup' AND sha256=?1"),[hash],decode).optional()?)
}
fn same_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    let mut same = before.is_file()
        && after.is_file()
        && !after.file_type().is_symlink()
        && before.len() == after.len()
        && before.modified().ok() == after.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same &= before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && before.uid() == after.uid()
            && before.mode() == after.mode()
            && before.nlink() == after.nlink();
    }
    same
}
/// 재사용할 pending 본문의 전체 해시는 전역 잠금/읽기 트랜잭션 밖에서 검사한다.
fn verify_pending_snapshots(
    directory: &Path,
    chunks: &BTreeMap<String, u64>,
    target: &QueueTarget,
) -> Result<BTreeMap<String, fs::Metadata>> {
    let conn = open_readonly(directory)?;
    assert_target(&conn, target)?;
    let mut checked = BTreeMap::new();
    for (hash, size) in chunks {
        let Some(item) = lookup(&conn, hash)? else {
            continue;
        };
        if item.size_bytes != *size {
            return Err("기존 큐 청크 크기 불일치".into());
        }
        if item.state == "sent" {
            verified_item(&item, target)?;
            continue;
        }
        let check = (|| -> Result<fs::Metadata> {
            let path = snapshot(directory, &item.id)?;
            private_file(&path)?;
            let before = fs::symlink_metadata(&path)?;
            let bytes = read_bounded(&path, bundle::CHUNK_BYTES)?;
            private_file(&path)?;
            let after = fs::symlink_metadata(&path)?;
            if bytes.len() as u64 != *size
                || sha256(&bytes) != *hash
                || !same_snapshot(&before, &after)
            {
                return Err("기존 pending 청크 본문이 유실·변경되었습니다: 등록 거부".into());
            }
            Ok(after)
        })();
        match check {
            Ok(meta) => {
                checked.insert(item.id, meta);
            }
            Err(error) => {
                // 동시에 완료된 항목은 검증된 수신증명이 본문을 대신한다.
                let current = lookup(&conn, hash)?;
                if let Some(current) = current.filter(|v| v.id == item.id && v.state == "sent") {
                    verified_item(&current, target)?;
                } else {
                    return Err(error);
                }
            }
        }
    }
    Ok(checked)
}
/// 마지막 잠금 안에서는 메타데이터만 대조한다. 새로 나타난 미검증 pending은 재시도를 요구한다.
fn check_reused_snapshots(
    conn: &Connection,
    directory: &Path,
    refs: &[BundleChunkRef],
    checked: &BTreeMap<String, fs::Metadata>,
    target: &QueueTarget,
    require_existing: bool,
) -> Result<()> {
    for reference in refs {
        let Some(item) = lookup(conn, &reference.sha256)? else {
            if require_existing {
                return Err("기존 번들 청크 참조가 없습니다".into());
            }
            continue;
        };
        if item.id != reference.item_id || item.size_bytes != reference.size_bytes {
            return Err("기존 번들 청크 참조가 변경되었습니다".into());
        }
        if item.state == "sent" {
            verified_item(&item, target)?;
        } else {
            let before = checked
                .get(&item.id)
                .ok_or("동시 등록된 pending 청크를 검증하려면 다시 등록하세요")?;
            let path = snapshot(directory, &item.id)?;
            private_file(&path)?;
            if !same_snapshot(before, &fs::symlink_metadata(path)?) {
                return Err("검증 후 pending 청크가 변경되었습니다: 등록 거부".into());
            }
        }
    }
    Ok(())
}
fn admission(
    conn: &Connection,
    chunks: &BTreeMap<String, u64>,
    limits: &QueueLimits,
    target: &QueueTarget,
) -> Result<Vec<BundleChunkRef>> {
    let (active, bytes): (u64, u64) = conn.query_row(
        "SELECT COUNT(*),COALESCE(SUM(size_bytes),0) FROM queue_items",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let archived: u64 = conn.query_row("SELECT COUNT(*) FROM receipt_archive", [], |r| r.get(0))?;
    let jobs: u64 = conn.query_row("SELECT COUNT(*) FROM bundle_jobs", [], |r| r.get(0))?;
    if jobs >= MAX_BUNDLE_JOBS {
        return Err("번들 작업 보관 1000개 상한: 기존 큐를 보존하고 새 큐를 사용하세요".into());
    }
    let mut added = 0u64;
    let mut extra = 0u64;
    let mut refs = vec![];
    for (hash, size) in chunks {
        let item_id = if let Some(item) = lookup(conn, hash)? {
            if item.size_bytes != *size {
                return Err("기존 큐 청크 크기 불일치".into());
            }
            if item.state == "sent" {
                verified_item(&item, target)?;
            }
            item.id
        } else {
            added += 1;
            extra = extra.checked_add(*size).ok_or("청크 합계 초과")?;
            random_id()?
        };
        refs.push(BundleChunkRef {
            item_id,
            sha256: hash.clone(),
            size_bytes: *size,
        });
    }
    if active.saturating_add(added) > limits.max_items
        || bytes.saturating_add(extra) > limits.max_bytes
        || active.saturating_add(archived).saturating_add(added) > MAX_ARCHIVE_ITEMS
    {
        return Err(
            "전체 번들 청크의 활성 개수/바이트/보관 슬롯을 확보할 수 없습니다: 작업 미등록".into(),
        );
    }
    Ok(refs)
}
/// 검증된 모든 고유 청크와 구성 목록을 한 번에 게시한다. 성공 이후 준비 디렉터리가 없어도 전송한다.
pub fn enqueue_bundle(
    directory: &Path,
    config: &VaultConfig,
    stage: &Path,
    limits: &QueueLimits,
) -> Result<BundleJob> {
    limits.validate()?;
    let target = QueueTarget::from_config(config)?;
    validate_private_directory(stage)?;
    validate_private_directory(&stage.join("chunks"))?;
    if directory.starts_with(stage) || stage.starts_with(directory) {
        return Err("준비 경로와 큐는 서로 분리된 경로여야 합니다".into());
    }
    let manifest = bundle::read_manifest(&stage.join("manifest.json"))?;
    let chunks = unique_chunks(&manifest)?;
    if chunks
        .values()
        .any(|size| *size > config.max_object_bytes as u64)
    {
        return Err("청크가 현재 클라이언트 객체 상한을 초과합니다".into());
    }
    let text = serde_json::to_string(&manifest)?;
    let hash = sha256(text.as_bytes());
    let already_registered = {
        let (_lock, conn) = open_mutating(directory, Some((&target, limits)))?;
        assert_target(&conn, &target)?;
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM bundle_jobs WHERE bundle_id=?1)",
            [&manifest.bundle_id],
            |r| r.get(0),
        )?;
        if exists {
            let old = load(&conn, &manifest.bundle_id)?;
            if old.manifest != manifest {
                return Err("같은 번들 ID의 구성 목록 변경을 거부합니다".into());
            }
        } else {
            admission(&conn, &chunks, limits, &target)?;
        }
        exists
    };
    if already_registered {
        let checked = verify_pending_snapshots(directory, &chunks, &target)?;
        let (_lock, conn) = open_mutating(directory, None)?;
        assert_target(&conn, &target)?;
        let old = load(&conn, &manifest.bundle_id)?;
        if old.manifest != manifest {
            return Err("같은 번들 ID의 구성 목록 변경을 거부합니다".into());
        }
        check_reused_snapshots(&conn, directory, &old.chunk_items, &checked, &target, true)?;
        return Ok(old);
    }
    let spool = Spool(directory.join(format!(".bundle-spool-{}", random_id()?)));
    make_directory(&spool.0)?;
    let mut full = Sha256::new();
    for chunk in &manifest.chunks {
        let path = spool.0.join(format!("{}.bin", chunk.sha256));
        let bytes = if path.exists() {
            read_bounded(&path, bundle::CHUNK_BYTES)?
        } else {
            let bytes = read_bounded(
                &stage.join("chunks").join(format!("{}.bin", chunk.sha256)),
                bundle::CHUNK_BYTES,
            )?;
            if bytes.len() as u64 != chunk.size_bytes || sha256(&bytes) != chunk.sha256 {
                return Err("번들 청크의 실제 내용/구성 목록 불일치: 작업 미등록".into());
            }
            write_new(&path, &bytes)?;
            bytes
        };
        if bytes.len() as u64 != chunk.size_bytes || sha256(&bytes) != chunk.sha256 {
            return Err("번들 고정 청크 불일치".into());
        }
        full.update(&bytes);
    }
    if hex::encode(full.finalize()) != manifest.sha256 {
        return Err("번들 전체 파일 해시 불일치: 작업 미등록".into());
    }
    let checked = verify_pending_snapshots(directory, &chunks, &target)?;
    let (_lock, mut conn) = open_mutating(directory, None)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert_target(&tx, &target)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM bundle_jobs WHERE bundle_id=?1)",
        [&manifest.bundle_id],
        |r| r.get(0),
    )?;
    if exists {
        let old = load(&tx, &manifest.bundle_id)?;
        if old.manifest != manifest {
            return Err("같은 번들 ID의 구성 목록 변경을 거부합니다".into());
        }
        check_reused_snapshots(&tx, directory, &old.chunk_items, &checked, &target, true)?;
        tx.commit()?;
        return Ok(old);
    }
    let refs = admission(&tx, &chunks, limits, &target)?;
    check_reused_snapshots(&tx, directory, &refs, &checked, &target, false)?;
    let now = crate::now_ms().min(i64::MAX as u64);
    for item in &refs {
        if lookup(&tx, &item.sha256)?.is_some() {
            continue;
        }
        let source = spool.0.join(format!("{}.bin", item.sha256));
        let destination = snapshot(directory, &item.item_id)?;
        fs::hard_link(&source, &destination)?;
        fs::remove_file(source)?;
        tx.execute("INSERT INTO queue_items(id,kind,sha256,size_bytes,state,created_at_ms,next_retry_ms) VALUES(?1,'backup',?2,?3,'pending',?4,?4)",params![item.item_id,item.sha256,item.size_bytes,now])?;
    }
    crate::sync_directory(&spool.0)?;
    crate::sync_directory(&directory.join(OBJECTS))?;
    tx.execute("INSERT INTO bundle_jobs(bundle_id,manifest_json,manifest_sha256,state,phase,created_at_ms,next_retry_ms) VALUES(?1,?2,?3,'pending','register',?4,?4)",params![manifest.bundle_id,text,hash,now])?;
    for item in &refs {
        tx.execute(
            "INSERT INTO bundle_refs(bundle_id,item_id,sha256,size_bytes) VALUES(?1,?2,?3,?4)",
            params![
                manifest.bundle_id,
                item.item_id,
                item.sha256,
                item.size_bytes
            ],
        )?;
    }
    tx.execute(
        "UPDATE queue_meta SET max_items=?1,max_bytes=?2 WHERE singleton=1",
        params![limits.max_items, limits.max_bytes],
    )?;
    let job = load(&tx, &manifest.bundle_id)?;
    tx.commit()?;
    Ok(job)
}
struct JobLease {
    job: BundleJob,
    token: String,
}
fn claim_job(
    directory: &Path,
    target: &QueueTarget,
    timeout: u64,
    now: u64,
) -> Result<Option<JobLease>> {
    let (_lock, mut conn) = open_mutating(directory, None)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert_target(&tx, target)?;
    let now = now.max(crate::now_ms()).min(i64::MAX as u64);
    let id:Option<String>=tx.query_row("SELECT j.bundle_id FROM bundle_jobs j WHERE j.state='pending' AND j.next_retry_ms<=?1 AND (j.lease_expires_ms IS NULL OR j.lease_expires_ms<=?1) AND NOT EXISTS(SELECT 1 FROM bundle_refs r LEFT JOIN receipt_archive a ON a.id=r.item_id WHERE r.bundle_id=j.bundle_id AND a.id IS NULL) ORDER BY j.created_at_ms,j.bundle_id LIMIT 1",[now],|r|r.get(0)).optional()?;
    let Some(id) = id else {
        tx.commit()?;
        return Ok(None);
    };
    let mut job = load(&tx, &id)?;
    for r in &job.chunk_items {
        let item = tx.query_row(
            &format!("SELECT {ITEM_COLUMNS} FROM receipt_archive WHERE id=?1"),
            [&r.item_id],
            decode,
        )?;
        verified_item(&item, target)?;
    }
    job.attempts = job.attempts.saturating_add(1);
    let token = random_id()?;
    let expires = now
        .saturating_add(timeout.saturating_mul(1000))
        .saturating_add(LEASE_GRACE_MS)
        .min(i64::MAX as u64);
    tx.execute("UPDATE bundle_jobs SET attempts=?1,lease_token=?2,lease_expires_ms=?3,next_retry_ms=?4,last_error='interrupted_or_unconfirmed' WHERE bundle_id=?5",params![job.attempts,token,expires,now.saturating_add(retry_delay(job.attempts)).min(i64::MAX as u64),id])?;
    tx.commit()?;
    Ok(Some(JobLease { job, token }))
}
fn finish_job(
    directory: &Path,
    target: &QueueTarget,
    lease: &JobLease,
    result: &std::result::Result<BundleRecord, &'static str>,
    now: u64,
) -> Result<bool> {
    let (_lock, mut conn) = open_mutating(directory, None)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert_target(&tx, target)?;
    let now = now.max(crate::now_ms()).min(i64::MAX as u64);
    let owns:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM bundle_jobs WHERE bundle_id=?1 AND lease_token=?2 AND lease_expires_ms>?3)",params![lease.job.bundle_id,lease.token,now],|r|r.get(0))?;
    if !owns {
        tx.commit()?;
        return Ok(false);
    }
    match result {
        Ok(record) => {
            bundle::verify_record(record, &target.pinned_pubkey, &target.key_id)?;
            if record.manifest != lease.job.manifest
                || record.agent_id != target.agent_id
                || (lease.job.phase == "complete" && record.completion.is_none())
            {
                return Err("번들 작업 응답의 구성 목록/완료 증명 불일치".into());
            }
            let completed = record.completion.is_some();
            tx.execute("UPDATE bundle_jobs SET state=?1,phase=?2,manifest_receipt_json=?3,completion_json=?4,completed_at_ms=?5,next_retry_ms=?6,last_error=NULL,lease_token=NULL,lease_expires_ms=NULL WHERE bundle_id=?7 AND lease_token=?8",params![if completed {"complete"} else {"pending"},if completed {"done"} else {"complete"},serde_json::to_string(&record.manifest_receipt)?,record.completion.as_ref().map(serde_json::to_string).transpose()?,if completed {Some(now)} else {None},if completed {0} else {now},lease.job.bundle_id,lease.token])?;
        }
        Err(code) => {
            tx.execute("UPDATE bundle_jobs SET next_retry_ms=?1,last_error=?2,lease_token=NULL,lease_expires_ms=NULL WHERE bundle_id=?3 AND lease_token=?4",params![now.saturating_add(retry_delay(lease.job.attempts)).min(i64::MAX as u64),code,lease.job.bundle_id,lease.token])?;
        }
    }
    tx.commit()?;
    Ok(true)
}
pub(super) fn drain_one(
    directory: &Path,
    config: &VaultConfig,
    target: &QueueTarget,
) -> Result<Option<BundleJobOutcome>> {
    let Some(lease) = claim_job(directory, target, config.timeout_secs, crate::now_ms())? else {
        return Ok(None);
    };
    let result = if lease.job.phase == "register" {
        bundle::register_manifest(config, &lease.job.manifest)
    } else {
        bundle::complete(config, &lease.job.bundle_id)
    };
    // 대상·manifest·ID는 임대 전에 검증했다. HTTP/전송 분류 외의 고정 실패는
    // 번들 응답의 파싱·서명·프로토콜 결합 실패로 별도 기록한다.
    let result = result.map_err(|e| match client::error_code(e.as_ref()) {
        "unknown" => "bundle_response_or_state_invalid",
        code => code,
    });
    let result = result.and_then(|record| {
        if record.manifest != lease.job.manifest
            || record.agent_id != target.agent_id
            || (lease.job.phase == "complete" && record.completion.is_none())
        {
            Err("response_integrity")
        } else {
            Ok(record)
        }
    });
    let committed = finish_job(directory, target, &lease, &result, crate::now_ms())?;
    let completed = committed && result.as_ref().is_ok_and(|r| r.completion.is_some());
    let error = if !committed {
        Some("lease_expired_or_replaced".into())
    } else {
        result.err().map(str::to_owned)
    };
    Ok(Some(BundleJobOutcome {
        bundle_id: lease.job.bundle_id,
        phase: lease.job.phase,
        completed,
        error,
    }))
}

#[cfg(test)]
mod tests;
