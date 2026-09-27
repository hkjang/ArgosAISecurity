//! 명시적 run-once 업로드만 수행하는 영속 로컬 대기열.
//! 동일 UID/root의 변조나 삭제를 막는 경계가 아니며 토큰은 저장하지 않는다.
use crate::{
    client, read_bounded, sha256, valid_hash, valid_id, valid_kind, validate_private_directory,
    verify_receipt, write_new, Result, SignedReceipt, VaultConfig, MAX_OBJECT_BYTES,
};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

const DB: &str = "queue.sqlite3";
const OBJECTS: &str = "objects";
const MAX_ITEMS: u64 = 10_000;
const MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const STATUS_ITEMS: usize = 100;
const SCHEMA_VERSION: u32 = 3;
/// 완료 수신증명과 아직 완료되지 않은 예약의 합계. 자동 삭제하지 않는다.
pub const MAX_ARCHIVE_ITEMS: u64 = 100_000;
const LEASE_GRACE_MS: u64 = 30_000;
const ITEM_COLUMNS:&str="id,kind,sha256,size_bytes,state,created_at_ms,attempts,next_retry_ms,last_error,sent_at_ms,receipt_json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QueueLimits {
    /// 임대 중인 항목을 포함한 활성 항목만 계산한다. 완료 이력은 별도 보관한다.
    pub max_items: u64,
    /// 아직 완료 처리되지 않은 스냅샷의 바이트 합계.
    pub max_bytes: u64,
}
impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            max_items: 1000,
            max_bytes: 256 * 1024 * 1024,
        }
    }
}
impl QueueLimits {
    fn validate(self) -> Result<()> {
        if !(1..=MAX_ITEMS).contains(&self.max_items) || !(1..=MAX_BYTES).contains(&self.max_bytes)
        {
            return Err("활성 큐 상한은 1~10000개, 본문 1바이트~8GiB입니다".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DrainOptions {
    pub max_items: usize,
}
impl Default for DrainOptions {
    fn default() -> Self {
        Self { max_items: 10 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QueueTarget {
    pub endpoint: String,
    pub agent_id: String,
    pub key_id: String,
    pub pinned_pubkey: String,
    pub allow_http_loopback: bool,
    #[serde(default)]
    pub tls_ca_sha256: Option<String>,
}
impl QueueTarget {
    fn from_config(config: &VaultConfig) -> Result<Self> {
        let url = client::validated_endpoint(config)?; // 설정 검사만 하며 네트워크에 연결하지 않는다.
        if !valid_id(&config.agent_id) {
            return Err("큐 에이전트 ID 오류".into());
        }
        Ok(Self {
            endpoint: url.to_string(),
            agent_id: config.agent_id.clone(),
            key_id: config.key_id.clone(),
            pinned_pubkey: hex::encode(crate::public_key(&config.pinned_pubkey)?.to_bytes()),
            allow_http_loopback: config.allow_http_loopback,
            tls_ca_sha256: client::tls_ca_sha256(config)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueItem {
    pub id: String,
    pub kind: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub state: String,
    pub created_at_ms: u64,
    pub attempts: u32,
    pub next_retry_ms: u64,
    pub last_error: Option<String>,
    pub sent_at_ms: Option<u64>,
    pub receipt: Option<SignedReceipt>,
}
#[derive(Debug, Serialize)]
pub struct QueueStatus {
    pub target: Option<QueueTarget>,
    pub limits: Option<QueueLimits>,
    pub items_total: u64,
    pub pending_items: u64,
    pub sent_items: u64,
    pub pending_bytes: u64,
    pub failed_items: u64,
    pub leased_items: u64,
    pub archive_items: u64,
    pub archive_capacity: u64,
    pub archive_slots_available: u64,
    pub earliest_retry_ms: Option<u64>,
    /// 최근 최대 100개. 전체 상태 집계는 전체 큐를 사용한다.
    pub items: Vec<QueueItem>,
    pub items_truncated: bool,
    pub bundle_jobs: BundleJobsStatus,
}
#[derive(Debug, Serialize)]
pub struct DrainOutcome {
    pub id: String,
    pub sent: bool,
    pub error: Option<String>,
    pub receipt: Option<SignedReceipt>,
}
#[derive(Debug, Serialize)]
pub struct DrainReport {
    pub attempted: usize,
    pub sent: usize,
    pub failed: usize,
    pub remaining_pending: u64,
    pub items: Vec<DrainOutcome>,
    pub attempted_jobs: usize,
    pub completed_jobs: usize,
    pub failed_jobs: usize,
    pub remaining_jobs: u64,
    pub jobs: Vec<BundleJobOutcome>,
}

fn private_file(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err("큐 파일은 일반 파일이어야 합니다".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1
        {
            return Err("큐 파일은 현재 계정 소유 0600 단일 링크 파일이어야 합니다".into());
        }
    }
    Ok(())
}
fn make_directory(path: &Path) -> Result<()> {
    // 경로 정책 위반은 생성 전에 거부한다. 단일 상대 경로의 parent는 빈 경로다.
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("큐 디렉터리는 .. 없는 절대 경로여야 합니다".into());
    }
    if fs::symlink_metadata(path).is_err() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
        if let Some(parent) = path.parent() {
            crate::sync_directory(parent)?;
        }
    }
    validate_private_directory(path)
}
fn open_private(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = if create {
        let file = options.create_new(true).open(path)?;
        file.sync_all()?;
        crate::sync_directory(path.parent().ok_or("큐 파일 부모 없음")?)?;
        file
    } else {
        options.open(path)?
    };
    private_file(path)?;
    Ok(file)
}
struct Lock {
    file: File,
}
impl Lock {
    fn acquire(directory: &Path, create: bool) -> Result<Self> {
        let file = open_private(&directory.join("queue.lock"), create)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let started = std::time::Instant::now();
            loop {
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if !matches!(
                    error.raw_os_error(),
                    Some(libc::EWOULDBLOCK) | Some(libc::EINTR)
                ) {
                    return Err(error.into());
                }
                if started.elapsed() >= Duration::from_secs(2) {
                    return Err("큐 상태 변경 잠금이 2초 동안 사용 중입니다".into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        #[cfg(not(unix))]
        {
            return Err("이 플랫폼에서는 큐의 프로세스 간 잠금을 지원하지 않습니다".into());
        }
        #[allow(unreachable_code)]
        Ok(Self { file })
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

fn open_mutating(
    directory: &Path,
    initialize: Option<(&QueueTarget, &QueueLimits)>,
) -> Result<(Lock, Connection)> {
    if initialize.is_some() {
        make_directory(directory)?;
    } else {
        validate_private_directory(directory)?;
    }
    // DB가 유실된 큐를 빈 큐로 재생성하면 기존 스냅샷을 고아로 오인한다.
    // 완전히 빈 디렉터리만 초기화하며, 중단된 초기화 흔적도 자동 수리하지 않는다.
    let fresh = fs::read_dir(directory)?.next().transpose()?.is_none();
    if fresh && initialize.is_none() {
        return Err("큐가 초기화되지 않았습니다. 먼저 enqueue 하세요".into());
    }
    // fresh일 때 create_new로 경쟁 초기화도 거부한다. 기존 잠금은 재생성하지 않는다.
    let lock = Lock::acquire(directory, fresh)?;
    if fresh {
        make_directory(&directory.join(OBJECTS))?;
    } else {
        validate_private_directory(&directory.join(OBJECTS))?;
    }
    let path = directory.join(DB);
    let _file = open_private(&path, fresh)?;
    let mut conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_secs(2))?;
    if fresh {
        conn.pragma_update(None, "journal_mode", "DELETE")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let (target, limits) = initialize.ok_or("큐 초기화 대상 없음")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE queue_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),target_json TEXT NOT NULL,max_items INTEGER NOT NULL,max_bytes INTEGER NOT NULL);
CREATE TABLE queue_items(id TEXT PRIMARY KEY,kind TEXT NOT NULL,sha256 TEXT NOT NULL,size_bytes INTEGER NOT NULL CHECK(size_bytes>=0),state TEXT NOT NULL CHECK(state IN ('pending','sent')),created_at_ms INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_retry_ms INTEGER NOT NULL,last_error TEXT,sent_at_ms INTEGER,receipt_json TEXT,UNIQUE(kind,sha256));
CREATE INDEX queue_due ON queue_items(state,next_retry_ms,created_at_ms);
ALTER TABLE queue_items ADD COLUMN lease_token TEXT;
ALTER TABLE queue_items ADD COLUMN lease_expires_ms INTEGER;
CREATE TABLE receipt_archive AS SELECT * FROM queue_items WHERE 0;
CREATE UNIQUE INDEX archive_id ON receipt_archive(id);
CREATE UNIQUE INDEX archive_object ON receipt_archive(kind,sha256);")?;
        tx.execute(
            "INSERT INTO queue_meta(singleton,target_json,max_items,max_bytes) VALUES(1,?1,?2,?3)",
            params![
                serde_json::to_string(target)?,
                limits.max_items,
                limits.max_bytes
            ],
        )?;
        jobs::create_schema(&tx)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
    }
    validate_database(&conn)?;
    migrate(&mut conn)?;
    conn.pragma_update(None, "journal_mode", "DELETE")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    cleanup(directory, &conn)?;
    Ok((lock, conn))
}

fn validate_database(conn: &Connection) -> Result<()> {
    let version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !matches!(version, 1 | 2 | SCHEMA_VERSION) {
        return Err(
            "큐 DB 형식이 없거나 지원하지 않습니다. 남은 파일을 보존하고 점검하세요".into(),
        );
    }
    let check: String = conn.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if check != "ok" {
        return Err("큐 DB 무결성 검사 실패. 남은 파일을 보존하고 점검하세요".into());
    }
    for table in ["queue_meta", "queue_items"] {
        let count: u64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )?;
        if count != 1 {
            return Err("큐 DB 스키마가 불완전합니다. 자동 초기화하지 않습니다".into());
        }
    }
    // 정리에 쓰는 열 외에도 전체 계약의 스키마가 남아 있는지 먼저 확인한다.
    conn.prepare(&format!("SELECT {ITEM_COLUMNS} FROM queue_items LIMIT 0"))?;
    let count: u64 = conn.query_row("SELECT COUNT(*) FROM queue_meta", [], |row| row.get(0))?;
    let (target, limits) = metadata(conn)?.ok_or("큐 대상 기록이 없어 정리를 거부합니다")?;
    if count != 1 || !valid_id(&target.agent_id) || !valid_id(&target.key_id) {
        return Err("큐 대상 기록이 유효하지 않습니다".into());
    }
    crate::public_key(&target.pinned_pubkey)?;
    limits.validate()?;
    let active: u64 = conn.query_row("SELECT COUNT(*) FROM queue_items", [], |r| r.get(0))?;
    if active > MAX_ITEMS {
        return Err("활성 큐 절대 상한 초과".into());
    }
    if version >= 2 {
        conn.prepare("SELECT lease_token,lease_expires_ms FROM queue_items LIMIT 0")?;
        conn.prepare(&format!(
            "SELECT {ITEM_COLUMNS} FROM receipt_archive LIMIT 0"
        ))?;
        let archived: u64 =
            conn.query_row("SELECT COUNT(*) FROM receipt_archive", [], |r| r.get(0))?;
        if archived.saturating_add(active) > MAX_ARCHIVE_ITEMS {
            return Err("큐 수신증명 보관 상한 초과".into());
        }
        let bad: u64 = conn.query_row("SELECT COUNT(*) FROM queue_items WHERE state!='pending' OR receipt_json IS NOT NULL OR sent_at_ms IS NOT NULL OR ((lease_token IS NULL)!=(lease_expires_ms IS NULL))", [], |r| r.get(0))?;
        let duplicates: u64 = conn.query_row("SELECT COUNT(*) FROM queue_items q JOIN receipt_archive a ON q.id=a.id OR (q.kind=a.kind AND q.sha256=a.sha256)", [], |r| r.get(0))?;
        let bad_archive:u64=conn.query_row("SELECT COUNT(*) FROM receipt_archive WHERE state!='sent' OR receipt_json IS NULL OR sent_at_ms IS NULL OR lease_token IS NOT NULL OR lease_expires_ms IS NOT NULL",[],|r|r.get(0))?;
        if bad != 0 || duplicates != 0 || bad_archive != 0 {
            return Err("활성 큐/수신증명 보관 스키마 상태 오류".into());
        }
    }
    if version >= 3 {
        jobs::validate_schema(conn)?;
    }
    Ok(())
}
fn verified_item(item: &QueueItem, target: &QueueTarget) -> Result<()> {
    let ack = item
        .receipt
        .as_ref()
        .ok_or("완료 항목에 수신증명이 없습니다")?;
    verify_receipt(ack, &target.pinned_pubkey)?;
    if !id_ok(&item.id)
        || item.state != "sent"
        || item.sent_at_ms.is_none()
        || ack.receipt.agent_id != target.agent_id
        || ack.receipt.key_id != target.key_id
        || ack.receipt.kind != item.kind
        || ack.receipt.sha256 != item.sha256
        || ack.receipt.size_bytes != item.size_bytes
    {
        return Err("완료 항목과 서명 수신증명이 일치하지 않습니다".into());
    }
    Ok(())
}
fn migrate(conn: &mut Connection) -> Result<()> {
    let version: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version == 1 {
        let (target, _) = metadata(conn)?.ok_or("큐 대상 없음")?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {ITEM_COLUMNS} FROM queue_items WHERE state='sent'"
        ))?;
        for row in stmt.query_map([], decode)? {
            verified_item(&row?, &target)?;
        }
        let bad:u64=conn.query_row("SELECT COUNT(*) FROM queue_items WHERE state NOT IN ('pending','sent') OR (state='pending' AND (receipt_json IS NOT NULL OR sent_at_ms IS NOT NULL))",[],|r|r.get(0))?;
        if bad != 0 {
            return Err("기존 큐 상태가 유효하지 않아 마이그레이션을 거부합니다".into());
        }
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if version == 1 {
        tx.execute_batch("ALTER TABLE queue_items ADD COLUMN lease_token TEXT; ALTER TABLE queue_items ADD COLUMN lease_expires_ms INTEGER; CREATE TABLE receipt_archive AS SELECT * FROM queue_items WHERE state='sent'; CREATE UNIQUE INDEX archive_id ON receipt_archive(id); CREATE UNIQUE INDEX archive_object ON receipt_archive(kind,sha256); DELETE FROM queue_items WHERE state='sent';")?;
    }
    jobs::create_schema(&tx)?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}
fn decode(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueueItem> {
    let receipt: Option<String> = row.get(10)?;
    let receipt = receipt
        .map(|text| {
            serde_json::from_str(&text).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    10,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()?;
    Ok(QueueItem {
        id: row.get(0)?,
        kind: row.get(1)?,
        sha256: row.get(2)?,
        size_bytes: row.get(3)?,
        state: row.get(4)?,
        created_at_ms: row.get(5)?,
        attempts: row.get(6)?,
        next_retry_ms: row.get(7)?,
        last_error: row.get(8)?,
        sent_at_ms: row.get(9)?,
        receipt,
    })
}
fn id_ok(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn snapshot(directory: &Path, id: &str) -> Result<PathBuf> {
    if !id_ok(id) {
        return Err("큐 항목 ID 오류".into());
    }
    Ok(directory.join(OBJECTS).join(format!("{id}.bin")))
}
fn metadata(conn: &Connection) -> Result<Option<(QueueTarget, QueueLimits)>> {
    let row: Option<(String, u64, u64)> = conn
        .query_row(
            "SELECT target_json,max_items,max_bytes FROM queue_meta WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    row.map(|(json, max_items, max_bytes)| {
        Ok((
            serde_json::from_str(&json)?,
            QueueLimits {
                max_items,
                max_bytes,
            },
        ))
    })
    .transpose()
}
fn assert_target(conn: &Connection, target: &QueueTarget) -> Result<()> {
    let (stored, _) = metadata(conn)?.ok_or("큐 대상이 없습니다. 먼저 enqueue 하세요")?;
    if stored != *target {
        return Err("큐에 고정된 대상·에이전트·수신증명 키와 현재 설정이 다릅니다. 다른 대상을 위한 새 큐를 사용하세요".into());
    }
    Ok(())
}
fn cleanup(directory: &Path, conn: &Connection) -> Result<()> {
    let rows = {
        let mut stmt = conn.prepare("SELECT id,state FROM queue_items LIMIT 10001")?;
        let found = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if found.len() > MAX_ITEMS as usize {
            return Err("큐 기록의 절대 상한 초과".into());
        }
        if found
            .iter()
            .any(|(id, state)| !id_ok(id) || !matches!(state.as_str(), "pending" | "sent"))
        {
            return Err("큐 기록이 유효하지 않아 스냅샷 정리를 거부합니다".into());
        }
        found
    };
    let pending: BTreeSet<_> = rows
        .into_iter()
        .filter(|(_, s)| s == "pending")
        .map(|(id, _)| id)
        .collect();
    let mut removed = false;
    for (count, entry) in fs::read_dir(directory.join(OBJECTS))?.enumerate() {
        if count >= MAX_ITEMS as usize * 2 + 100 {
            return Err("큐 스냅샷 디렉터리 항목 상한 초과".into());
        }
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("큐 스냅샷 이름 오류")?;
        let meta = fs::symlink_metadata(entry.path())?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("큐 스냅샷 경로에 일반 파일 외 항목이 있습니다".into());
        }
        let temporary = name.starts_with(".argos-vault-") && name.ends_with(".tmp");
        let id = name.strip_suffix(".bin").filter(|id| id_ok(id));
        if temporary || id.is_some_and(|id| !pending.contains(id)) {
            if let Some(id) = id {
                if let Some(completed) = conn
                    .query_row(
                        &format!("SELECT {ITEM_COLUMNS} FROM receipt_archive WHERE id=?1"),
                        [id],
                        decode,
                    )
                    .optional()?
                {
                    verified_item(&completed, &metadata(conn)?.ok_or("큐 대상 없음")?.0)?;
                }
            }
            fs::remove_file(entry.path())?;
            removed = true;
        } else if id.is_none() {
            return Err("큐 스냅샷 디렉터리에 알 수 없는 파일이 있습니다".into());
        }
    }
    if removed {
        crate::sync_directory(&directory.join(OBJECTS))?;
    }
    Ok(())
}

/// 원본을 한 번 읽어 안정성을 검사하고 스냅샷을 디스크에 동기화한 다음 SQLite FULL로 게시한다.
/// 같은 큐의 kind+sha256은 기존 항목을 반환하며 완료 이력도 중복 생성하지 않는다.
pub fn enqueue(
    directory: &Path,
    config: &VaultConfig,
    source: &Path,
    kind: &str,
    limits: &QueueLimits,
) -> Result<QueueItem> {
    limits.validate()?;
    if !valid_kind(kind) {
        return Err("보관 종류 오류".into());
    }
    let target = QueueTarget::from_config(config)?;
    let bytes = read_bounded(source, config.max_object_bytes)?;
    let hash = sha256(&bytes);
    let (_lock, mut conn) = open_mutating(directory, Some((&target, limits)))?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert_target(&tx, &target)?;
    if let Some(item) = tx
        .query_row(
            &format!("SELECT {ITEM_COLUMNS} FROM queue_items WHERE kind=?1 AND sha256=?2 UNION ALL SELECT {ITEM_COLUMNS} FROM receipt_archive WHERE kind=?1 AND sha256=?2"),
            params![kind, hash],
            decode,
        )
        .optional()?
    {
        if item.state == "sent" {
            verified_item(&item, &target)?;
        } else {
            // 재등록 성공도 원본을 제거해도 되는 상태여야 한다. 기존 본문을 자동 수리하지 않는다.
            let path = snapshot(directory, &item.id)?;
            private_file(&path)?;
            let stored = read_bounded(&path, config.max_object_bytes)?;
            private_file(&path)?;
            if stored.len() as u64 != item.size_bytes || sha256(&stored) != item.sha256 {
                return Err("기존 pending 스냅샷 내용 불일치: 원본을 보존하고 큐를 점검하세요".into());
            }
        }
        tx.commit()?;
        return Ok(item);
    }
    let (count,pending_bytes):(u64,u64)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(CASE WHEN state='pending' THEN size_bytes ELSE 0 END),0) FROM queue_items",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    let archived: u64 = tx.query_row("SELECT COUNT(*) FROM receipt_archive", [], |r| r.get(0))?;
    if count.saturating_add(archived) >= MAX_ARCHIVE_ITEMS {
        return Err("수신증명 보관 상한(100000건)에 도달했습니다. 남은 항목 전송 뒤 export-archive하고 기존 큐를 보존한 채 새 경로를 사용하세요".into());
    }
    if count >= limits.max_items
        || pending_bytes.saturating_add(bytes.len() as u64) > limits.max_bytes
    {
        return Err("활성 큐 기록/본문 용량 상한에 도달했습니다. pending 항목을 전송하거나 상한을 검토하세요".into());
    }
    let mut random = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| "큐 ID 난수 생성 실패")?;
    let id = hex::encode(random);
    let path = snapshot(directory, &id)?;
    write_new(&path, &bytes)?;
    let now = crate::now_ms().min(i64::MAX as u64);
    let result = (|| -> Result<QueueItem> {
        tx.execute(
            "UPDATE queue_meta SET max_items=?1,max_bytes=?2 WHERE singleton=1",
            params![limits.max_items, limits.max_bytes],
        )?;
        tx.execute("INSERT INTO queue_items(id,kind,sha256,size_bytes,state,created_at_ms,next_retry_ms) VALUES(?1,?2,?3,?4,'pending',?5,?5)",params![id,kind,hash,bytes.len() as u64,now])?;
        let item = tx.query_row(
            &format!("SELECT {ITEM_COLUMNS} FROM queue_items WHERE id=?1"),
            [&id],
            decode,
        )?;
        tx.commit()?;
        Ok(item)
    })();
    // COMMIT 오류는 결과가 불확실할 수 있다. 스냅샷은 남기고 다음 SQLite 복구 후 정리한다.
    result
}

fn open_readonly(directory: &Path) -> Result<Connection> {
    validate_private_directory(directory)?;
    private_file(&directory.join(DB))?;
    let conn = Connection::open_with_flags(
        directory.join(DB),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_secs(2))?;
    validate_database(&conn)?;
    Ok(conn)
}
fn item_source(conn: &Connection) -> Result<String> {
    let version: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    Ok(if version == 1 {
        "queue_items".into()
    } else {
        format!("(SELECT {ITEM_COLUMNS} FROM queue_items UNION ALL SELECT {ITEM_COLUMNS} FROM receipt_archive)")
    })
}
/// 읽기 전용. 이전 형식도 조회하되 마이그레이션·파일 정리·통신을 하지 않는다.
pub fn status(directory: &Path) -> Result<QueueStatus> {
    let conn = open_readonly(directory)?;
    let tx = conn.unchecked_transaction()?;
    let meta = metadata(&tx)?;
    let source = item_source(&tx)?;
    let (items_total,pending_items,sent_items,pending_bytes,failed_items,earliest_retry_ms):(u64,u64,u64,u64,u64,Option<u64>)=tx.query_row(&format!("SELECT COUNT(*),COALESCE(SUM(state='pending'),0),COALESCE(SUM(state='sent'),0),COALESCE(SUM(CASE WHEN state='pending' THEN size_bytes ELSE 0 END),0),COALESCE(SUM(state='pending' AND last_error IS NOT NULL),0),MIN(CASE WHEN state='pending' THEN next_retry_ms END) FROM {source}"),[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
    let version: u32 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let earliest_retry_ms = if version == 1 {
        earliest_retry_ms
    } else {
        tx.query_row(
            "SELECT MIN(MAX(next_retry_ms,COALESCE(lease_expires_ms,0))) FROM queue_items",
            [],
            |r| r.get(0),
        )?
    };
    let leased_items = if version == 1 {
        0
    } else {
        tx.query_row(
            "SELECT COUNT(*) FROM queue_items WHERE lease_expires_ms>?1",
            [crate::now_ms()],
            |r| r.get(0),
        )?
    };
    let items = {
        let mut stmt = tx.prepare(&format!("SELECT {ITEM_COLUMNS} FROM {source} ORDER BY created_at_ms DESC,id DESC LIMIT {STATUS_ITEMS}"))?;
        let items = stmt
            .query_map([], decode)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if let Some((target, _)) = &meta {
            for item in &items {
                if item.state == "sent" {
                    verified_item(item, target)?;
                }
            }
        }
        items
    };
    let bundle_jobs = jobs::status_with_conn(&tx)?;
    tx.commit()?;
    Ok(QueueStatus {
        target: meta.as_ref().map(|m| m.0.clone()),
        limits: meta.map(|m| m.1),
        items_total,
        pending_items,
        sent_items,
        pending_bytes,
        failed_items,
        earliest_retry_ms,
        leased_items,
        archive_items: sent_items,
        archive_capacity: MAX_ARCHIVE_ITEMS,
        archive_slots_available: MAX_ARCHIVE_ITEMS.saturating_sub(items_total),
        items_truncated: items_total > items.len() as u64,
        items,
        bundle_jobs,
    })
}
/// 임의 활성 항목 또는 오래된 완료 수신증명을 읽고 완료 서명을 검증한다.
pub fn item(directory: &Path, id: &str) -> Result<QueueItem> {
    if !id_ok(id) {
        return Err("큐 ID는 소문자 hex 32자여야 합니다".into());
    }
    let conn = open_readonly(directory)?;
    let tx = conn.unchecked_transaction()?;
    let source = item_source(&tx)?;
    let item = tx
        .query_row(
            &format!("SELECT {ITEM_COLUMNS} FROM {source} WHERE id=?1"),
            [id],
            decode,
        )
        .optional()?
        .ok_or("큐 항목을 찾을 수 없습니다")?;
    if item.state == "sent" {
        verified_item(&item, &metadata(&tx)?.ok_or("큐 대상 없음")?.0)?;
    }
    tx.commit()?;
    Ok(item)
}

mod jobs;
pub use jobs::{
    bundle_job, bundle_jobs, enqueue_bundle, BundleChunkRef, BundleJob, BundleJobOutcome,
    BundleJobSummary, BundleJobsStatus,
};
mod archive;
pub use archive::{export_archive, verify_archive, ArchiveExportReport, ArchiveVerification};

fn retry_delay(attempts: u32) -> u64 {
    5000u64
        .saturating_mul(1u64 << attempts.saturating_sub(1).min(10))
        .min(3_600_000)
}

struct Lease {
    item: QueueItem,
    token: String,
}
fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| "큐 임대 난수 생성 실패")?;
    Ok(hex::encode(bytes))
}
fn claim(
    directory: &Path,
    target: &QueueTarget,
    timeout_secs: u64,
    now: u64,
) -> Result<Option<Lease>> {
    let (_lock, mut conn) = open_mutating(directory, None)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert_target(&tx, target)?;
    let now = now.max(crate::now_ms()).min(i64::MAX as u64);
    let item = tx.query_row(&format!("SELECT {ITEM_COLUMNS} FROM queue_items WHERE next_retry_ms<=?1 AND (lease_expires_ms IS NULL OR lease_expires_ms<=?1) ORDER BY created_at_ms,id LIMIT 1"),[now],decode).optional()?;
    let Some(mut item) = item else {
        tx.commit()?;
        return Ok(None);
    };
    if !valid_kind(&item.kind)
        || !valid_hash(&item.sha256)
        || item.size_bytes > MAX_OBJECT_BYTES as u64
    {
        return Err("큐 항목 메타데이터 오류".into());
    }
    let token = random_id()?;
    let expires = now
        .saturating_add(timeout_secs.saturating_mul(1000))
        .saturating_add(LEASE_GRACE_MS)
        .min(i64::MAX as u64);
    item.attempts = item.attempts.saturating_add(1);
    let next = now
        .saturating_add(retry_delay(item.attempts))
        .min(i64::MAX as u64);
    tx.execute("UPDATE queue_items SET lease_token=?1,lease_expires_ms=?2,attempts=?3,next_retry_ms=?4,last_error='interrupted_or_unconfirmed' WHERE id=?5",params![token,expires,item.attempts,next,item.id])?;
    tx.commit()?;
    Ok(Some(Lease { item, token }))
}
/// 완료/실패 시 임대 소유권을 다시 확인한다. 오래된 작업자는 새 임대의 상태나 본문을 바꾸지 못한다.
fn finish(
    directory: &Path,
    target: &QueueTarget,
    lease: &Lease,
    result: &std::result::Result<SignedReceipt, &'static str>,
    now: u64,
) -> Result<bool> {
    let (_lock, mut conn) = open_mutating(directory, None)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert_target(&tx, target)?;
    let now = now.max(crate::now_ms()).min(i64::MAX as u64);
    let owns:bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM queue_items WHERE id=?1 AND lease_token=?2 AND lease_expires_ms>?3)",params![lease.item.id,lease.token,now],|r|r.get(0))?;
    if !owns {
        tx.commit()?;
        return Ok(false);
    }
    if let Ok(receipt) = result {
        let mut completed = lease.item.clone();
        completed.state = "sent".into();
        completed.receipt = Some(receipt.clone());
        completed.sent_at_ms = Some(now);
        verified_item(&completed, target)?;
        tx.execute("INSERT INTO receipt_archive(id,kind,sha256,size_bytes,state,created_at_ms,attempts,next_retry_ms,last_error,sent_at_ms,receipt_json) SELECT id,kind,sha256,size_bytes,'sent',created_at_ms,attempts,0,NULL,?1,?2 FROM queue_items WHERE id=?3 AND lease_token=?4",params![now,serde_json::to_string(receipt)?,lease.item.id,lease.token])?;
        tx.execute(
            "DELETE FROM queue_items WHERE id=?1 AND lease_token=?2",
            params![lease.item.id, lease.token],
        )?;
        tx.commit()?;
        // 완료 archive COMMIT 이후에만 지운다. 중단하면 다음 mutating open에서 정리한다.
        fs::remove_file(snapshot(directory, &lease.item.id)?)?;
        crate::sync_directory(&directory.join(OBJECTS))?;
    } else {
        let retry = now
            .saturating_add(retry_delay(lease.item.attempts))
            .min(i64::MAX as u64);
        tx.execute("UPDATE queue_items SET lease_token=NULL,lease_expires_ms=NULL,next_retry_ms=?1,last_error=?2 WHERE id=?3 AND lease_token=?4",params![retry,result.as_ref().err().copied().unwrap_or("unknown"),lease.item.id,lease.token])?;
        tx.commit()?;
    }
    Ok(true)
}
/// 항목별 임대를 먼저 커밋하고 잠금과 DB를 닫은 뒤 네트워크를 사용한다.
/// enqueue는 전송 대기 시간과 무관하며 중단된 임대는 만료 후 다른 작업자가 재처리한다.
pub fn drain_once(
    directory: &Path,
    config: &VaultConfig,
    options: &DrainOptions,
) -> Result<DrainReport> {
    if !(1..=100).contains(&options.max_items) {
        return Err("drain 배치는 1~100개입니다".into());
    }
    let target = QueueTarget::from_config(config)?;
    client::token(&config.upload_token)?;
    let mut report = DrainReport {
        attempted: 0,
        sent: 0,
        failed: 0,
        remaining_pending: 0,
        items: vec![],
        attempted_jobs: 0,
        completed_jobs: 0,
        failed_jobs: 0,
        remaining_jobs: 0,
        jobs: vec![],
    };
    for _ in 0..options.max_items {
        if let Some(outcome) = jobs::drain_one(directory, config, &target)? {
            report.attempted_jobs += 1;
            if outcome.completed {
                report.completed_jobs += 1;
            }
            if outcome.error.is_some() {
                report.failed_jobs += 1;
            }
            report.jobs.push(outcome);
            continue;
        }
        let Some(lease) = claim(directory, &target, config.timeout_secs, crate::now_ms())? else {
            break;
        };
        report.attempted += 1;
        let result = (|| -> std::result::Result<SignedReceipt, &'static str> {
            let path = snapshot(directory, &lease.item.id).map_err(|_| "queue_local")?;
            private_file(&path).map_err(|_| "queue_local")?;
            let bytes = read_bounded(&path, config.max_object_bytes).map_err(|_| "queue_local")?;
            if bytes.len() as u64 != lease.item.size_bytes || sha256(&bytes) != lease.item.sha256 {
                return Err("queue_local");
            }
            let receipt = client::upload_bytes(config, bytes, &lease.item.kind)
                .map_err(|e| client::error_code(e.as_ref()))?;
            let mut completed = lease.item.clone();
            completed.state = "sent".into();
            completed.receipt = Some(receipt.clone());
            completed.sent_at_ms = Some(crate::now_ms());
            verified_item(&completed, &target).map_err(|_| "response_integrity")?;
            Ok(receipt)
        })();
        let committed = finish(directory, &target, &lease, &result, crate::now_ms())?;
        let sent = committed && result.is_ok();
        let error = if !committed {
            Some("lease_expired_or_replaced".into())
        } else if let Err(code) = &result {
            Some((*code).into())
        } else {
            None
        };
        if sent {
            report.sent += 1;
        } else {
            report.failed += 1;
        }
        report.items.push(DrainOutcome {
            id: lease.item.id,
            sent,
            error,
            receipt: if sent { result.ok() } else { None },
        });
    }
    let current = status(directory)?;
    report.remaining_pending = current.pending_items;
    report.remaining_jobs = current.bundle_jobs.pending;
    Ok(report)
}

#[cfg(test)]
mod tests;
