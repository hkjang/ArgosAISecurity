//! 별도 호스트의 추가 전용 보관 API와 고정 공개키로 검증하는 수신증명.
//! 디스크 관리자/root가 보관 데이터를 바꾸지 못하게 하는 WORM 구현은 아니다.
pub mod bundle;
mod client;
pub mod queue;
mod quota;
mod server;
pub use client::{fetch_file, fetch_usage, upload_file, VaultConfig};
pub use quota::{
    AgentCapacityLimit, AgentCapacityUsage, CapacityConfig, CapacityUsage, FilesystemCapacity,
    ObjectUsage,
};
pub use server::{load_server_config, router, ServerConfig};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 16 * 1024;
const FORMAT: &str = "argos-vault-receipt-v1";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub format: String,
    pub key_id: String,
    pub agent_id: String,
    pub kind: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub received_at_ms: u64,
    pub retention_until_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    pub signature_hex: String,
}

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_kind(value: &str) -> bool {
    matches!(
        value,
        "evidence" | "backup" | "audit" | "bundle-manifest" | "bundle-completion" | "bundle-review"
    )
}
fn public_key(hex_key: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_key)?
        .try_into()
        .map_err(|_| "공개키는 32바이트 hex여야 합니다")?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}
fn sign(receipt: Receipt, key: &SigningKey) -> Result<SignedReceipt> {
    let signature_hex = hex::encode(key.sign(&serde_json::to_vec(&receipt)?).to_bytes());
    Ok(SignedReceipt {
        receipt,
        signature_hex,
    })
}

/// 서명 형식·필드와 서명을 검사한다. 키는 수신증명 자체가 아닌 신뢰 설정에서 받는다.
pub fn verify_receipt(receipt: &SignedReceipt, pinned_pubkey: &str) -> Result<()> {
    let value = &receipt.receipt;
    if value.format != FORMAT
        || !valid_id(&value.key_id)
        || !valid_id(&value.agent_id)
        || !valid_kind(&value.kind)
        || !valid_hash(&value.sha256)
        || value.size_bytes > MAX_OBJECT_BYTES as u64
        || value.retention_until_ms <= value.received_at_ms
    {
        return Err("수신증명 필드/형식이 유효하지 않습니다".into());
    }
    let signature: [u8; 64] = hex::decode(&receipt.signature_hex)?
        .try_into()
        .map_err(|_| "서명은 64바이트 hex여야 합니다")?;
    public_key(pinned_pubkey)?.verify(
        &serde_json::to_vec(value)?,
        &Signature::from_bytes(&signature),
    )?;
    Ok(())
}

pub fn verify_file(path: &Path, receipt: &SignedReceipt, pinned_pubkey: &str) -> Result<()> {
    verify_receipt(receipt, pinned_pubkey)?;
    let bytes = read_bounded(path, MAX_OBJECT_BYTES)?;
    verify_body(&bytes, receipt)
}
fn verify_body(bytes: &[u8], receipt: &SignedReceipt) -> Result<()> {
    if receipt.receipt.size_bytes != bytes.len() as u64 || receipt.receipt.sha256 != sha256(bytes) {
        return Err("수신증명의 크기/해시와 본문이 다릅니다".into());
    }
    Ok(())
}

pub fn read_receipt(path: &Path) -> Result<SignedReceipt> {
    Ok(serde_json::from_slice(&read_bounded(
        path,
        MAX_RECEIPT_BYTES,
    )?)?)
}
pub fn write_receipt_new(path: &Path, receipt: &SignedReceipt) -> Result<()> {
    write_new(path, &serde_json::to_vec_pretty(receipt)?)
}

/// 전용 키 디렉터리를 먼저 만들고 권한을 0700으로 설정해야 한다.
pub fn generate_signing_key_file(path: &Path) -> Result<String> {
    validate_private_directory(path.parent().ok_or("키 부모 경로가 없습니다")?)?;
    let key = SigningKey::generate(&mut rand_core::OsRng);
    write_new(path, hex::encode(key.to_bytes()).as_bytes())?;
    Ok(hex::encode(key.verifying_key().to_bytes()))
}

pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    read_bounded_with_check(path, limit, || {})
}

fn read_bounded_with_check(
    path: &Path,
    limit: usize,
    after_read: impl FnOnce(),
) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > limit as u64 {
        return Err("일반 파일과 크기 상한만 허용합니다".into());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    after_read();
    let after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    let mut stable = before.len() == after.len()
        && before.modified()? == after.modified()?
        && path_after.is_file()
        && !path_after.file_type().is_symlink()
        && bytes.len() as u64 == before.len()
        && bytes.len() <= limit;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        stable &= before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && before.dev() == path_after.dev()
            && before.ino() == path_after.ino();
    }
    if !stable {
        return Err("읽는 동안 파일 내용/경로가 변경되었습니다".into());
    }
    Ok(bytes)
}

/// 완성한 임시 파일을 하드링크로 독점 게시하고 디렉터리까지 동기화한다.
/// 기존 대상·심볼릭 링크를 덮어쓰지 않는다. 부모 경로는 신뢰하는 운영 경로여야 한다.
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(
        ".argos-vault-{}-{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temporary, path)?;
        fs::remove_file(&temporary)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

pub(crate) fn validate_private_directory(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, std::path::Component::ParentDir))
    {
        return Err("보관/키 경로는 .. 없는 절대 경로여야 합니다".into());
    }
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("보관/키 디렉터리와 상위 경로에 심볼릭 링크를 허용하지 않습니다".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let uid = unsafe { libc::geteuid() };
            if metadata.uid() != uid && metadata.uid() != 0 {
                return Err("보관/키 상위 디렉터리 소유자를 신뢰할 수 없습니다".into());
            }
            if metadata.mode() & 0o022 != 0
                && !(metadata.mode() & 0o1000 != 0 && metadata.uid() == 0)
            {
                return Err("보관/키 상위 디렉터리는 다른 계정이 쓰기 가능하면 안 됩니다".into());
            }
            if current == path && (metadata.uid() != uid || metadata.mode() & 0o777 != 0o700) {
                return Err("전용 보관/키 디렉터리는 현재 계정 소유 0700이어야 합니다".into());
            }
        }
    }
    Ok(())
}
fn load_key(path: &Path) -> Result<SigningKey> {
    validate_private_directory(path.parent().ok_or("키 부모 경로가 없습니다")?)?;
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err("서명키는 현재 계정 소유 0600 단일 링크 파일이어야 합니다".into());
        }
    }
    let bytes = read_bounded(path, 128)?;
    let bytes: [u8; 32] = hex::decode(std::str::from_utf8(&bytes)?.trim())?
        .try_into()
        .map_err(|_| "서명키는 32바이트 hex여야 합니다")?;
    Ok(SigningKey::from_bytes(&bytes))
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests;
