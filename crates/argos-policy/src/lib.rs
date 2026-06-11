//! Argos Policy: Ed25519 서명 기반 정책 배포 (요건서 11장 — 서명된 정책만 적용).
//!
//! 운영 흐름:
//! 1. 관리 머신에서 `argos policy gen-key` → 서명키(비밀)·검증키(공개) 생성
//! 2. 정책 파일(policy.toml) 작성 후 `argos policy sign --key-file <서명키>`
//!    → `policy.toml.sig` 생성
//! 3. 에이전트는 argos.toml의 `[policy] pubkey`로 서명을 검증하고,
//!    검증 실패 시 정책을 **적용하지 않는다**.
//!
//! 서명 대상은 정책 파일의 바이트 그대로다 — 정규화 과정이 없어 단순하고,
//! 파일이 1바이트라도 바뀌면 검증이 실패한다.

use argos_common::config::{DetectionConfig, ResponseConfig};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("IO 오류 ({path}): {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("키 형식 오류: {0}")]
    KeyFormat(String),
    #[error("서명 검증 실패 — 정책이 변조되었거나 다른 키로 서명되었습니다")]
    InvalidSignature,
    #[error("정책 파일 형식 오류: {0}")]
    Parse(#[from] toml::de::Error),
}

fn io_err(path: &Path, source: std::io::Error) -> PolicyError {
    PolicyError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// 배포 가능한 정책 본문. 에이전트 설정의 탐지·대응 섹션을 덮어쓴다.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// 정책 버전 — 롤백·감사 추적용 (요건서 13장).
    pub version: u64,
    pub detection: DetectionConfig,
    pub response: ResponseConfig,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: 0,
            detection: DetectionConfig::default(),
            response: ResponseConfig::default(),
        }
    }
}

/// 새 키쌍 생성. 반환: (서명키 hex 64자, 검증키 hex 64자).
pub fn gen_keypair() -> (String, String) {
    let signing = SigningKey::generate(&mut rand_core::OsRng);
    (
        hex::encode(signing.to_bytes()),
        hex::encode(signing.verifying_key().to_bytes()),
    )
}

fn parse_signing_key(secret_hex: &str) -> Result<SigningKey, PolicyError> {
    let bytes: [u8; 32] = hex::decode(secret_hex.trim())
        .map_err(|e| PolicyError::KeyFormat(e.to_string()))?
        .try_into()
        .map_err(|_| PolicyError::KeyFormat("서명키는 32바이트(hex 64자)여야 합니다".into()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn parse_verifying_key(pub_hex: &str) -> Result<VerifyingKey, PolicyError> {
    let bytes: [u8; 32] = hex::decode(pub_hex.trim())
        .map_err(|e| PolicyError::KeyFormat(e.to_string()))?
        .try_into()
        .map_err(|_| PolicyError::KeyFormat("검증키는 32바이트(hex 64자)여야 합니다".into()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| PolicyError::KeyFormat(e.to_string()))
}

/// 바이트 서명 → hex 128자.
pub fn sign_bytes(data: &[u8], secret_hex: &str) -> Result<String, PolicyError> {
    let key = parse_signing_key(secret_hex)?;
    Ok(hex::encode(key.sign(data).to_bytes()))
}

/// 서명 검증. 실패 시 InvalidSignature.
pub fn verify_bytes(data: &[u8], sig_hex: &str, pub_hex: &str) -> Result<(), PolicyError> {
    let key = parse_verifying_key(pub_hex)?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex.trim())
        .map_err(|e| PolicyError::KeyFormat(e.to_string()))?
        .try_into()
        .map_err(|_| PolicyError::KeyFormat("서명은 64바이트(hex 128자)여야 합니다".into()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    key.verify(data, &sig)
        .map_err(|_| PolicyError::InvalidSignature)
}

/// 정책 파일 서명 → `<policy>.sig` 파일 생성. 반환: 서명 파일 경로.
pub fn sign_file(policy_path: &Path, secret_hex: &str) -> Result<std::path::PathBuf, PolicyError> {
    let data = std::fs::read(policy_path).map_err(|e| io_err(policy_path, e))?;
    let sig = sign_bytes(&data, secret_hex)?;
    let sig_path = sig_path_for(policy_path);
    std::fs::write(&sig_path, sig).map_err(|e| io_err(&sig_path, e))?;
    Ok(sig_path)
}

/// 정책 파일 + 서명 파일 검증.
pub fn verify_file(policy_path: &Path, pub_hex: &str) -> Result<(), PolicyError> {
    let data = std::fs::read(policy_path).map_err(|e| io_err(policy_path, e))?;
    let sig_path = sig_path_for(policy_path);
    let sig = std::fs::read_to_string(&sig_path).map_err(|e| io_err(&sig_path, e))?;
    verify_bytes(&data, &sig, pub_hex)
}

/// 서명 검증을 통과한 경우에만 정책을 파싱해 반환한다.
pub fn load_verified(policy_path: &Path, pub_hex: &str) -> Result<Policy, PolicyError> {
    verify_file(policy_path, pub_hex)?;
    let text = std::fs::read_to_string(policy_path).map_err(|e| io_err(policy_path, e))?;
    let policy: Policy = toml::from_str(&text)?;
    tracing::info!(version = policy.version, "서명 검증된 정책 로드");
    Ok(policy)
}

pub fn sig_path_for(policy_path: &Path) -> std::path::PathBuf {
    let mut s = policy_path.as_os_str().to_owned();
    s.push(".sig");
    std::path::PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let (secret, public) = gen_keypair();
        let data = b"version = 3\n[detection]\nwindow_secs = 5\n";
        let sig = sign_bytes(data, &secret).unwrap();
        verify_bytes(data, &sig, &public).unwrap();
    }

    #[test]
    fn tampered_data_fails() {
        let (secret, public) = gen_keypair();
        let sig = sign_bytes(b"original", &secret).unwrap();
        let err = verify_bytes(b"tampered", &sig, &public).unwrap_err();
        assert!(matches!(err, PolicyError::InvalidSignature));
    }

    #[test]
    fn wrong_key_fails() {
        let (secret, _) = gen_keypair();
        let (_, other_public) = gen_keypair();
        let sig = sign_bytes(b"data", &secret).unwrap();
        let err = verify_bytes(b"data", &sig, &other_public).unwrap_err();
        assert!(matches!(err, PolicyError::InvalidSignature));
    }

    #[test]
    fn file_roundtrip_and_load() {
        let dir = std::env::temp_dir().join(format!("argos-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let policy_path = dir.join("policy.toml");
        std::fs::write(
            &policy_path,
            "version = 7\n[detection]\nwindow_secs = 5\n[response]\nblock_score = 90.0\n",
        )
        .unwrap();

        let (secret, public) = gen_keypair();
        sign_file(&policy_path, &secret).unwrap();

        let policy = load_verified(&policy_path, &public).unwrap();
        assert_eq!(policy.version, 7);
        assert_eq!(policy.detection.window_secs, 5);
        assert_eq!(policy.response.block_score, 90.0);

        // 변조 후에는 로드가 거부되어야 한다.
        std::fs::write(&policy_path, "version = 8\n").unwrap();
        assert!(load_verified(&policy_path, &public).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
