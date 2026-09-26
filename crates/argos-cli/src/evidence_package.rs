use argos_common::AgentConfig;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_BYTES: usize = 64 * 1024 * 1024;

pub fn export(
    config: &AgentConfig,
    id: i64,
    directory: &Path,
    span_secs: u64,
    limit: usize,
    sensitive: bool,
) -> Result<()> {
    let store = argos_storage::EventStore::open_readonly(&config.db_path)?;
    let detection = store.detection_by_id(id)?.ok_or("탐지 ID가 없습니다")?;
    let span = span_secs
        .checked_mul(1000)
        .filter(|v| *v > 0)
        .ok_or("유효한 시간 범위 필요")?;
    let ts = u64::try_from(detection.timestamp_ms)?;
    let query = argos_storage::EvidenceQuery {
        from_ms: ts.saturating_sub(span),
        to_ms: ts.saturating_add(span).min(i64::MAX as u64),
        pid: None,
        limit,
    };
    let evidence = store.query_evidence(&query)?;
    let response = store.response_results(&query)?;
    let policy = if config.policy.is_enabled() {
        let path = argos_policy::policy_state_path(&config.policy, &config.db_path);
        json!({"mode":"last_accepted_signed_policy","state":argos_policy::read_state(&path,100)?,"policy":argos_policy::load_active_policy(&path)?})
    } else {
        json!({"mode":"local_unsigned_configuration_at_export","detection":config.detection,"response":config.response})
    };
    let data = json!({"incident":detection,"evidence":evidence,"response_results":response});
    write_package(
        directory,
        BTreeMap::from([("evidence.json", data), ("policy.json", policy)]),
        sensitive,
    )?;
    println!("사고 증거 패키지: {}", directory.display());
    Ok(())
}

fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if (key == "id" && value.is_string())
                    || matches!(
                        key.as_str(),
                        "path"
                            | "paths"
                            | "exe"
                            | "cmdline"
                            | "comm"
                            | "summary"
                            | "reason"
                            | "error"
                            | "note"
                            | "trust_note"
                            | "exclude_paths"
                            | "protected_paths"
                            | "canary_paths"
                            | "host_id"
                            | "target_hosts"
                            | "target_groups"
                            | "policy_id"
                            | "key_id"
                            | "approval_id"
                    )
                {
                    *value = json!("[REDACTED]");
                } else {
                    redact(value);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact(item);
            }
        }
        _ => {}
    }
}

fn write_package(
    directory: &Path,
    mut files: BTreeMap<&str, Value>,
    sensitive: bool,
) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory)?; // exclusive destination; never replace an existing package
    let mut hashes = serde_json::Map::new();
    for (name, value) in &mut files {
        if !sensitive {
            redact(value);
        }
        let bytes = serde_json::to_vec_pretty(value)?;
        if bytes.len() > MAX_BYTES {
            return Err("패키지 파일 크기 상한 초과; 조회 범위를 줄이세요".into());
        }
        write_new(&directory.join(name), &bytes)?;
        hashes.insert(
            (*name).into(),
            json!({"sha256":format!("{:x}",Sha256::digest(&bytes)),"size_bytes":bytes.len()}),
        );
    }
    let manifest = json!({"format":"argos-evidence-v1","collected_at_ms":argos_common::now_ms(),"include_sensitive":sensitive,"redaction":if sensitive {"none"}else{"paths, executable/command, summaries, freeform notes and identity labels removed; timestamps/event IDs/PIDs/UIDs retained"},"coverage":"Per-source counts and truncation are in evidence.json. Evidence, response and policy are separate read snapshots, not a forensic image or a global atomic snapshot.","integrity":"SHA-256 verifies file consistency, not origin authenticity. Keep the manifest in a trusted location.","files":hashes});
    write_new(
        &directory.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err("패키지 파일은 symlink가 아닌 일반 파일이어야 합니다".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err("일반 파일 아님".into());
    }
    let mut data = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut data)?;
    if data.len() > MAX_BYTES {
        return Err("패키지 파일 크기 상한 초과".into());
    }
    Ok(data)
}

pub fn verify(directory: &Path) -> Result<()> {
    let manifest: Value = serde_json::from_slice(&read_file(&directory.join("manifest.json"))?)?;
    if manifest["format"] != "argos-evidence-v1" {
        return Err("지원하지 않는 패키지 형식".into());
    }
    let files = manifest["files"]
        .as_object()
        .ok_or("manifest 파일 목록 없음")?;
    if files.len() != 2
        || !files.contains_key("evidence.json")
        || !files.contains_key("policy.json")
    {
        return Err("예상한 증거 파일 목록과 다름".into());
    }
    for (name, info) in files {
        let bytes = read_file(&directory.join(name))?;
        if info["size_bytes"].as_u64() != Some(bytes.len() as u64)
            || info["sha256"].as_str() != Some(&format!("{:x}", Sha256::digest(&bytes)))
        {
            return Err(format!("증거 파일 무결성 검증 실패: {name}").into());
        }
    }
    if fs::read_dir(directory)?.count() != 3 {
        return Err("manifest에 없는 추가 파일 존재".into());
    }
    println!("증거 패키지 SHA-256 검증 성공: {}", directory.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn package_redacts_preserves_ids_detects_tamper_and_refuses_overwrite() {
        let root = std::env::temp_dir().join(format!(
            "argos-evidence-package-{}-{}",
            std::process::id(),
            argos_common::now_ms()
        ));
        let files = BTreeMap::from([
            (
                "evidence.json",
                json!({"id":42,"cmdline":"secret","files":{"truncated":true,"rows":[{"path":"/secret","id":3}]}}),
            ),
            (
                "policy.json",
                json!({"version":7,"approved_changes":[{"id":"private-ticket-title"}]}),
            ),
        ]);
        write_package(&root, files.clone(), false).unwrap();
        verify(&root).unwrap();
        let value: Value =
            serde_json::from_slice(&fs::read(root.join("evidence.json")).unwrap()).unwrap();
        assert_eq!(value["id"], 42);
        assert_eq!(value["cmdline"], "[REDACTED]");
        assert_eq!(value["files"]["truncated"], true);
        let policy: Value =
            serde_json::from_slice(&fs::read(root.join("policy.json")).unwrap()).unwrap();
        assert_eq!(policy["approved_changes"][0]["id"], "[REDACTED]");
        assert!(write_package(&root, files, false).is_err());
        fs::write(root.join("evidence.json"), b"{}").unwrap();
        assert!(verify(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
