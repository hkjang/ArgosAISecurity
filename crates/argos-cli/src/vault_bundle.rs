//! 원본 에이전트 설정·DB 없이 원격 묶음만으로 복구 시험을 수행한다.
use super::{convert, load_config, write_new, Result};
use argos_recovery::service::{self, ServiceRecoveryPlan};
use argos_vault::{bundle, queue, VaultConfig};
use clap::{Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const PLAN_BYTES: usize = 65_536;
const HISTORY_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, ValueEnum)]
pub(super) enum Decision {
    Good,
    Revoked,
}

#[derive(Subcommand)]
pub(super) enum Action {
    /// 최대 1GiB 파일을 16MiB 청크와 구성 목록으로 준비 (통신 없음)
    Prepare {
        #[arg(long)]
        file: PathBuf,
        /// 전용 0700 부모 아래 존재하지 않는 절대 경로
        #[arg(long)]
        out: PathBuf,
        /// 원본 경로에 대한 주장. 자동 복원 목적지로 사용하지 않음
        #[arg(long)]
        original_path: String,
        #[arg(long)]
        version: Option<i64>,
        #[arg(long)]
        plan: Option<PathBuf>,
        /// 원본의 판정 이력 JSON. 원격 정상 판정을 대신하지 않음
        #[arg(long)]
        review_history: Option<PathBuf>,
    },
    /// 청크·구성 목록·완료 요청을 영속 작업으로 원자적 등록 (통신 없음)
    Enqueue {
        #[arg(long)]
        stage: PathBuf,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long, default_value_t = 1000)]
        max_items: u64,
        #[arg(long, default_value_t = 268_435_456)]
        max_bytes: u64,
    },
    /// 구성 목록 등록 후 모든 청크가 보관됐는지 검증하여 완료 표시
    Publish {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// 청크를 직접 전송하고 구성 목록 완료 (재실행 시 같은 해시 재사용)
    Upload {
        #[arg(long)]
        stage: PathBuf,
    },
    /// 원격 에이전트의 완성·미완성 묶음 목록
    List {
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// 구성 목록·완료 증명·현재 원격 정상 판정 조회
    Show {
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        id: String,
    },
    /// 서명·청크·전체 해시 검증 후 새 파일로 재조립
    Fetch {
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        out: PathBuf,
        /// 정상 판정이 없는 완성 묶음도 조사 목적으로 받기 (복구 추천 아님)
        #[arg(long)]
        evidence_only: bool,
    },
    /// 관리자 토큰으로 정상 판정·취소 이력 추가 (원본 증거는 보존)
    Review {
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        id: String,
        /// 동일 검토 요청의 재시도에 사용할 고유 ID
        #[arg(long)]
        request_id: String,
        #[arg(long, value_enum)]
        decision: Decision,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        reason: String,
    },
    /// 원격 정상본을 새 경로에 받아 내장 계획으로 DB 복구 시험
    Test {
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        id: String,
        /// 전용 0700 부모 아래 존재하지 않는 절대 경로
        #[arg(long)]
        out: PathBuf,
        /// 미확인 완성 묶음을 실제 격리 환경에서 승인 전 시험 (정상본 승인 아님)
        #[arg(long)]
        preapproval: bool,
    },
}

pub(super) fn run(action: Action, config_path: Option<PathBuf>) -> Result<()> {
    if let Action::Prepare {
        file,
        out,
        original_path,
        version,
        plan,
        review_history,
    } = action
    {
        let recovery_plan = plan.as_deref().map(read_plan_text).transpose()?;
        let history = review_history
            .as_deref()
            .map(|path| -> Result<Value> {
                serde_json::from_slice(&read_small(path, HISTORY_BYTES)?)
                    .map_err(|_| "판정 이력 JSON 형식 오류".into())
            })
            .transpose()?
            .unwrap_or(Value::Null);
        let manifest = convert(bundle::prepare(
            &file,
            &out,
            bundle::BundleMetadata {
                original_path,
                version,
                review_history: history,
                recovery_plan,
            },
        ))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "bundle_id": manifest.bundle_id, "manifest": out.join("manifest.json"),
                "sha256": manifest.sha256, "size_bytes": manifest.size_bytes,
                "chunk_count": manifest.chunks.len(), "source_metadata_claims_verified": false,
                "remote_review": "unknown", "recommended": false
            }))?
        );
        return Ok(());
    }
    let config = load_config(config_path)?;
    let output = match action {
        Action::Enqueue {
            stage,
            directory,
            max_items,
            max_bytes,
        } => enqueue_stage(
            &config,
            &stage,
            &directory,
            queue::QueueLimits {
                max_items,
                max_bytes,
            },
        )?,
        Action::Publish { manifest } => {
            let manifest = convert(bundle::read_manifest(&manifest))?;
            convert(bundle::register_manifest(&config, &manifest))?;
            let completed = convert(bundle::complete(&config, &manifest.bundle_id))?;
            if completed.manifest != manifest {
                return Err("완료 응답의 구성 목록이 등록한 구성 목록과 다릅니다".into());
            }
            serde_json::to_value(completed)?
        }
        Action::Upload { stage } => {
            serde_json::to_value(convert(bundle::upload_prepared(&config, &stage))?)?
        }
        Action::List {
            agent_id,
            after,
            limit,
        } => serde_json::to_value(convert(bundle::list(
            &config,
            &agent_id,
            after.as_deref(),
            limit,
        ))?)?,
        Action::Show { agent_id, id } => {
            serde_json::to_value(convert(bundle::get(&config, &agent_id, &id))?)?
        }
        Action::Fetch {
            agent_id,
            id,
            out,
            evidence_only,
        } => {
            let record = convert(bundle::fetch(&config, &agent_id, &id, &out, evidence_only))?;
            json!({"out":out,"evidence_only":evidence_only,"recommended":!evidence_only && record.recommended,"record":record})
        }
        Action::Review {
            agent_id,
            id,
            request_id,
            decision,
            actor,
            reason,
        } => {
            let request = bundle::ReviewRequest {
                request_id,
                decision: match decision {
                    Decision::Good => bundle::ReviewDecision::Good,
                    Decision::Revoked => bundle::ReviewDecision::Revoked,
                },
                actor,
                reason,
            };
            serde_json::to_value(convert(bundle::review(&config, &agent_id, &id, &request))?)?
        }
        Action::Test {
            agent_id,
            id,
            out,
            preapproval,
        } => return test_bundle(&config, &agent_id, &id, &out, preapproval),
        Action::Prepare { .. } => unreachable!(),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn enqueue_stage(
    config: &VaultConfig,
    stage: &Path,
    directory: &Path,
    limits: queue::QueueLimits,
) -> Result<Value> {
    serde_json::to_value(convert(queue::enqueue_bundle(
        directory, config, stage, &limits,
    ))?)
    .map_err(Into::into)
}

fn parse_plan(text: &str) -> Result<ServiceRecoveryPlan> {
    if text.len() > PLAN_BYTES {
        return Err("복구 계획은 64KiB 이하여야 합니다".into());
    }
    let plan: ServiceRecoveryPlan = toml::from_str(text).map_err(|_| "복구 계획 TOML 형식 오류")?;
    service::validate_plan(&plan)?;
    Ok(plan)
}

fn read_plan_text(path: &Path) -> Result<String> {
    let text = String::from_utf8(read_small(path, PLAN_BYTES)?)
        .map_err(|_| "복구 계획은 UTF-8이어야 합니다")?;
    parse_plan(&text)?;
    Ok(text)
}

fn relocated_plan(
    text: Option<&str>,
    backup_bytes: u64,
    destination: &Path,
) -> std::result::Result<ServiceRecoveryPlan, &'static str> {
    let mut plan =
        parse_plan(text.ok_or("embedded_plan_missing")?).map_err(|_| "embedded_plan_invalid")?;
    if backup_bytes > plan.max_backup_bytes {
        return Err("plan_backup_limit_exceeded");
    }
    plan.backup_path = destination.into();
    service::validate_plan(&plan).map_err(|_| "relocated_plan_invalid")?;
    Ok(plan)
}

fn eligible(
    record: &bundle::BundleRecord,
    preapproval: bool,
) -> std::result::Result<(), &'static str> {
    eligible_review(
        record.completion.is_some(),
        &record.current_review,
        record.recommended,
        preapproval,
    )
}

fn eligible_review(
    complete: bool,
    current_review: &str,
    recommended: bool,
    preapproval: bool,
) -> std::result::Result<(), &'static str> {
    if !complete {
        return Err("bundle_incomplete");
    }
    if preapproval {
        if current_review != "unknown" || recommended {
            return Err("preapproval_requires_unknown_review");
        }
    } else if current_review != "good" || !recommended {
        return Err("remote_review_not_good");
    }
    Ok(())
}

fn test_bundle(
    config: &VaultConfig,
    agent: &str,
    id: &str,
    out: &Path,
    preapproval: bool,
) -> Result<()> {
    new_private_directory(out)?;
    let mut summary = json!({
        "format":"argos-bundle-recovery-test-v1","agent_id":agent,"bundle_id":id,
        "started_at_ms":now_ms(),"status":"rejected","recommended":false,
        "preapproval":preapproval,"trial_passed":false,"operational_restore_authorized":false,
        "isolation_required":preapproval,
        "failure_code":Value::Null,"report_authenticated":false,
        "trial_executor_authenticated":false,"remote_review_authenticated":false,
        "remote_record_authenticated":false,
        "source_metadata_claims_verified":false,"original_agent_database_used":false,
        "out":out,"drill_report":Value::Null,"verification":Value::Null,
        "limitations":["서비스 시험 보고서는 무서명이며 실행자 신원을 인증하지 않습니다.",
            "원격 정상 판정은 마지막 조회 시점의 서버 서명 이력입니다. 이후 취소될 수 있습니다.",
            "기재한 담당자 이름은 관리자 토큰 요청의 주장입니다. 담당자 개인 인증을 증명하지 않습니다.",
            "고정 DB 검사는 전체 업무 서비스 복구나 데이터의 업무적 정상성을 증명하지 않습니다."]
    });
    let result = (|| -> std::result::Result<(), &'static str> {
        let before =
            bundle::get(config, agent, id).map_err(|_| "remote_record_unavailable_or_invalid")?;
        summary["remote_record_authenticated"] = json!(true);
        summary["remote_review_authenticated"] =
            json!(before.completion.is_some() && !before.reviews.is_empty());
        summary["initial_review"] = json!(before.current_review);
        eligible(&before, preapproval)?;
        let plan = relocated_plan(
            before.manifest.metadata.recovery_plan.as_deref(),
            before.manifest.size_bytes,
            &out.join("backup.bin"),
        )?;
        let fetched = bundle::fetch(config, agent, id, &plan.backup_path, preapproval)
            .map_err(|_| "backup_fetch_or_review_failed")?;
        eligible(&fetched, preapproval)?;
        if fetched.manifest != before.manifest || fetched.completion != before.completion {
            return Err("bundle_changed_during_fetch");
        }
        let plan_text =
            toml::to_string(&plan).map_err(|_| "relocated_plan_serialization_failed")?;
        if plan_text.len() > PLAN_BYTES {
            return Err("relocated_plan_size_exceeded");
        }
        let plan_path = out.join("plan.toml");
        write_new(&plan_path, plan_text.as_bytes()).map_err(|_| "plan_write_failed")?;
        write_new(
            &out.join("manifest.json"),
            &serde_json::to_vec_pretty(&before.manifest)
                .map_err(|_| "manifest_serialization_failed")?,
        )
        .map_err(|_| "manifest_write_failed")?;
        let drill = out.join("drill");
        let trial_result = (|| -> std::result::Result<(), &'static str> {
            let report = if preapproval {
                crate::service_recovery::supervise_preapproval_report(&plan_path, &drill)
                    .map_err(|_| "preapproval_isolation_or_supervision_failed")?
            } else {
                crate::service_recovery::supervise_report(&plan_path, &drill)
                    .map_err(|_| "drill_supervision_failed")?
            };
            let passed = report.status == "passed";
            summary["drill_report"] =
                serde_json::to_value(&report).map_err(|_| "report_serialization_failed")?;
            if !passed {
                return Err("service_recovery_failed");
            }
            let verified = service::verify_report(
                &plan,
                &drill.join(service::REPORT_NAME),
                plan.timeout_secs + 60,
            )
            .map_err(|_| "report_consistency_failed")?;
            if verified.backup_sha256 != before.manifest.sha256
                || verified.backup_bytes != before.manifest.size_bytes
            {
                return Err("report_bundle_backup_mismatch");
            }
            summary["verification"] =
                serde_json::to_value(&verified).map_err(|_| "verification_serialization_failed")?;
            Ok(())
        })();
        // 시험과 보고서 재검증이 끝난 뒤 취소 여부를 다시 조회한다.
        let latest = bundle::get(config, agent, id)
            .map_err(|_| "final_remote_record_unavailable_or_invalid")?;
        summary["final_review"] = json!(latest.current_review);
        summary["review_sequence"] = json!(latest.reviews.len());
        eligible(&latest, preapproval)?;
        if latest.manifest != before.manifest || latest.completion != before.completion {
            return Err("bundle_changed_during_drill");
        }
        write_new(
            &out.join("remote-record.json"),
            &serde_json::to_vec_pretty(&latest)
                .map_err(|_| "remote_record_serialization_failed")?,
        )
        .map_err(|_| "remote_record_write_failed")?;
        summary["manifest_sha256"] = json!(latest.manifest_receipt.receipt.sha256);
        summary["backup_sha256"] = json!(latest.manifest.sha256);
        summary["backup_bytes"] = json!(latest.manifest.size_bytes);
        trial_result
    })();
    summary["finished_at_ms"] = json!(now_ms());
    match result {
        Ok(()) => {
            summary["status"] = json!("passed");
            summary["trial_passed"] = json!(true);
            summary["recommended"] = json!(!preapproval);
            summary["operational_restore_authorized"] = json!(!preapproval);
        }
        Err(code) => {
            summary["failure_code"] = json!(code);
        }
    }
    let bytes = serde_json::to_vec_pretty(&summary)?;
    write_new(&out.join("bundle-test.json"), &bytes)?;
    fs::File::open(out)?.sync_all()?;
    println!("{}", String::from_utf8(bytes)?);
    if result.is_err() {
        return Err("원격 번들 복구 추천을 보류했습니다. failure_code를 확인하세요".into());
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    let same = left.is_file()
        && right.is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same && left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        same
    }
}

fn read_small(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let path_before = fs::symlink_metadata(path)?;
    if !path_before.is_file()
        || path_before.file_type().is_symlink()
        || path_before.len() > limit as u64
    {
        return Err("메타데이터·청크는 크기 제한 안의 일반 파일이어야 합니다".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let before = file.metadata()?;
    if !same_file(&path_before, &before) {
        return Err("입력 파일 신원이 변경되었습니다".into());
    }
    let mut bytes = Vec::new();
    (&file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if !same_file(&before, &after)
        || !same_file(&before, &path_after)
        || path_after.file_type().is_symlink()
        || bytes.len() > limit
        || bytes.len() as u64 != before.len()
    {
        return Err("읽는 동안 입력 내용·경로가 변경되었습니다".into());
    }
    Ok(bytes)
}

fn private_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.components().any(|p| matches!(p, Component::ParentDir)) {
        return Err("전용 디렉터리는 .. 없는 절대 경로여야 합니다".into());
    }
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("전용 경로와 상위 경로의 symlink를 거부합니다".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let uid = unsafe { libc::geteuid() };
            if metadata.uid() != uid && metadata.uid() != 0 {
                return Err("디렉터리 소유자를 신뢰할 수 없습니다".into());
            }
            if metadata.mode() & 0o022 != 0
                && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0)
            {
                return Err("다른 계정이 쓰기 가능한 경로를 거부합니다".into());
            }
            if current == path && (metadata.uid() != uid || metadata.mode() & 0o777 != 0o700) {
                return Err("전용 디렉터리는 현재 계정 소유 0700이어야 합니다".into());
            }
        }
    }
    Ok(())
}

fn new_private_directory(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("새 시험 디렉터리는 .. 없는 절대 경로여야 합니다".into());
    }
    let parent = path.parent().ok_or("시험 부모 경로 없음")?;
    private_directory(parent)?;
    super::create_private_dir(path)?;
    private_directory(path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> &'static str {
        "service_id='orders'\nengine='sqlite'\nbackup_path='/lost-host/orders.db'\n[[tables]]\ncheck_id='orders'\ntable='orders'\nmin_rows=2\n"
    }

    #[test]
    fn embedded_plan_relocation_only_changes_backup_path() {
        let original = parse_plan(plan()).unwrap();
        let destination = Path::new("/new-host/private/backup.bin");
        let moved = relocated_plan(Some(plan()), 4096, destination).unwrap();
        assert_eq!(moved.backup_path, destination);
        assert!(relocated_plan(None, 4096, destination).is_err());
        assert!(relocated_plan(Some(plan()), bundle::MAX_BUNDLE_BYTES, destination).is_err());
        let mut before = serde_json::to_value(original).unwrap();
        let mut after = serde_json::to_value(moved).unwrap();
        before.as_object_mut().unwrap().remove("backup_path");
        after.as_object_mut().unwrap().remove("backup_path");
        assert_eq!(before, after);
    }

    #[test]
    fn preapproval_requires_complete_unknown_and_never_allows_revoked() {
        assert!(eligible_review(true, "unknown", false, true).is_ok());
        assert!(eligible_review(true, "good", true, false).is_ok());
        for review in ["unknown", "good", "revoked"] {
            for recommended in [false, true] {
                for preapproval in [false, true] {
                    assert!(eligible_review(false, review, recommended, preapproval).is_err());
                }
            }
        }
        for preapproval in [false, true] {
            assert!(eligible_review(true, "revoked", false, preapproval).is_err());
            assert!(eligible_review(true, "revoked", true, preapproval).is_err());
        }
        assert!(eligible_review(true, "unknown", false, false).is_err());
        assert!(eligible_review(true, "unknown", true, true).is_err());
        assert!(eligible_review(true, "good", true, true).is_err());
        assert!(eligible_review(true, "good", false, false).is_err());
    }

    #[test]
    fn embedded_plan_rejects_commands_invalid_expectations_and_large_input() {
        assert!(parse_plan(&format!("command='secret external command'\n{}", plan())).is_err());
        assert!(parse_plan(&plan().replace("min_rows=2", "min_rows=-1")).is_err());
        assert!(parse_plan(&"x".repeat(PLAN_BYTES + 1)).is_err());
    }

    #[test]
    fn private_outputs_and_bounded_inputs_reject_reuse_symlink_and_parent_escape() {
        let temporary = super::super::PrivateDirectory::new().unwrap();
        let out = temporary.0.join("drill");
        new_private_directory(&out).unwrap();
        assert!(new_private_directory(&out).is_err());
        assert!(new_private_directory(&temporary.0.join("../escape")).is_err());
        let input = temporary.0.join("plan.toml");
        write_new(&input, plan().as_bytes()).unwrap();
        assert_eq!(read_plan_text(&input).unwrap(), plan());
        assert!(read_small(&input, 1).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&input, temporary.0.join("linked-plan")).unwrap();
            assert!(read_plan_text(&temporary.0.join("linked-plan")).is_err());
            std::os::unix::fs::symlink(&out, temporary.0.join("linked-dir")).unwrap();
            assert!(private_directory(&temporary.0.join("linked-dir")).is_err());
        }
    }

    #[test]
    fn offline_enqueue_checks_all_bytes_before_registering_job() {
        let temporary = super::super::PrivateDirectory::new().unwrap();
        let source = temporary.0.join("backup.bin");
        write_new(&source, b"reviewed backup bytes").unwrap();
        let stage = temporary.0.join("stage");
        let manifest = bundle::prepare(
            &source,
            &stage,
            bundle::BundleMetadata {
                original_path: "/old-host/backup.db".into(),
                version: None,
                review_history: Value::Null,
                recovery_plan: None,
            },
        )
        .unwrap();
        let config = VaultConfig {
            endpoint: "http://127.0.0.1:9".into(),
            allow_http_loopback: true,
            agent_id: "test-agent".into(),
            pinned_pubkey: argos_vault::generate_signing_key_file(&temporary.0.join("key"))
                .unwrap(),
            ..Default::default()
        };
        let chunk = stage
            .join("chunks")
            .join(format!("{}.bin", manifest.chunks[0].sha256));
        fs::write(&chunk, b"changed bytes").unwrap();
        let directory = temporary.0.join("queue");
        assert!(enqueue_stage(&config, &stage, &directory, queue::QueueLimits::default()).is_err());
        assert_eq!(queue::status(&directory).unwrap().pending_items, 0);
        assert!(queue::bundle_job(&directory, &manifest.bundle_id).is_err());
        fs::write(&chunk, b"reviewed backup bytes").unwrap();
        let result =
            enqueue_stage(&config, &stage, &directory, queue::QueueLimits::default()).unwrap();
        assert_eq!(result["chunk_items"].as_array().unwrap().len(), 1);
        assert_eq!(result["state"], "pending");
        assert_eq!(result["recommended"], false);
        assert_eq!(queue::status(&directory).unwrap().pending_items, 1);
    }
}
