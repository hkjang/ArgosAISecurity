use argos_common::AgentConfig;
use argos_vault::{queue, SignedReceipt, VaultConfig};
use clap::{Args, Subcommand, ValueEnum};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Args)]
pub struct Arguments {
    /// 고정 공개키·서버 주소·역할별 토큰을 담은 별도 보관 설정
    #[arg(long, global = true)]
    vault_config: Option<PathBuf>,
    #[command(subcommand)]
    action: Action,
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Evidence,
    Backup,
    Audit,
}
impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Backup => "backup",
            Self::Audit => "audit",
        }
    }
}

#[derive(Subcommand)]
enum Action {
    /// 관리자 인증으로 보관 용량·디스크 여유·신규 업로드 차단 이유 조회
    Usage,
    /// 전송할 바이트를 로컬에 보존하고 중단 후 이어 보내기
    Queue {
        #[command(subcommand)]
        action: QueueAction,
    },
    /// 새 Ed25519 보관 서버 서명키 생성 (부모 전용 디렉터리 0700 필요)
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// 파일 보관 후 서명 수신증명을 새 파일에 저장
    Upload {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, value_enum)]
        kind: Kind,
        #[arg(long)]
        receipt: PathBuf,
    },
    /// 정상 판정된 로컬 백업 버전을 검증·보관
    UploadBackup {
        path: PathBuf,
        #[arg(long)]
        version: i64,
        #[arg(long)]
        receipt: PathBuf,
    },
    /// 증거 패키지의 같은 검증 바이트를 보관 (manifest는 마지막)
    UploadEvidence {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        receipts: PathBuf,
    },
    /// 고정 공개키로 수신증명 서명 및 로컬 파일 해시 검증
    Verify {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        pubkey: String,
    },
    /// 관리자 토큰으로 받아 서명·해시 검증 후 새 파일로 복원
    Fetch {
        #[arg(long = "agent-id")]
        agent: String,
        #[arg(long)]
        sha256: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
    },
}

#[derive(Args)]
struct EnqueueOptions {
    /// 현재 계정 소유 전용 0700 큐 절대 경로 (처음 등록 시 생성)
    #[arg(long)]
    directory: PathBuf,
    /// 전송 대기·임대 중인 활성 항목 수 상한
    #[arg(long, default_value_t = 1000)]
    max_items: u64,
    /// 미전송 파일 스냅샷의 총 바이트 상한
    #[arg(long, default_value_t = 268_435_456)]
    max_bytes: u64,
}
impl EnqueueOptions {
    fn limits(&self) -> queue::QueueLimits {
        queue::QueueLimits {
            max_items: self.max_items,
            max_bytes: self.max_bytes,
        }
    }
}
#[derive(Subcommand)]
enum QueueAction {
    /// 완료 수신증명을 새 파일에 검증 가능한 JSONL로 내보내기 (원본 이력 유지)
    ExportArchive {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// 큐 DB 없이 완료 이력의 구조·개별 수신증명 서명 확인
    VerifyArchive {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        pubkey: String,
    },
    /// 파일을 같은 바이트의 로컬 스냅샷으로 대기열에 등록 (전송하지 않음)
    Enqueue {
        #[command(flatten)]
        options: EnqueueOptions,
        #[arg(long)]
        file: PathBuf,
        #[arg(long, value_enum)]
        kind: Kind,
    },
    /// 검토된 백업 버전을 해시 검증 후 대기열에 등록
    EnqueueBackup {
        #[command(flatten)]
        options: EnqueueOptions,
        path: PathBuf,
        #[arg(long)]
        version: i64,
    },
    /// 검증된 증거 패키지의 세 파일 등록 (여러 등록은 단일 트랜잭션이 아님)
    EnqueueEvidence {
        #[command(flatten)]
        options: EnqueueOptions,
        #[arg(long)]
        package: PathBuf,
    },
    /// 대기·재시도·완료 수신증명 조회 (전송·큐 변경 없음)
    Status {
        #[arg(long)]
        directory: PathBuf,
    },
    /// 항목 ID로 완료 수신증명과 재시도 상태 조회
    Show {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        id: String,
    },
    /// 재시도 시각이 된 항목을 제한된 개수만 전송하고 종료
    Drain {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long, default_value_t = 16)]
        max_items: usize,
    },
}

fn run_queue(action: QueueAction, config_path: Option<PathBuf>, agent_config: &Path) -> Result<()> {
    if let QueueAction::ExportArchive { directory, out } = &action {
        println!(
            "{}",
            serde_json::to_string_pretty(&convert(queue::export_archive(directory, out))?)?
        );
        return Ok(());
    }
    if let QueueAction::VerifyArchive { file, pubkey } = &action {
        println!(
            "{}",
            serde_json::to_string_pretty(&convert(queue::verify_archive(file, pubkey))?)?
        );
        return Ok(());
    }
    if let QueueAction::Show { directory, id } = &action {
        let item = convert(queue::item(directory, id))?;
        println!("{}", serde_json::to_string_pretty(&item)?);
        return Ok(());
    }
    if let QueueAction::Status { directory } = action {
        let status = convert(queue::status(&directory))?;
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }
    let config = load_config(config_path)?;
    match action {
        QueueAction::Enqueue {
            options,
            file,
            kind,
        } => {
            let item = convert(queue::enqueue(
                &options.directory,
                &config,
                &file,
                kind.as_str(),
                &options.limits(),
            ))?;
            println!("{}", serde_json::to_string_pretty(&item)?);
        }
        QueueAction::EnqueueBackup {
            options,
            path,
            version,
        } => {
            let (temporary, selected) = prepare_backup(agent_config, &path, version)?;
            let item = convert(queue::enqueue(
                &options.directory,
                &config,
                &temporary.0.join("backup"),
                "backup",
                &options.limits(),
            ))?;
            if item.sha256 != selected.hash || item.size_bytes != selected.size {
                return Err("대기열 스냅샷과 선택한 백업의 해시·크기가 다릅니다".into());
            }
            println!("{}", serde_json::to_string_pretty(&item)?);
        }
        QueueAction::EnqueueEvidence { options, package } => {
            let package = package.canonicalize()?;
            let parent = options
                .directory
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .canonicalize()?;
            let queue_path = if options.directory.try_exists()? {
                options.directory.canonicalize()?
            } else {
                parent.join(
                    options
                        .directory
                        .file_name()
                        .ok_or("큐 경로 이름이 없습니다")?,
                )
            };
            if queue_path.starts_with(&package) {
                return Err("큐 디렉터리는 증거 패키지 밖에 두세요".into());
            }
            let snapshot = crate::evidence_package::snapshot(&package)?;
            let temporary = PrivateDirectory::new()?;
            for name in ["evidence.json", "policy.json", "manifest.json"] {
                let path = temporary.0.join(name);
                write_new(&path, snapshot.get(name).ok_or("증거 파일 누락")?)?;
                let item = convert(queue::enqueue(
                    &options.directory,
                    &config,
                    &path,
                    "evidence",
                    &options.limits(),
                ))?;
                // 뒤의 등록이 실패해도 완료된 항목의 ID는 출력한다.
                println!("{}", json!({"package_file":name,"item":item}));
            }
        }
        QueueAction::Drain {
            directory,
            max_items,
        } => {
            let report = convert(queue::drain_once(
                &directory,
                &config,
                &queue::DrainOptions { max_items },
            ))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report.failed > 0 {
                return Err(
                    "일부 전송이 실패했습니다. 대기열의 재시도 시각과 상태를 확인하세요".into(),
                );
            }
        }
        QueueAction::Status { .. }
        | QueueAction::Show { .. }
        | QueueAction::ExportArchive { .. }
        | QueueAction::VerifyArchive { .. } => unreachable!(),
    }
    Ok(())
}

fn prepare_backup(
    agent_config: &Path,
    path: &Path,
    version: i64,
) -> Result<(PrivateDirectory, argos_recovery::BackupVersion)> {
    let agent = AgentConfig::load(agent_config)?;
    if !agent.backup.dir.join("index.db").is_file() {
        return Err("기존 백업 저장소가 없습니다".into());
    }
    let store = argos_recovery::BackupStore::open(&agent.backup.dir, agent.backup.max_file_bytes)?;
    let selected = store
        .versions(path)?
        .into_iter()
        .find(|v| v.id == version)
        .ok_or("백업 버전이 없습니다")?;
    if !selected.known_good {
        return Err("정상 판정되지 않은 백업은 이 어댑터로 보관할 수 없습니다".into());
    }
    let temporary = PrivateDirectory::new()?;
    let selected = store.preview(path, version, &temporary.0.join("backup"))?;
    if !selected.known_good {
        return Err("정상본 판정이 취소되었습니다".into());
    }
    Ok((temporary, selected))
}

fn convert<T>(result: argos_vault::Result<T>) -> Result<T> {
    result.map_err(|error| error as Box<dyn std::error::Error>)
}

fn load_config(path: Option<PathBuf>) -> Result<VaultConfig> {
    let path = path.ok_or("--vault-config 설정 파일이 필요합니다")?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 65_536 {
        return Err("보관 설정은 64KiB 이하 일반 파일이어야 합니다".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err("보관 설정은 현재 계정 소유이며 그룹·다른 계정의 접근을 금지해야 합니다 (chmod 600)".into());
        }
    }
    let mut text = String::new();
    file.take(65_537).read_to_string(&mut text)?;
    if text.len() > 65_536 {
        return Err("보관 설정 크기 상한 초과".into());
    }
    // TOML 오류에 원문 토큰이 포함될 수 있으므로 출력하지 않는다.
    toml::from_str(&text).map_err(|_| "보관 설정 TOML 형식 오류".into())
}

pub fn run(args: Arguments, agent_config: &Path) -> Result<()> {
    match args.action {
        Action::Queue { action } => return run_queue(action, args.vault_config, agent_config),
        Action::Usage => {
            let config = load_config(args.vault_config)?;
            let usage = convert(argos_vault::fetch_usage(&config))?;
            println!("{}", serde_json::to_string_pretty(&usage)?);
        }
        Action::Keygen { out } => {
            let public_key = convert(argos_vault::generate_signing_key_file(&out))?;
            println!("{}", json!({"public_key":public_key,"key_file":out}));
        }
        Action::Verify {
            file,
            receipt,
            pubkey,
        } => {
            let receipt = convert(argos_vault::read_receipt(&receipt))?;
            convert(argos_vault::verify_file(&file, &receipt, &pubkey))?;
            println!("{}", json!({"verified":true,"receipt":receipt}));
        }
        Action::Upload {
            file,
            kind,
            receipt,
        } => {
            ensure_new(&receipt)?;
            let config = load_config(args.vault_config)?;
            let received = convert(argos_vault::upload_file(&config, &file, kind.as_str()))?;
            save_receipt(&receipt, &received)?;
        }
        Action::Fetch {
            agent,
            sha256,
            out,
            receipt,
        } => {
            ensure_new(&receipt)?;
            if out == receipt {
                return Err("본문과 수신증명 출력 경로는 달라야 합니다".into());
            }
            let config = load_config(args.vault_config)?;
            let received = convert(argos_vault::fetch_file(&config, &agent, &sha256, &out))?;
            save_receipt(&receipt, &received)?;
        }
        Action::UploadBackup {
            path,
            version,
            receipt,
        } => {
            ensure_new(&receipt)?;
            let config = load_config(args.vault_config)?;
            let (temporary, selected) = prepare_backup(agent_config, &path, version)?;
            let restored = temporary.0.join("backup");
            let received = convert(argos_vault::upload_file(&config, &restored, "backup"))?;
            if received.receipt.sha256 != selected.hash
                || received.receipt.size_bytes != selected.size
            {
                return Err("보관 수신증명이 선택한 백업 버전과 다릅니다".into());
            }
            save_receipt(&receipt, &received)?;
        }
        Action::UploadEvidence { package, receipts } => {
            let config = load_config(args.vault_config)?;
            let package = package.canonicalize()?;
            let parent = receipts
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .canonicalize()?;
            if parent.starts_with(&package) {
                return Err("수신증명 디렉터리는 증거 패키지 밖에 두세요".into());
            }
            let snapshot = crate::evidence_package::snapshot(&package)?;
            let temporary = PrivateDirectory::new()?;
            create_private_dir(&receipts)?;
            // Keep completed receipts if a later upload fails; retries are idempotent remotely.
            for name in ["evidence.json", "policy.json", "manifest.json"] {
                let bytes = snapshot.get(name).ok_or("증거 파일 누락")?;
                let path = temporary.0.join(name);
                write_new(&path, bytes)?;
                let received = convert(argos_vault::upload_file(&config, &path, "evidence"))?;
                if received.receipt.sha256 != argos_vault::sha256(bytes) {
                    return Err("증거 스냅샷과 수신증명 해시가 다릅니다".into());
                }
                save_receipt(&receipts.join(format!("{name}.receipt.json")), &received)?;
            }
        }
    }
    Ok(())
}

fn ensure_new(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err("출력 경로가 이미 존재합니다".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn save_receipt(path: &Path, receipt: &SignedReceipt) -> Result<()> {
    convert(argos_vault::write_receipt_new(path, receipt))?;
    println!("{}", serde_json::to_string(receipt)?);
    Ok(())
}
fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
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
struct PrivateDirectory(PathBuf);
impl PrivateDirectory {
    fn new() -> Result<Self> {
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let suffix: String = random.iter().map(|v| format!("{v:02x}")).collect();
        let path = std::env::temp_dir().join(format!("argos-vault-client-{suffix}"));
        create_private_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
