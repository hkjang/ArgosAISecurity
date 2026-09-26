use argos_common::AgentConfig;
use argos_vault::{SignedReceipt, VaultConfig};
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
            let agent = AgentConfig::load(agent_config)?;
            // BackupStore::open can initialize a store; require the existing metadata first.
            if !agent.backup.dir.join("index.db").is_file() {
                return Err("기존 백업 저장소가 없습니다".into());
            }
            let store =
                argos_recovery::BackupStore::open(&agent.backup.dir, agent.backup.max_file_bytes)?;
            let temporary = PrivateDirectory::new()?;
            let restored = temporary.0.join("backup");
            let selected = store
                .versions(&path)?
                .into_iter()
                .find(|v| v.id == version)
                .ok_or("백업 버전이 없습니다")?;
            if !selected.known_good {
                return Err(
                    "정상 판정되지 않은 백업은 upload-backup으로 보관할 수 없습니다".into(),
                );
            }
            let selected = store.preview(&path, version, &restored)?;
            if !selected.known_good {
                return Err("정상본 판정이 취소되었습니다".into());
            }
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
