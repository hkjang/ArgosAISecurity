//! 시작 시 한 번 재구성하는 논리 용량 계수와 단일 작성자 잠금.
//! 관리자가 파일을 직접 바꾸는 행위·물리 디스크 예약·WORM은 제공하지 않는다.
use crate::*;
use std::{collections::BTreeMap, fs::File};

const LOCK_NAME: &str = ".argos-vault.lock";
const MAX_REASONS: usize = 32;
const METADATA_MARGIN: u64 = (MAX_RECEIPT_BYTES + 65536) as u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CapacityConfig {
    pub global_max_bytes: u64,
    pub global_max_objects: u64,
    pub agent_max_bytes: u64,
    pub agent_max_objects: u64,
    pub min_free_bytes: u64,
    pub max_scan_entries: usize,
    pub max_tracked_agents: usize,
    pub agent_overrides: BTreeMap<String, AgentCapacityLimit>,
}
impl Default for CapacityConfig {
    fn default() -> Self {
        Self {
            global_max_bytes: 100 * 1024 * 1024 * 1024,
            global_max_objects: 1_000_000,
            agent_max_bytes: 10 * 1024 * 1024 * 1024,
            agent_max_objects: 100_000,
            min_free_bytes: 1024 * 1024 * 1024,
            max_scan_entries: 2_100_000,
            max_tracked_agents: 4096,
            agent_overrides: BTreeMap::new(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCapacityLimit {
    pub max_bytes: u64,
    pub max_objects: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectUsage {
    pub logical_bytes: u64,
    pub objects: u64,
    pub receipted_objects: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapacityUsage {
    pub usage: ObjectUsage,
    pub limits: AgentCapacityLimit,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemCapacity {
    pub supported: bool,
    pub available_bytes: Option<u64>,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityUsage {
    pub limits: CapacityConfig,
    pub total: ObjectUsage,
    pub agents: BTreeMap<String, AgentCapacityUsage>,
    pub filesystem: FilesystemCapacity,
    pub reconstruction_complete: bool,
    pub storage_consistent: bool,
    /// 전역 용량/정합성/스캔/파일시스템 여유 조건상 신규 쓰기가 중단되었는지 나타낸다.
    /// false여도 개별 요청은 전역·에이전트 한도에 따라 거부될 수 있다.
    pub new_uploads_blocked: bool,
    pub reasons: Vec<String>,
    /// 이번 서버 프로세스의 admission 거부 수. 재시작 시 0부터 시작한다.
    pub admission_rejections: u64,
}
#[derive(Debug)]
pub(crate) struct CapacityRejection(pub &'static str);
impl std::fmt::Display for CapacityRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "보관 신규 쓰기 거부: {}", self.0)
    }
}
impl std::error::Error for CapacityRejection {}

/// 프로세스 수명 동안 열어 둔다. 잠금 파일을 삭제하거나 재생성하지 않는다.
pub(crate) struct WriterLock {
    file: File,
}
impl WriterLock {
    pub(crate) fn acquire(directory: &Path) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let path = directory.join(LOCK_NAME);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(&path)?;
            let metadata = file.metadata()?;
            let path_metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.dev() != path_metadata.dev()
                || metadata.ino() != path_metadata.ino()
            {
                return Err(
                    "보관 작성자 잠금은 현재 계정 소유 0600 단일 링크 일반 파일이어야 합니다"
                        .into(),
                );
            }
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(
                    "다른 서버가 보관 저장소를 사용 중이거나 배타 잠금을 지원하지 않습니다".into(),
                );
            }
            Ok(Self { file })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = directory;
            Err("현재 플랫폼은 보관 서버의 프로세스 배타 잠금을 지원하지 않습니다".into())
        }
    }
    fn free_space(&self) -> FilesystemCapacity {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            if unsafe { libc::fstatvfs(self.file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
                return FilesystemCapacity {
                    supported: true,
                    available_bytes: None,
                    error: Some("filesystem_free_probe_failed".into()),
                };
            }
            let info = unsafe { info.assume_init() };
            let bytes = (info.f_bavail as u64).checked_mul(info.f_frsize as u64);
            return FilesystemCapacity {
                supported: true,
                available_bytes: bytes,
                error: bytes.is_none().then(|| "filesystem_free_overflow".into()),
            };
        }
        #[cfg(not(target_os = "linux"))]
        FilesystemCapacity {
            supported: false,
            available_bytes: None,
            error: Some("filesystem_free_unsupported".into()),
        }
    }
    fn same_filesystem(&self, metadata: &fs::Metadata) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != self.file.metadata()?.dev() {
                return Err(
                    "보관 객체/디렉터리는 저장소 잠금 파일과 같은 파일시스템이어야 합니다".into(),
                );
            }
        }
        Ok(())
    }
}

pub(crate) struct CapacityState {
    limits: CapacityConfig,
    total: ObjectUsage,
    agents: BTreeMap<String, ObjectUsage>,
    reconstruction_complete: bool,
    storage_consistent: bool,
    reasons: Vec<String>,
    admission_rejections: u64,
    _writer: WriterLock,
}
impl CapacityState {
    pub(crate) fn open(
        directory: &Path,
        limits: CapacityConfig,
        configured_agents: impl Iterator<Item = String>,
        key: &SigningKey,
        key_id: &str,
    ) -> Result<Self> {
        if !(1..=2_100_000).contains(&limits.max_scan_entries)
            || !(1..=16_384).contains(&limits.max_tracked_agents)
            || limits.agent_overrides.len() > limits.max_tracked_agents
            || limits.agent_overrides.keys().any(|id| !valid_id(id))
        {
            return Err("용량 설정의 스캔/에이전트 상한 또는 개별 ID가 유효하지 않습니다".into());
        }
        let writer = WriterLock::acquire(directory)?;
        let mut state = Self {
            limits,
            total: ObjectUsage::default(),
            agents: BTreeMap::new(),
            reconstruction_complete: true,
            storage_consistent: true,
            reasons: Vec::new(),
            admission_rejections: 0,
            _writer: writer,
        };
        for agent in configured_agents {
            if state.agents.len() >= state.limits.max_tracked_agents {
                return Err("설정된 에이전트 수가 용량 계수 메모리 상한을 초과합니다".into());
            }
            state.agents.insert(agent, ObjectUsage::default());
        }
        if state.scan(directory, key, key_id).is_err() {
            state.reconstruction_complete = false;
            state.inconsistent("startup_scan_failed");
        }
        Ok(state)
    }
    fn inconsistent(&mut self, code: &str) {
        self.storage_consistent = false;
        if self.reasons.len() < MAX_REASONS && !self.reasons.iter().any(|item| item == code) {
            self.reasons.push(code.into());
        }
    }
    fn count_entry(&mut self, entries: &mut usize) -> bool {
        if *entries >= self.limits.max_scan_entries {
            self.reconstruction_complete = false;
            self.inconsistent("startup_scan_limit");
            false
        } else {
            *entries += 1;
            true
        }
    }
    fn scan(&mut self, directory: &Path, key: &SigningKey, key_id: &str) -> Result<()> {
        let mut entries = 0;
        let public = hex::encode(key.verifying_key().to_bytes());
        for entry in fs::read_dir(directory)? {
            if !self.count_entry(&mut entries) {
                return Ok(());
            }
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == LOCK_NAME {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                // 루트의 설정/키 등 비객체 파일은 논리 사용량에서 제외한다.
                // 설정된 에이전트 자리를 가리는 파일과 게시 임시 파일은 모순이다.
                if self.agents.contains_key(&name) || name.starts_with(".argos-vault-") {
                    self.inconsistent("unexpected_root_entry");
                }
                continue;
            }
            if !valid_id(&name) {
                self.inconsistent("invalid_agent_directory");
                continue;
            }
            if !self.agents.contains_key(&name) {
                if self.agents.len() >= self.limits.max_tracked_agents {
                    self.reconstruction_complete = false;
                    self.inconsistent("agent_tracking_limit");
                    return Ok(());
                }
                self.agents.insert(name.clone(), ObjectUsage::default());
            }
            if validate_private_directory(&entry.path()).is_err()
                || self._writer.same_filesystem(&metadata).is_err()
            {
                self.inconsistent("invalid_agent_directory_permissions_or_filesystem");
                self.reconstruction_complete = false;
                continue;
            }
            for object in fs::read_dir(entry.path())? {
                if !self.count_entry(&mut entries) {
                    return Ok(());
                }
                let object = object?;
                let filename = object.file_name().to_string_lossy().into_owned();
                let Some(hash) = filename.strip_suffix(".blob") else {
                    if let Some(hash) = filename
                        .strip_suffix(".receipt.json")
                        .filter(|hash| valid_hash(hash))
                    {
                        if !entry.path().join(format!("{hash}.blob")).is_file() {
                            self.inconsistent("receipt_without_object");
                        }
                    } else {
                        self.inconsistent("unexpected_or_temporary_object_file");
                    }
                    continue;
                };
                if !valid_hash(hash) {
                    self.inconsistent("invalid_object_name");
                    continue;
                }
                let Ok(metadata) = self.object_metadata(&object.path()) else {
                    self.inconsistent("invalid_object_file");
                    self.reconstruction_complete = false;
                    continue;
                };
                self.add_usage(&name, metadata.len())?;
                let receipt_path = entry.path().join(format!("{hash}.receipt.json"));
                let verified = (|| -> Result<()> {
                    self.object_metadata(&receipt_path)?;
                    let receipt: SignedReceipt =
                        serde_json::from_slice(&read_bounded(&receipt_path, MAX_RECEIPT_BYTES)?)?;
                    verify_receipt(&receipt, &public)?;
                    if receipt.receipt.agent_id != name
                        || receipt.receipt.sha256 != hash
                        || receipt.receipt.key_id != key_id
                        || receipt.receipt.size_bytes != metadata.len()
                    {
                        return Err("증명과 객체 메타데이터 불일치".into());
                    }
                    Ok(())
                })();
                if verified.is_ok() {
                    self.mark_receipted(&name);
                } else {
                    self.inconsistent("object_receipt_missing_invalid_or_mismatched");
                }
            }
        }
        Ok(())
    }
    pub(crate) fn validate_directory(&self, directory: &Path) -> Result<()> {
        self._writer
            .same_filesystem(&fs::symlink_metadata(directory)?)
    }
    fn object_metadata(&self, path: &Path) -> Result<fs::Metadata> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("일반 객체 파일 필요".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
            {
                return Err("객체 파일 권한/링크 오류".into());
            }
        }
        self._writer.same_filesystem(&metadata)?;
        Ok(metadata)
    }
    fn agent_limit(&self, agent: &str) -> AgentCapacityLimit {
        self.limits
            .agent_overrides
            .get(agent)
            .cloned()
            .unwrap_or(AgentCapacityLimit {
                max_bytes: self.limits.agent_max_bytes,
                max_objects: self.limits.agent_max_objects,
            })
    }
    fn add_usage(&mut self, agent: &str, bytes: u64) -> Result<()> {
        let current = self.agents.get_mut(agent).ok_or("계수 에이전트 없음")?;
        // 계산을 모두 끝내기 전에는 부분 계수를 반영하지 않는다.
        let total_bytes = self
            .total
            .logical_bytes
            .checked_add(bytes)
            .ok_or("전역 바이트 초과")?;
        let total_objects = self
            .total
            .objects
            .checked_add(1)
            .ok_or("전역 객체수 초과")?;
        let agent_bytes = current
            .logical_bytes
            .checked_add(bytes)
            .ok_or("에이전트 바이트 초과")?;
        let agent_objects = current
            .objects
            .checked_add(1)
            .ok_or("에이전트 객체수 초과")?;
        self.total.logical_bytes = total_bytes;
        self.total.objects = total_objects;
        current.logical_bytes = agent_bytes;
        current.objects = agent_objects;
        Ok(())
    }
    pub(crate) fn reserve(
        &mut self,
        agent: &str,
        bytes: u64,
    ) -> std::result::Result<(), CapacityRejection> {
        let result = self.admit(agent, bytes);
        if result.is_err() {
            self.admission_rejections = self.admission_rejections.saturating_add(1);
        }
        result
    }
    fn admit(&mut self, agent: &str, bytes: u64) -> std::result::Result<(), CapacityRejection> {
        if !self.storage_consistent || !self.reconstruction_complete {
            return Err(CapacityRejection("storage_accounting_incomplete"));
        }
        let Some(current) = self.agents.get(agent) else {
            return Err(CapacityRejection("untracked_agent"));
        };
        let agent_limit = self.agent_limit(agent);
        if self.total.logical_bytes >= self.limits.global_max_bytes
            || self
                .total
                .logical_bytes
                .checked_add(bytes)
                .is_none_or(|v| v > self.limits.global_max_bytes)
            || self
                .total
                .objects
                .checked_add(1)
                .is_none_or(|v| v > self.limits.global_max_objects)
        {
            return Err(CapacityRejection("global_limit"));
        }
        if current.logical_bytes >= agent_limit.max_bytes
            || current
                .logical_bytes
                .checked_add(bytes)
                .is_none_or(|v| v > agent_limit.max_bytes)
            || current
                .objects
                .checked_add(1)
                .is_none_or(|v| v > agent_limit.max_objects)
        {
            return Err(CapacityRejection("agent_limit"));
        }
        if self.limits.min_free_bytes > 0 {
            let free = self._writer.free_space();
            let required = self
                .limits
                .min_free_bytes
                .checked_add(bytes)
                .and_then(|v| v.checked_add(METADATA_MARGIN));
            if free
                .available_bytes
                .zip(required)
                .is_none_or(|(free, required)| free < required)
            {
                return Err(CapacityRejection("filesystem_free_floor_or_unavailable"));
            }
        }
        self.add_usage(agent, bytes)
            .map_err(|_| CapacityRejection("accounting_overflow"))?;
        Ok(())
    }
    pub(crate) fn mark_receipted(&mut self, agent: &str) {
        self.total.receipted_objects = self.total.receipted_objects.saturating_add(1);
        if let Some(usage) = self.agents.get_mut(agent) {
            usage.receipted_objects = usage.receipted_objects.saturating_add(1);
        }
    }
    pub(crate) fn write_failed(&mut self) {
        self.inconsistent("publish_failed_restart_required");
    }
    pub(crate) fn usage(&self) -> CapacityUsage {
        let filesystem = self._writer.free_space();
        let floor_blocked = self.limits.min_free_bytes > 0
            && filesystem.available_bytes.is_none_or(|free| {
                self.limits
                    .min_free_bytes
                    .checked_add(METADATA_MARGIN)
                    .is_none_or(|needed| free < needed)
            });
        let global_blocked = self.total.logical_bytes >= self.limits.global_max_bytes
            || self.total.objects >= self.limits.global_max_objects;
        let mut reasons = self.reasons.clone();
        if global_blocked {
            reasons.push("global_capacity_reached".into());
        }
        if floor_blocked {
            reasons.push("filesystem_free_floor_or_unavailable".into());
        }
        CapacityUsage {
            limits: self.limits.clone(),
            total: self.total.clone(),
            agents: self
                .agents
                .iter()
                .map(|(id, usage)| {
                    (
                        id.clone(),
                        AgentCapacityUsage {
                            usage: usage.clone(),
                            limits: self.agent_limit(id),
                        },
                    )
                })
                .collect(),
            filesystem,
            reconstruction_complete: self.reconstruction_complete,
            storage_consistent: self.storage_consistent,
            new_uploads_blocked: !self.reconstruction_complete
                || !self.storage_consistent
                || floor_blocked
                || global_blocked,
            reasons,
            admission_rejections: self.admission_rejections,
        }
    }
}
