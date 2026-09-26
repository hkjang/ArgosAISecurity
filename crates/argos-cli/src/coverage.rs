use argos_common::AgentConfig;
use argos_storage::EventStore;
use rand_core::{OsRng, RngCore};
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct ProbeChild(Child);
impl Drop for ProbeChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn bounded_read(path: &Path, limit: usize) -> Result<Vec<u8>> {
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
        return Err("일반 파일/크기 상한 검사 실패".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("읽기 상한 초과".into());
    }
    Ok(bytes)
}

pub fn status(config: &AgentConfig) -> Result<()> {
    let bytes = bounded_read(
        &config.db_path.with_extension("health.json"),
        8 * 1024 * 1024,
    )?;
    let health: serde_json::Value = serde_json::from_slice(&bytes)?;
    let age = argos_common::now_ms()
        .checked_sub(health["timestamp_ms"].as_u64().ok_or("상태 시각 없음")?);
    let stale = age.is_none_or(|ms| ms > 60_000);
    let coverage = health
        .get("coverage")
        .ok_or("이 에이전트 상태에는 보호 공백 검사가 없습니다")?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"health_stale":stale,"health_age_ms":age,"coverage":coverage,"last_probe":"coverage probe를 별도로 실행해 지정 경로의 DB 도달을 확인하세요"})
        )?
    );
    if stale {
        return Err("에이전트 상태가 오래되었거나 시계가 역전되었습니다".into());
    }
    Ok(())
}

/// 고정된 시험 파일 작성 전용 자식. 다른 명령이나 임의 내용을 실행하지 않는다.
pub fn write_probe(path: &Path) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or("시험 파일 이름 오류")?;
    let nonce = name
        .strip_prefix(".argos-coverage-probe-")
        .ok_or("시험 파일 접두사 오류")?;
    if nonce.len() != 32 || !nonce.bytes().all(|x| x.is_ascii_hexdigit()) {
        return Err("시험 nonce 오류".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    file.write_all(format!("Argos coverage probe {nonce}\n").as_bytes())?;
    file.sync_all()?;
    Ok(())
}

pub fn probe(
    config: &AgentConfig,
    directory: &Path,
    timeout_secs: u64,
    out: Option<&Path>,
) -> Result<()> {
    if !(1..=60).contains(&timeout_secs) {
        return Err("시험 제한 시간은 1~60초입니다".into());
    }
    let directory = directory.canonicalize()?;
    if !directory.is_dir()
        || !config
            .watch_paths
            .iter()
            .filter_map(|p| p.canonicalize().ok())
            .any(|p| directory.starts_with(p))
    {
        return Err("시험 디렉터리는 설정된 감시 경로 안의 기존 디렉터리여야 합니다".into());
    }
    let store = EventStore::open_readonly(&config.db_path)?;
    let after_id = store.last_file_event_id()?;
    let mut nonce = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| "시험 난수 생성 실패")?;
    let nonce = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let path = directory.join(format!(".argos-coverage-probe-{nonce}"));
    #[cfg(target_os = "linux")]
    let directory_handle = {
        use std::os::unix::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawFd,
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&directory)?;
        let meta = file.metadata()?;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
            return Err(
                "시험 디렉터리는 실행 계정 소유이고 다른 계정에 쓰기 권한이 없어야 합니다".into(),
            );
        }
        let stable = std::path::PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            file.as_raw_fd()
        ))
        .join(path.file_name().unwrap());
        (file, stable)
    };
    #[cfg(target_os = "linux")]
    let write_path = &directory_handle.1;
    #[cfg(not(target_os = "linux"))]
    let write_path = &path;
    // 에이전트 자신의 fanotify 이벤트는 제외되므로 별도의 짧게 실행되는 자식이 쓴다.
    // 이 파일은 탐지/대응 규칙에서 제외하지 않는다. 종료되더라도 시험 자식에 한정된다.
    let mut child = ProbeChild(
        Command::new(std::env::current_exe()?)
            .arg("coverage-probe-write")
            .arg(write_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let start = Instant::now();
    let started_at = argos_common::now_ms();
    let mut observed = None;
    let mut child_ok = None;
    while start.elapsed() < Duration::from_secs(timeout_secs) {
        if child_ok.is_none() {
            child_ok = child.0.try_wait()?.map(|s| s.success());
        }
        if child_ok == Some(false) {
            break;
        }
        observed = store.probe_file_event(&path.to_string_lossy(), after_id)?;
        if child_ok == Some(true) && observed.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if child_ok.is_none() {
        let _ = child.0.kill();
        let _ = child.0.wait();
    }
    let expected = format!("Argos coverage probe {nonce}\n").into_bytes();
    let regular = fs::symlink_metadata(write_path)
        .is_ok_and(|m| m.is_file() && m.len() == expected.len() as u64);
    let unchanged = regular && bounded_read(write_path, 128).is_ok_and(|b| b == expected);
    // 고유한 새 이름에 만든 파일만 정리한다. 외부 교체/내용 변경은 그대로 두고 보고한다.
    let cleaned = unchanged && fs::remove_file(write_path).is_ok();
    #[cfg(target_os = "linux")]
    let directory_unchanged = {
        use std::os::unix::fs::MetadataExt;
        match (
            fs::symlink_metadata(&directory),
            directory_handle.0.metadata(),
        ) {
            (Ok(now), Ok(before)) => {
                now.is_dir() && now.dev() == before.dev() && now.ino() == before.ino()
            }
            _ => false,
        }
    };
    #[cfg(not(target_os = "linux"))]
    let directory_unchanged = directory.canonicalize().is_ok_and(|p| p == directory);
    let success = child_ok == Some(true) && observed.is_some() && unchanged && directory_unchanged;
    let report = json!({"format":"argos-coverage-probe-v1","success":success,"directory":directory,"directory_unchanged":directory_unchanged,"probe_path":path,"started_at_ms":started_at,"finished_at_ms":argos_common::now_ms(),"elapsed_ms":start.elapsed().as_millis(),"event_id":observed.map(|e|e.0),"event_timestamp_ms":observed.map(|e|e.1),"writer_succeeded":child_ok==Some(true),"content_unchanged":unchanged,"cleaned_up":cleaned,"scope":"지정 시험 파일의 센서→에이전트→로컬 DB 도달만 확인. 전체 경로/다른 네임스페이스/자동 차단/백업의 성공 증명이 아닙니다. 일반 탐지 규칙을 우회하지 않습니다."});
    let bytes = serde_json::to_vec_pretty(&report)?;
    if let Some(out) = out {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(out)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    println!("{}", String::from_utf8(bytes)?);
    if !success {
        return Err("보호 경로 시험 실패: 작성 결과와 저장된 이벤트를 확인하세요".into());
    }
    Ok(())
}
