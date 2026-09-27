//! A fixed self-binary worker keeps the complete drill behind a wall-clock
//! deadline, including native library and filesystem operations. Plans never
//! contain commands, arbitrary SQL, credentials, or database connection URLs.
use argos_recovery::service::{self, ServiceRecoveryPlan, ServiceRecoveryReport};
use clap::Subcommand;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type CmdResult = Result<(), Box<dyn std::error::Error>>;
const PLAN_LIMIT: usize = 64 * 1024;
const OUTPUT_LIMIT: usize = 256 * 1024;

#[derive(Subcommand)]
pub enum Action {
    /// 새 작업 디렉터리에 DB 네이티브 백업 복원 후 서비스 검증
    Test {
        /// 명시적 TOML 검증 계획 (로컬 백업만 지원)
        #[arg(long)]
        plan: PathBuf,
        /// 새 작업 디렉터리 절대 경로 (기존 경로는 거부)
        #[arg(long)]
        out: PathBuf,
    },
    /// 현재 계획·백업과 과거 성공 보고서의 일관성·유효 기간 확인 (무서명)
    Verify {
        /// 확인할 현재 TOML 복구 시험 계획
        #[arg(long)]
        plan: PathBuf,
        /// 비교할 v2 복구 시험 보고서 JSON
        #[arg(long)]
        report: PathBuf,
        /// 보고서 완료 후 허용할 최대 경과 시간(초, 1 이상)
        #[arg(long)]
        max_age_secs: u64,
    },
}

pub fn run(action: Action) -> CmdResult {
    match action {
        Action::Test { plan, out } => supervise(&plan, &out),
        Action::Verify {
            plan,
            report,
            max_age_secs,
        } => {
            let plan = read_plan(&plan)?;
            match service::verify_report(&plan, &report, max_age_secs) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    Ok(())
                }
                Err(error) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "format": "argos-service-report-verification-v1", "status": "rejected",
                            "failure_code": error.code, "report_authenticated": false
                        }))?
                    );
                    Err(error.into())
                }
            }
        }
    }
}

fn read_plan(path: &Path) -> Result<ServiceRecoveryPlan, Box<dyn std::error::Error>> {
    let path_before =
        std::fs::symlink_metadata(path).map_err(|_| "서비스 복구 계획을 읽을 수 없습니다")?;
    if !path_before.is_file() || path_before.file_type().is_symlink() {
        return Err("서비스 복구 계획은 일반 파일이어야 합니다".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "서비스 복구 계획을 읽을 수 없습니다")?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err("서비스 복구 계획은 일반 파일이어야 합니다".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((PLAN_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > PLAN_LIMIT {
        return Err("서비스 복구 계획이 64 KiB 제한을 초과했습니다".into());
    }
    let after = file.metadata()?;
    let path_after =
        std::fs::symlink_metadata(path).map_err(|_| "서비스 복구 계획이 읽는 중 변경되었습니다")?;
    let same = |left: &std::fs::Metadata, right: &std::fs::Metadata| {
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
    };
    if !same(&path_before, &before)
        || !same(&before, &after)
        || !same(&before, &path_after)
        || path_after.file_type().is_symlink()
        || bytes.len() as u64 != before.len()
    {
        return Err("서비스 복구 계획이 읽는 중 변경되었습니다".into());
    }
    // Do not echo parse errors: they can include the original, sensitive line.
    let text = std::str::from_utf8(&bytes).map_err(|_| "서비스 복구 계획은 UTF-8이어야 합니다")?;
    let plan: ServiceRecoveryPlan =
        toml::from_str(text).map_err(|_| "서비스 복구 TOML 계획이 올바르지 않습니다")?;
    service::validate_plan(&plan)?;
    Ok(plan)
}

fn capture(
    mut stream: impl Read + Send + 'static,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut result = Vec::new();
        let mut buffer = [0; 4096];
        while let Ok(n) = stream.read(&mut buffer) {
            if n == 0 {
                break;
            }
            let keep = n.min(OUTPUT_LIMIT.saturating_sub(result.len()));
            result.extend_from_slice(&buffer[..keep]);
            if keep < n {
                overflow.store(true, Ordering::Relaxed);
            }
        }
        result
    })
}

fn supervise(plan_path: &Path, out: &Path) -> CmdResult {
    let plan = read_plan(plan_path)?;
    if !out.is_absolute()
        || out.file_name().is_none()
        || out
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        || std::fs::symlink_metadata(out).is_ok()
    {
        return Err("서비스 복구 작업 경로는 존재하지 않는 절대 디렉터리 경로여야 합니다".into());
    }
    let data = serde_json::to_vec(&plan)?;
    if data.len() > PLAN_LIMIT {
        return Err("서비스 복구 계획이 작업 프로세스 입력 상한을 초과했습니다".into());
    }
    let start = Instant::now();
    let deadline = start + Duration::from_secs(plan.timeout_secs);
    let mut failed = service::new_report(&plan);
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("service-recovery-worker")
        .arg("--out")
        .arg(out)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let cpu = plan.timeout_secs + 1;
        let file = plan
            .max_backup_bytes
            .saturating_mul(4)
            .max(64 * 1024 * 1024);
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for (resource, limit) in [
                    (libc::RLIMIT_CPU, cpu),
                    (libc::RLIMIT_FSIZE, file),
                    (libc::RLIMIT_CORE, 0),
                    (libc::RLIMIT_AS, 2 * 1024 * 1024 * 1024),
                    (libc::RLIMIT_NOFILE, 256),
                ] {
                    let value = libc::rlimit {
                        rlim_cur: limit as libc::rlim_t,
                        rlim_max: limit as libc::rlim_t,
                    };
                    if libc::setrlimit(resource, &value) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    let mut child = command
        .spawn()
        .map_err(|_| "서비스 복구 작업 프로세스를 시작할 수 없습니다")?;
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout = capture(
        child
            .stdout
            .take()
            .ok_or("작업 프로세스 표준 출력 연결 실패")?,
        overflow.clone(),
    );
    let stderr = capture(
        child
            .stderr
            .take()
            .ok_or("작업 프로세스 오류 출력 연결 실패")?,
        overflow.clone(),
    );
    let mut input = child.stdin.take().ok_or("작업 프로세스 입력 연결 실패")?;
    let writer = thread::spawn(move || input.write_all(&data));
    let mut child_finished = false;
    let reason = loop {
        if Instant::now() >= deadline {
            break Some("timeout");
        }
        if overflow.load(Ordering::Relaxed) {
            break Some("worker_output_limit");
        }
        if !child_finished {
            match child.try_wait() {
                Ok(Some(_)) => child_finished = true,
                Ok(None) => {}
                Err(_) => break Some("worker_wait_failed"),
            }
        }
        // An exited worker is insufficient if a descendant still holds a pipe.
        if child_finished && stdout.is_finished() && stderr.is_finished() && writer.is_finished() {
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = if reason.is_some() {
        if !child_finished {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
        }
        // SIGKILL cannot make a task in uninterruptible kernel I/O exit
        // immediately. Cleanup must not hold the timeout report hostage.
        thread::spawn(move || {
            let _ = child.wait();
            let _ = writer.join();
            let _ = stdout.join();
            let _ = stderr.join();
        });
        Vec::new()
    } else {
        let _ = child.wait();
        let _ = writer.join();
        let output = stdout.join().unwrap_or_default();
        let _ = stderr.join(); // Never echo database errors or backup data.
        output
    };
    let reason = reason.or_else(|| {
        overflow
            .load(Ordering::Relaxed)
            .then_some("worker_output_limit")
    });
    let report = if let Some(reason) = reason {
        failed.failure_code = Some(reason.into());
        failed.total_duration_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
        failed.finished_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        failed.limitations.push("Supervisor failure report is stdout only; a killed worker may leave an incomplete workspace.".into());
        failed
    } else {
        serde_json::from_slice::<ServiceRecoveryReport>(&output).map_err(|_|"서비스 복구 작업 프로세스가 완료 보고서를 반환하지 못했습니다. 작업 경로 권한과 입력 파일을 확인하세요")?
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.status != "passed" {
        return Err(format!(
            "서비스 복구 검증 실패: {}",
            report.failure_code.as_deref().unwrap_or("unknown")
        )
        .into());
    }
    Ok(())
}

/// Internal command: only bounded, validated JSON is read from stdin. Direct use
/// has the same isolated workdir and no-external-connection constraints.
pub fn worker(out: &Path) -> CmdResult {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((PLAN_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > PLAN_LIMIT {
        return Err("작업 프로세스 입력 상한을 초과했습니다".into());
    }
    let plan: ServiceRecoveryPlan =
        serde_json::from_slice(&bytes).map_err(|_| "작업 프로세스 계획이 올바르지 않습니다")?;
    let report = service::run(&plan, out)?;
    println!("{}", serde_json::to_string(&report)?);
    if report.status != "passed" {
        return Err("서비스 복구 검증에 실패했습니다".into());
    }
    Ok(())
}
