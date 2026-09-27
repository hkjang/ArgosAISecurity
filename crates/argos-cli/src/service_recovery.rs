//! A fixed self-binary worker keeps the complete drill behind a wall-clock
//! deadline, including native library and filesystem operations. Plans never
//! contain commands, arbitrary SQL, credentials, or database connection URLs.
use argos_recovery::service::{self, ServiceRecoveryPlan, ServiceRecoveryReport};
use clap::Subcommand;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
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

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod sqlite_sandbox;

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

/// namespace 밖에서 열린 FD는 namespace 분리만으로 닫히지 않는다.
#[cfg(target_os = "linux")]
fn close_inherited_fds_on_exec() -> std::io::Result<()> {
    // exec 오류 전달 pipe도 CLOEXEC이므로 Rust spawn의 실패 보고는 유지한다.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Linux에서는 종료한 leader를 reap하지 않아 정리 시점까지 PID 재사용을 막는다.
fn observe_worker_exit(child: &mut Child) -> std::io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id(),
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(unsafe { info.si_pid() } != 0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        child.try_wait().map(|status| status.is_some())
    }
}

fn await_worker(
    child: &mut Child,
    deadline: Instant,
    overflow: &AtomicBool,
    pipes_finished: impl Fn() -> bool,
) -> Option<&'static str> {
    let mut child_finished = false;
    let reason = loop {
        if !child_finished {
            match observe_worker_exit(child) {
                Ok(done) => child_finished = done,
                // 다른 reaper가 PID 소유권을 잃게 했다면 해당 PID/그룹에 신호를 보내지 않는다.
                Err(_) => return Some("worker_wait_failed"),
            }
        }
        if Instant::now() >= deadline {
            break Some("timeout");
        }
        if overflow.load(Ordering::Relaxed) {
            break Some("worker_output_limit");
        }
        if child_finished && pipes_finished() {
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    if reason.is_some() {
        #[cfg(target_os = "linux")]
        {
            // WNOWAIT로 보존한 leader가 종료됐어도 pipe를 쥔 같은 그룹 자식을 종료한다.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
        }
        #[cfg(not(target_os = "linux"))]
        if !child_finished {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
        }
    }
    reason
}

fn configure_worker_limits(command: &mut Command, plan: &ServiceRecoveryPlan, preapproval: bool) {
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
                #[cfg(target_os = "linux")]
                if preapproval {
                    close_inherited_fds_on_exec()?;
                }
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
}

fn supervise(plan_path: &Path, out: &Path) -> CmdResult {
    let report = supervise_report(plan_path, out)?;
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

/// 동일한 격리·제한·감독 경계를 사용하되 호출자가 보고서 출력을 결정한다.
pub(crate) fn supervise_report(
    plan_path: &Path,
    out: &Path,
) -> Result<ServiceRecoveryReport, Box<dyn std::error::Error>> {
    supervise_report_mode(plan_path, out, false)
}

/// 미승인 입력은 지원되는 실제 격리 환경에서만 실행하며 일반 작업자로 우회하지 않는다.
pub(crate) fn supervise_preapproval_report(
    plan_path: &Path,
    out: &Path,
) -> Result<ServiceRecoveryReport, Box<dyn std::error::Error>> {
    supervise_report_mode(plan_path, out, true)
}

fn supervise_report_mode(
    plan_path: &Path,
    out: &Path,
    preapproval: bool,
) -> Result<ServiceRecoveryReport, Box<dyn std::error::Error>> {
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
    let start = Instant::now();
    let deadline = start + Duration::from_secs(plan.timeout_secs);
    let mut failed = service::new_report(&plan);
    let mut worker_plan = plan.clone();
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    let mut sandbox = None;
    let mut command;
    if preapproval && plan.engine == service::DatabaseEngine::Sqlite {
        #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
        {
            let isolated = sqlite_sandbox::Sandbox::new(&plan, out)?;
            worker_plan = isolated.worker_plan(&plan);
            command = isolated.worker_command();
            sandbox = Some(isolated);
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
        {
            return Err(
                "승인 전 SQLite 시험에는 GNU/Linux x86_64와 bubblewrap이 필요합니다".into(),
            );
        }
    } else {
        command = Command::new(std::env::current_exe()?);
        command.arg("service-recovery-worker").arg("--out").arg(out);
    }
    let data = serde_json::to_vec(&worker_plan)?;
    if data.len() > PLAN_LIMIT {
        return Err("서비스 복구 계획이 작업 프로세스 입력 상한을 초과했습니다".into());
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_worker_limits(&mut command, &plan, preapproval);
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
    let reason = await_worker(&mut child, deadline, &overflow, || {
        stdout.is_finished() && stderr.is_finished() && writer.is_finished()
    });
    let output = if reason.is_some() {
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    if let Some(sandbox) = sandbox {
        if reason.is_none() {
            sandbox.publish(out)?;
        }
    }
    Ok(report)
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

#[cfg(all(test, target_os = "linux"))]
mod supervision_tests {
    use super::*;
    use std::{io::BufRead, os::unix::process::CommandExt, sync::mpsc};

    #[test]
    fn exited_leader_keeps_pid_reserved_until_descendant_pipe_timeout_cleanup() {
        const FIXTURE: &str = "ARGOS_SUPERVISOR_FIXTURE";
        if std::env::var_os(FIXTURE).is_none() {
            // subreaper 설정이 병렬 테스트에 영향을 주지 않도록 전용 테스트 프로세스를 쓴다.
            let mut command = Command::new(std::env::current_exe().unwrap());
            command.env(FIXTURE, "1").args(["--exact", "service_recovery::supervision_tests::exited_leader_keeps_pid_reserved_until_descendant_pipe_timeout_cleanup"]);
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = command.spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if child.try_wait().unwrap().is_some() {
                    let result = child.wait_with_output().unwrap();
                    assert!(
                        result.status.success(),
                        "{} {}",
                        String::from_utf8_lossy(&result.stdout),
                        String::from_utf8_lossy(&result.stderr)
                    );
                    return;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("고정 감독 시험 제한 시간 초과");
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        // 계획에는 명령을 받지 않는다. 이 고정 fixture만 pipe를 상속한 자식을 남긴다.
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 60 & printf '%s\\n' \"$!\"; exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let mut pipe = std::io::BufReader::new(child.stdout.take().unwrap());
        let (ready, wait) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut line = String::new();
            pipe.read_line(&mut line).unwrap();
            ready.send(line.trim().parse::<i32>().unwrap()).unwrap();
            let mut rest = Vec::new();
            pipe.read_to_end(&mut rest).unwrap();
        });
        let descendant = wait.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        let reason = await_worker(
            &mut child,
            started + Duration::from_millis(200),
            &AtomicBool::new(false),
            || reader.is_finished(),
        );
        assert_eq!(reason, Some("timeout"));
        assert!(started.elapsed() < Duration::from_secs(2));
        // waitid(WNOWAIT)는 이미 종료한 leader를 소비하지 않았으며 여기서 처음 reap한다.
        assert!(observe_worker_exit(&mut child).unwrap());
        assert!(child.wait().unwrap().success());
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(descendant, &mut status, libc::WNOHANG) };
            if waited == descendant {
                assert!(libc::WIFSIGNALED(status));
                assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "pipe를 보유한 자식이 종료되지 않았습니다"
            );
            thread::sleep(Duration::from_millis(10));
        }
        reader.join().unwrap();
    }
    #[test]
    fn preapproval_postgresql_supervisor_closes_inherited_file_and_socket_fds() {
        const FILE: &str = "ARGOS_PG_TRIAL_FILE_FD";
        const SOCKET: &str = "ARGOS_PG_TRIAL_SOCKET_FD";
        if std::env::var_os(FILE).is_some() {
            for name in [FILE, SOCKET] {
                let fd: i32 = std::env::var(name).unwrap().parse().unwrap();
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF)
                );
            }
            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"fixed plan pipe");
            return;
        }
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let file = std::fs::File::open("/proc/self/status").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let inheritable = |fd| {
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD, 200) };
            assert!(duplicate >= 200);
            assert_eq!(unsafe { libc::fcntl(duplicate, libc::F_SETFD, 0) }, 0);
            unsafe { OwnedFd::from_raw_fd(duplicate) }
        };
        let file_fd = inheritable(file.as_raw_fd());
        let socket_fd = inheritable(socket.as_raw_fd());
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.env(FILE, file_fd.as_raw_fd().to_string()).env(SOCKET, socket_fd.as_raw_fd().to_string())
            .args(["--exact", "service_recovery::supervision_tests::preapproval_postgresql_supervisor_closes_inherited_file_and_socket_fds"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // PostgreSQL 작업자 선택 뒤 적용하는 실제 공통 감독 설정이다. DB 실행은 별도 시나리오가 검증한다.
        let mut plan: ServiceRecoveryPlan = toml::from_str("service_id='trial'\nengine='sqlite'\nbackup_path='/unused'\n[[tables]]\ncheck_id='orders'\ntable='orders'\n").unwrap();
        plan.engine = service::DatabaseEngine::Postgresql;
        configure_worker_limits(&mut command, &plan, true);
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"fixed plan pipe")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.try_wait().unwrap().is_some() {
                let result = child.wait_with_output().unwrap();
                assert!(
                    result.status.success(),
                    "{} {}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
                return;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("승인 전 PostgreSQL worker FD 검사 제한 시간 초과");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
