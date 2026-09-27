//! 승인 전 SQLite 입력은 호스트 파일/네트워크 없이 고정 실행 파일로만 검사한다.
use argos_recovery::service::ServiceRecoveryPlan;
use rand_core::{OsRng, RngCore};
use std::{
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(super) struct Sandbox {
    work: PathBuf,
    backup: PathBuf,
    executable: PathBuf,
    loader: PathBuf,
    libraries: Vec<(PathBuf, &'static str)>,
}

fn trusted_file(path: &Path, root_owned: bool) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let canonical = path.canonicalize()?;
    let metadata = fs::metadata(&canonical)?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.mode() & 0o022 != 0
        || (root_owned && metadata.uid() != 0)
        || (!root_owned && metadata.uid() != 0 && metadata.uid() != uid)
    {
        return Err("격리 시험 실행 파일·라이브러리 소유자/권한 오류".into());
    }
    let mut current = canonical.parent();
    while let Some(parent) = current {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && (root_owned || metadata.uid() != uid))
            || (metadata.mode() & 0o022 != 0
                && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0))
        {
            return Err("격리 시험 런타임 상위 경로를 신뢰할 수 없습니다".into());
        }
        current = parent.parent();
    }
    Ok(canonical)
}

fn runtime_file(name: &'static str) -> Result<PathBuf> {
    for parent in [
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/lib64",
        "/usr/lib64",
    ] {
        let path = Path::new(parent).join(name);
        if path.exists() {
            return trusted_file(&path, true);
        }
    }
    Err("승인 전 SQLite 시험에 필요한 GNU 런타임이 없습니다".into())
}

impl Sandbox {
    pub(super) fn new(plan: &ServiceRecoveryPlan, out: &Path) -> Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        if unsafe { libc::geteuid() } == 0 {
            return Err("승인 전 SQLite 시험은 일반 사용자로 실행해야 합니다".into());
        }
        if !out.is_absolute() || out.components().any(|p| matches!(p, Component::ParentDir)) {
            return Err("격리 시험 출력은 .. 없는 절대 경로여야 합니다".into());
        }
        let parent = out.parent().ok_or("격리 시험 부모 경로 없음")?;
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o700
        {
            return Err("격리 시험 부모는 현재 계정 소유 0700이어야 합니다".into());
        }
        // 호스트의 설정·라이브러리 검색 환경은 전달하지 않는다.
        trusted_file(Path::new("/usr/bin/bwrap"), true)?;
        let executable = trusted_file(&std::env::current_exe()?, false)?;
        let loader = trusted_file(Path::new("/lib64/ld-linux-x86-64.so.2"), true)?;
        let mut libraries = Vec::new();
        for name in ["libc.so.6", "libm.so.6", "libgcc_s.so.1"] {
            libraries.push((runtime_file(name)?, name));
        }
        let source_metadata = fs::symlink_metadata(&plan.backup_path)?;
        if !source_metadata.is_file() || source_metadata.file_type().is_symlink() {
            return Err("격리 시험 백업은 일반 파일이어야 합니다".into());
        }
        let backup = plan.backup_path.canonicalize()?;
        let mut random = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| "격리 경로 난수 생성 실패")?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let work = parent.join(format!(".sqlite-preapproval-{suffix}"));
        fs::DirBuilder::new().mode(0o700).create(&work)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(Self {
            work,
            backup,
            executable,
            loader,
            libraries,
        })
    }

    fn command_base(&self) -> Command {
        use std::os::unix::process::CommandExt;
        let mut command = Command::new("/usr/bin/bwrap");
        // bwrap 자체는 부모의 임의 FD를 닫지 않으므로 exec 경계에서 강제한다.
        unsafe {
            command.pre_exec(super::close_inherited_fds_on_exec);
        }
        command.env_clear().args([
            "--unshare-all",
            "--unshare-user",
            "--unshare-net",
            "--unshare-pid",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--dir",
            "/lib64",
            "--dir",
            "/runtime",
            "--dir",
            "/input",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--size",
            "16777216",
            "--tmpfs",
            "/tmp",
        ]);
        command
            .arg("--ro-bind")
            .arg(&self.executable)
            .arg("/argos")
            .arg("--ro-bind")
            .arg(&self.loader)
            .arg("/lib64/ld-linux-x86-64.so.2");
        for (source, name) in &self.libraries {
            command
                .arg("--ro-bind")
                .arg(source)
                .arg(format!("/runtime/{name}"));
        }
        command
            .arg("--ro-bind")
            .arg(&self.backup)
            .arg("/input/backup.sqlite3")
            .arg("--bind")
            .arg(&self.work)
            .arg("/work")
            .args([
                "--remount-ro",
                "/",
                "--chdir",
                "/work",
                "--setenv",
                "HOME",
                "/work",
                "--setenv",
                "LC_ALL",
                "C",
                "--setenv",
                "LD_LIBRARY_PATH",
                "/runtime",
                "--setenv",
                "TMPDIR",
                "/tmp",
                "--setenv",
                "SQLITE_TMPDIR",
                "/tmp",
            ]);
        command
    }

    pub(super) fn worker_command(&self) -> Command {
        let mut command = self.command_base();
        command.args([
            "--",
            "/argos",
            "service-recovery-worker",
            "--out",
            "/work/drill",
        ]);
        command
    }

    pub(super) fn worker_plan(&self, plan: &ServiceRecoveryPlan) -> ServiceRecoveryPlan {
        let mut plan = plan.clone();
        plan.backup_path = "/input/backup.sqlite3".into();
        plan
    }

    pub(super) fn publish(&self, out: &Path) -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let metadata = fs::symlink_metadata(self.work.join("drill"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("격리 시험 결과는 실제 디렉터리여야 합니다".into());
        }
        let source = std::ffi::CString::new(self.work.join("drill").as_os_str().as_bytes())?;
        let destination = std::ffi::CString::new(out.as_os_str().as_bytes())?;
        if unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err("격리 시험 결과를 새 경로에 게시하지 못했습니다".into());
        }
        fs::File::open(out.parent().ok_or("격리 결과 부모 없음")?)?.sync_all()?;
        // 실패/중단 자료는 자동 삭제하지 않는다. 성공 뒤 비어 있는 작업 루트만 제거한다.
        let _ = fs::remove_dir(&self.work);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        net::{TcpListener, TcpStream},
        time::Duration,
    };

    #[test]
    #[ignore = "실제 비root GNU/Linux x86_64·bubblewrap·userns 환경 필요"]
    fn sandbox_hides_host_files_network_and_allows_only_private_workspace() {
        if std::env::var_os("ARGOS_SQLITE_SANDBOX_PROBE").is_some() {
            assert!(!Path::new("/etc/passwd").exists());
            assert!(!Path::new("/home").exists());
            assert!(!Path::new("/root").exists());
            assert!(!Path::new("/run").exists());
            assert!(fs::write("/escape", b"denied").is_err());
            assert!(fs::write("/runtime/escape", b"denied").is_err());
            for name in ["ARGOS_TEST_FILE_FD", "ARGOS_TEST_SOCKET_FD"] {
                let fd: i32 = std::env::var(name).unwrap().parse().unwrap();
                assert!(fs::read(format!("/proc/self/fd/{fd}")).is_err());
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF)
                );
                let mut byte = [0u8; 1];
                assert_eq!(unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF)
                );
                assert_eq!(
                    unsafe { libc::send(fd, byte.as_ptr().cast(), 1, libc::MSG_NOSIGNAL) },
                    -1
                );
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF)
                );
            }
            let secret = std::env::var("ARGOS_TEST_HOST_MARKER").unwrap();
            assert!(fs::read(secret).is_err());
            assert!(fs::OpenOptions::new()
                .write(true)
                .open("/input/backup.sqlite3")
                .is_err());
            assert!(fs::read("/input/backup.sqlite3").is_ok());
            assert!(std::env::var_os("ARGOS_TEST_HOST_SECRET").is_none());
            let address = std::env::var("ARGOS_TEST_HOST_ADDRESS").unwrap();
            assert!(TcpStream::connect_timeout(
                &address.parse().unwrap(),
                Duration::from_millis(100)
            )
            .is_err());
            fs::create_dir("/work/drill").unwrap();
            fs::File::create("/work/drill/marker")
                .unwrap()
                .write_all(b"sandbox write")
                .unwrap();
            return;
        }
        use std::os::unix::fs::DirBuilderExt;
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let parent = std::env::temp_dir().join(format!("argos-sqlite-sandbox-{suffix}"));
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let backup = parent.join("backup");
        fs::write(&backup, b"sandbox input").unwrap();
        let marker = parent.join("host-secret");
        fs::write(&marker, b"host private data").unwrap();
        let plan: ServiceRecoveryPlan = toml::from_str(&format!("service_id='test'\nengine='sqlite'\nbackup_path='{}'\n[[tables]]\ncheck_id='orders'\ntable='orders'\n",backup.display())).unwrap();
        let out = parent.join("result");
        let sandbox = Sandbox::new(&plan, &out).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host_socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let host_file = fs::File::open(&marker).unwrap();
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let inheritable = |fd| {
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD, 200) };
            assert!(duplicate >= 200);
            let flags = unsafe { libc::fcntl(duplicate, libc::F_GETFD) };
            assert_eq!(
                unsafe { libc::fcntl(duplicate, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
                0
            );
            assert_eq!(
                unsafe { libc::fcntl(duplicate, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            unsafe { OwnedFd::from_raw_fd(duplicate) }
        };
        let file_fd = inheritable(host_file.as_raw_fd());
        let socket_fd = inheritable(host_socket.as_raw_fd());
        let mut command = sandbox.command_base();
        command.args(["--setenv","ARGOS_SQLITE_SANDBOX_PROBE","1","--setenv","ARGOS_TEST_HOST_MARKER"])
            .arg(&marker).args(["--setenv","ARGOS_TEST_HOST_ADDRESS"])
            .arg(listener.local_addr().unwrap().to_string())
            .args(["--setenv", "ARGOS_TEST_FILE_FD"]).arg(file_fd.as_raw_fd().to_string())
            .args(["--setenv", "ARGOS_TEST_SOCKET_FD"]).arg(socket_fd.as_raw_fd().to_string())
            .args(["--","/argos","--ignored","--exact","service_recovery::sqlite_sandbox::tests::sandbox_hides_host_files_network_and_allows_only_private_workspace"]);
        command.env("ARGOS_TEST_HOST_SECRET", "must-not-enter");
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("격리 시험 자식 제한 시간 초과");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "sandbox failed: {} {}",
            String::from_utf8_lossy(&result.stderr),
            String::from_utf8_lossy(&result.stdout)
        );
        sandbox.publish(&out).unwrap();
        assert_eq!(fs::read(out.join("marker")).unwrap(), b"sandbox write");
        assert_eq!(fs::read(&marker).unwrap(), b"host private data");
        assert_eq!(fs::read(&backup).unwrap(), b"sandbox input");
        assert!(sandbox.publish(&out).is_err());
        fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn runtime_trust_resolves_links_and_rejects_writable_files_or_ancestors() {
        use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let parent = std::env::temp_dir().join(format!("argos-runtime-trust-{suffix}"));
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let directory = parent.join("runtime");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let file = directory.join("library");
        fs::write(&file, b"trusted fixture").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let link = parent.join("library-link");
        symlink(&file, &link).unwrap();
        assert_eq!(
            trusted_file(&link, false).unwrap(),
            file.canonicalize().unwrap()
        );
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(trusted_file(&link, false).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(trusted_file(&link, false).is_err());
        fs::remove_dir_all(parent).unwrap();
    }
}
