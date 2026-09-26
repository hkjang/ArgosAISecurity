//! PostgreSQL custom-archive drills. Every server/client process runs in a
//! networkless Linux bubblewrap sandbox. The host report directory is not bound.
use super::*;
use std::{
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

const OUTPUT_LIMIT: usize = 64 * 1024;
struct Captured {
    child: Child,
    exceeded: Arc<AtomicBool>,
    readers: Vec<thread::JoinHandle<Vec<u8>>>,
    budget: Option<(PathBuf, u64)>,
}
impl Drop for Captured {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}
impl Captured {
    fn start(mut command: Command, sql: Option<&str>) -> Result<Self> {
        command
            .stdin(if sql.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|_| failure("postgresql_sandbox_start_failed"))?;
        let exceeded = Arc::new(AtomicBool::new(false));
        let mut readers = Vec::new();
        fn drain(
            mut stream: impl Read + Send + 'static,
            exceeded: Arc<AtomicBool>,
        ) -> thread::JoinHandle<Vec<u8>> {
            thread::spawn(move || {
                let mut captured = Vec::new();
                let mut buffer = [0; 4096];
                while let Ok(n) = stream.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    let keep = n.min(OUTPUT_LIMIT.saturating_sub(captured.len()));
                    captured.extend_from_slice(&buffer[..keep]);
                    if keep < n {
                        exceeded.store(true, Ordering::Relaxed);
                    }
                }
                captured
            })
        }
        readers.push(drain(
            child
                .stdout
                .take()
                .ok_or_else(|| failure("postgresql_output_capture_failed"))?,
            exceeded.clone(),
        ));
        readers.push(drain(
            child
                .stderr
                .take()
                .ok_or_else(|| failure("postgresql_output_capture_failed"))?,
            exceeded.clone(),
        ));
        let mut process = Self {
            child,
            exceeded,
            readers,
            budget: None,
        };
        if let Some(sql) = sql {
            process
                .child
                .stdin
                .take()
                .ok_or_else(|| failure("postgresql_input_failed"))?
                .write_all(sql.as_bytes())
                .map_err(|_| failure("postgresql_input_failed"))?;
        }
        Ok(process)
    }
    fn with_budget(mut self, path: &Path, limit: u64) -> Self {
        self.budget = Some((path.to_path_buf(), limit));
        self
    }
    fn finish(mut self, deadline: Instant) -> Result<Vec<u8>> {
        let mut last_budget = Instant::now() - Duration::from_secs(1);
        loop {
            deadline_check(deadline)?;
            if last_budget.elapsed() >= Duration::from_millis(100) {
                if let Some((path, limit)) = &self.budget {
                    workspace_budget(path, *limit, deadline)?;
                }
                last_budget = Instant::now();
            }
            if self.exceeded.load(Ordering::Relaxed) {
                return Err(failure("postgresql_output_limit"));
            }
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|_| failure("postgresql_process_wait_failed"))?
            {
                let outputs: Vec<Vec<u8>> = self
                    .readers
                    .drain(..)
                    .map(|handle| handle.join().unwrap_or_default())
                    .collect();
                if self.exceeded.load(Ordering::Relaxed) {
                    return Err(failure("postgresql_output_limit"));
                }
                if !status.success() {
                    return Err(failure("postgresql_command_failed"));
                }
                return Ok(outputs.into_iter().next().unwrap_or_default());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

struct Sandbox {
    bin: PathBuf,
    share: PathBuf,
    installation: PathBuf,
    libraries: PathBuf,
    work: PathBuf,
    identity: PathBuf,
    backup: PathBuf,
    memory_bytes: u64,
    file_bytes: u64,
    timeout_secs: u64,
    workspace_limit: u64,
}
impl Sandbox {
    fn new(plan: &ServiceRecoveryPlan, directory: &Path) -> Result<Self> {
        if unsafe { libc::geteuid() } == 0 {
            return Err(failure("postgresql_requires_unprivileged_user"));
        }
        let settings = plan
            .postgresql
            .as_ref()
            .ok_or_else(|| failure("postgresql_settings_required"))?;
        let root = fs::canonicalize(&settings.installation_root)
            .map_err(|_| failure("postgresql_installation_missing"))?;
        let bin = root.join(format!("usr/lib/postgresql/{}/bin", settings.major_version));
        let share = root.join(format!("usr/share/postgresql/{}", settings.major_version));
        let installation = PathBuf::from(format!(
            "/opt/pg/usr/lib/postgresql/{}",
            settings.major_version
        ));
        let libraries = root.join("usr/lib/x86_64-linux-gnu");
        if !Path::new("/usr/bin/bwrap").is_file() {
            return Err(failure("postgresql_bubblewrap_required"));
        }
        for name in ["postgres", "initdb", "pg_restore", "psql"] {
            if !bin.join(name).is_file() {
                return Err(failure("postgresql_tools_missing"));
            }
        }
        if !share.is_dir() || !libraries.is_dir() {
            return Err(failure("postgresql_runtime_missing"));
        }
        let private_directory =
            fs::canonicalize(directory).map_err(|_| failure("postgresql_workspace_unavailable"))?;
        // A workspace nested inside a runtime bind would expose its parent
        // report and identity files through a second, read-only path.
        for runtime in [
            bin.parent().unwrap(),
            share.as_path(),
            libraries.as_path(),
            Path::new("/usr/bin"),
            Path::new("/usr/lib"),
            Path::new("/bin"),
            Path::new("/lib"),
            Path::new("/lib64"),
            Path::new("/usr/share/zoneinfo"),
        ] {
            if fs::canonicalize(runtime).is_ok_and(|path| private_directory.starts_with(path)) {
                return Err(failure("postgresql_workspace_overlaps_runtime"));
            }
        }
        let work = directory.join("postgresql");
        create_workspace(&work)?;
        create_workspace(&work.join("socket"))?;
        // Keep bind sources outside writable /work: restored SQL may replace
        // files there with host-absolute symlinks before the next bwrap starts.
        // PostgreSQL requires /etc/passwd resolution even with explicit DB user.
        let mut passwd = new_file(&directory.join("sandbox-passwd"))?;
        writeln!(
            passwd,
            "argos:x:{}:{}:Argos:/work:/bin/false",
            unsafe { libc::getuid() },
            unsafe { libc::getgid() }
        )
        .map_err(|_| failure("postgresql_identity_write_failed"))?;
        let mut group = new_file(&directory.join("sandbox-group"))?;
        writeln!(group, "argos:x:{}:", unsafe { libc::getgid() })
            .map_err(|_| failure("postgresql_identity_write_failed"))?;
        Ok(Self {
            bin,
            share,
            installation,
            libraries,
            work,
            identity: directory.to_path_buf(),
            backup: directory.join("input.dump"),
            memory_bytes: 1024 * 1024 * 1024,
            file_bytes: plan
                .max_backup_bytes
                .saturating_mul(4)
                .max(64 * 1024 * 1024),
            timeout_secs: plan.timeout_secs,
            workspace_limit: plan.max_workspace_bytes,
        })
    }
    fn command(&self, binary: &str, args: &[&str]) -> Result<Command> {
        let mut command = Command::new("/usr/bin/bwrap");
        command.args([
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
            "/usr",
            "--ro-bind",
            "/usr/bin",
            "/usr/bin",
            "--ro-bind",
            "/usr/lib",
            "/usr/lib",
            "--dir",
            "/usr/share",
        ]);
        for path in ["/bin", "/lib", "/lib64", "/usr/share/zoneinfo"] {
            if Path::new(path).exists() {
                command.args(["--ro-bind", path, path]);
            }
        }
        command
            .args([
                "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/etc", "--dir",
                "/opt",
            ])
            .arg("--ro-bind")
            .arg(self.identity.join("sandbox-passwd"))
            .arg("/etc/passwd")
            .arg("--ro-bind")
            .arg(self.identity.join("sandbox-group"))
            .arg("/etc/group")
            .arg("--ro-bind")
            .arg(self.bin.parent().unwrap())
            .arg(&self.installation)
            .arg("--ro-bind")
            .arg(&self.share)
            .arg("/opt/pgshare")
            .arg("--ro-bind")
            .arg(&self.share)
            .arg(format!(
                "/opt/pg/usr/share/postgresql/{}",
                self.installation.file_name().unwrap().to_string_lossy()
            ))
            .arg("--ro-bind")
            .arg(&self.libraries)
            .arg("/opt/pglib")
            .arg("--ro-bind")
            .arg(&self.backup)
            .arg("/backup.dump")
            .arg("--bind")
            .arg(&self.work)
            .arg("/work")
            .args([
                "--chdir",
                "/work",
                "--setenv",
                "PATH",
                "/opt/pgbin:/usr/bin:/bin",
                "--setenv",
                "HOME",
                "/work",
                "--setenv",
                "LC_ALL",
                "C",
                "--setenv",
                "LD_LIBRARY_PATH",
                "/opt/pglib",
                "--setenv",
                "PGOPTIONS",
                "-csearch_path=pg_catalog -cstatement_timeout=300000 -cclient_min_messages=error",
                "--",
            ])
            .arg(self.installation.join("bin").join(binary))
            .args(args);
        // The trusted program paths cannot be supplied as an arbitrary command.
        // Cap every inherited sandbox process. Root report files are not exposed.
        use std::os::unix::process::CommandExt;
        let memory = self.memory_bytes;
        let file = self.file_bytes;
        let cpu = self.timeout_secs + 1;
        unsafe {
            command.pre_exec(move || {
                for (resource, limit) in [
                    (libc::RLIMIT_AS, memory),
                    (libc::RLIMIT_FSIZE, file),
                    (libc::RLIMIT_CPU, cpu),
                    (libc::RLIMIT_NOFILE, 128),
                    (libc::RLIMIT_CORE, 0),
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
        Ok(command)
    }
    fn exec(
        &self,
        binary: &str,
        args: &[&str],
        sql: Option<&str>,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        Captured::start(self.command(binary, args)?, sql)?
            .with_budget(self.work.parent().unwrap(), self.workspace_limit)
            .finish(deadline)
    }
    fn query(&self, sql: &str, deadline: Instant) -> Result<Vec<u8>> {
        self.exec(
            "psql",
            &[
                "-X",
                "-qAt",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                "/work/socket",
                "-U",
                "argosverify",
                "-d",
                "postgres",
                "--no-password",
            ],
            Some(sql),
            deadline,
        )
    }
    fn scalar(&self, sql: &str, deadline: Instant) -> Result<u64> {
        let bytes = self.query(sql, deadline)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| failure("postgresql_invalid_check_output"))?
            .trim();
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(failure("postgresql_invalid_check_output"));
        }
        text.parse()
            .map_err(|_| failure("postgresql_invalid_check_output"))
    }
}

pub(super) fn run(
    plan: &ServiceRecoveryPlan,
    directory: &Path,
    deadline: Instant,
    report: &mut ServiceRecoveryReport,
) -> Result<()> {
    let restore_start = Instant::now();
    let (hash, bytes) = stage_backup(plan, directory, deadline)?;
    report.backup_sha256 = Some(hash);
    report.backup_bytes = Some(bytes);
    let sandbox = Sandbox::new(plan, directory)?;
    sandbox
        .exec(
            "initdb",
            &[
                "-D",
                "/work/data",
                "-U",
                "argosverify",
                "--auth-local=trust",
                "--auth-host=reject",
                "--no-locale",
                "--encoding=UTF8",
                "--no-instructions",
                "-L",
                "/opt/pgshare",
            ],
            None,
            deadline,
        )
        .map_err(|e| {
            if e.code == "postgresql_command_failed" {
                failure("postgresql_initdb_or_sandbox_failed")
            } else {
                e
            }
        })?;
    let server = Captured::start(
        sandbox.command(
            "postgres",
            &[
                "-D",
                "/work/data",
                "-k",
                "/work/socket",
                "-c",
                "listen_addresses=",
                "-c",
                "unix_socket_permissions=0700",
                "-c",
                "max_connections=5",
                "-c",
                "shared_buffers=16MB",
                "-c",
                "max_worker_processes=0",
                "-c",
                "max_parallel_workers=0",
                "-c",
                "jit=off",
                "-c",
                "logging_collector=off",
                "-c",
                "log_min_messages=panic",
                "-c",
                "log_statement=none",
                "-c",
                "temp_file_limit=262144",
                "-c",
                "statement_timeout=300000",
                "-c",
                "shared_preload_libraries=",
                "-c",
                "session_preload_libraries=",
                "-c",
                "local_preload_libraries=",
            ],
        )?,
        None,
    )?;
    let ready_deadline = deadline.min(Instant::now() + Duration::from_secs(10));
    loop {
        deadline_check(ready_deadline)?;
        if server.exceeded.load(Ordering::Relaxed) {
            return Err(failure("postgresql_server_output_limit"));
        }
        if sandbox.scalar("SELECT 1;", ready_deadline).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    sandbox
        .exec(
            "pg_restore",
            &[
                "--exit-on-error",
                "--single-transaction",
                "--no-owner",
                "--no-acl",
                "--no-comments",
                "--no-password",
                "--host=/work/socket",
                "--username=argosverify",
                "--dbname=postgres",
                "/backup.dump",
            ],
            None,
            deadline,
        )
        .map_err(|e| {
            if e.code == "postgresql_command_failed" {
                failure("postgresql_native_restore_failed")
            } else {
                e
            }
        })?;
    report.restore_duration_ms = elapsed_ms(restore_start);
    let validation_start = Instant::now();
    let result = validate(&sandbox, plan, deadline, report);
    report.validation_duration_ms = elapsed_ms(validation_start);
    drop(server);
    // Keep the native cluster as evidence; no server remains running.
    result
}
fn validate(
    sandbox: &Sandbox,
    plan: &ServiceRecoveryPlan,
    deadline: Instant,
    report: &mut ServiceRecoveryReport,
) -> Result<()> {
    // pg_restore --exit-on-error validates restoration of FK constraints. Also
    // reject deliberately unvalidated constraints rather than implying validity.
    let invalid=sandbox.scalar("SELECT count(*) FROM pg_catalog.pg_constraint WHERE contype IN ('f','c') AND NOT convalidated;",deadline)?;
    check_result(
        report,
        "argos-constraints",
        invalid == 0,
        if invalid == 0 {
            "ok"
        } else {
            "unvalidated_constraints"
        },
        Some(invalid),
    );
    if invalid != 0 {
        return Err(failure("postgresql_unvalidated_constraints"));
    }
    for table in &plan.tables {
        let count=sandbox.scalar(&format!("SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='{}' AND c.relkind='r' AND NOT c.relrowsecurity;",table.table),deadline)?;
        if count != 1 {
            check_result(
                report,
                &table.check_id,
                false,
                "ordinary_public_table_missing_or_rls_enabled",
                None,
            );
            return Err(failure("postgresql_expected_table_missing"));
        }
        for column in &table.required_columns {
            let count=sandbox.scalar(&format!("SELECT count(*) FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='{}' AND a.attname='{}' AND a.attnum>0 AND NOT a.attisdropped;",table.table,column),deadline)?;
            if count != 1 {
                check_result(
                    report,
                    &table.check_id,
                    false,
                    "required_column_missing",
                    None,
                );
                return Err(failure("postgresql_expected_column_missing"));
            }
        }
        let count = sandbox.scalar(
            &format!("SELECT count(*) FROM public.\"{}\";", table.table),
            deadline,
        )?;
        check_result(
            report,
            &table.check_id,
            count >= table.min_rows,
            if count >= table.min_rows {
                "ok"
            } else {
                "insufficient_rows"
            },
            Some(count),
        );
        if count < table.min_rows {
            return Err(failure("postgresql_row_expectation_failed"));
        }
    }
    let result=sandbox.scalar("BEGIN; CREATE TABLE public.__argos_service_recovery_probe(value bigint NOT NULL); INSERT INTO public.__argos_service_recovery_probe VALUES(73021); SELECT value FROM public.__argos_service_recovery_probe; ROLLBACK;",deadline)?;
    if result != 73021 {
        return Err(failure("postgresql_write_probe_mismatch"));
    }
    check_result(report, "argos-write-read-rollback", true, "ok", None);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires explicit ARGOS_TEST_POSTGRES_ROOT and working unprivileged bubblewrap"]
    fn postgresql_custom_archive_restores_and_checks_in_networkless_sandbox() {
        let installation =
            std::env::var_os("ARGOS_TEST_POSTGRES_ROOT").expect("explicit PostgreSQL package root");
        let root =
            std::env::temp_dir().join(format!("argos-postgresql-drill-{}", std::process::id()));
        create_workspace(&root).unwrap();
        let fixture = root.join("fixture");
        create_workspace(&fixture).unwrap();
        fs::write(fixture.join("input.dump"), b"PGDMP").unwrap();
        let mut plan = ServiceRecoveryPlan {
            service_id: "orders".into(),
            engine: DatabaseEngine::Postgresql,
            backup_path: root.join("orders.dump"),
            timeout_secs: 30,
            max_backup_bytes: 16 * 1024 * 1024,
            max_workspace_bytes: 512 * 1024 * 1024,
            declared_recovery_point_ms: None,
            incident_at_ms: None,
            expected_user_version: None,
            tables: vec![TableExpectation {
                check_id: "orders".into(),
                table: "orders".into(),
                required_columns: vec!["id".into(), "secret".into()],
                min_rows: 2,
            }],
            postgresql: Some(PostgresqlSettings {
                installation_root: PathBuf::from(installation),
                major_version: 18,
            }),
        };
        let sandbox = Sandbox::new(&plan, &fixture).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        sandbox
            .exec(
                "initdb",
                &[
                    "-D",
                    "/work/data",
                    "-U",
                    "argosverify",
                    "--auth-local=trust",
                    "--auth-host=reject",
                    "--no-locale",
                    "--encoding=UTF8",
                    "--no-instructions",
                    "-L",
                    "/opt/pgshare",
                ],
                None,
                deadline,
            )
            .unwrap();
        let server = Captured::start(
            sandbox
                .command(
                    "postgres",
                    &[
                        "-D",
                        "/work/data",
                        "-k",
                        "/work/socket",
                        "-c",
                        "listen_addresses=",
                        "-c",
                        "shared_buffers=16MB",
                        "-c",
                        "max_connections=5",
                        "-c",
                        "log_min_messages=panic",
                    ],
                )
                .unwrap(),
            None,
        )
        .unwrap();
        loop {
            deadline_check(deadline).unwrap();
            if sandbox.scalar("SELECT 1;", deadline).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        // Simulate code carried by a restored archive replacing writable
        // identity names with host-absolute symlinks. Only a synthetic marker
        // is used; no host credential or production file is accessed.
        let marker = root.join("synthetic-host-only-marker");
        fs::write(&marker, "SYNTHETIC-HOST-MARKER-MUST-NOT-BE-BOUND").unwrap();
        let attack = format!(
            "COPY (SELECT 1) TO PROGRAM 'ln -s {} /work/passwd; ln -s {} /work/group';",
            marker.display(),
            marker.display()
        );
        let client = [
            "-X",
            "-qAt",
            "-h",
            "/work/socket",
            "-U",
            "argosverify",
            "-d",
            "postgres",
            "--no-password",
        ];
        Captured::start(sandbox.command("psql", &client).unwrap(), Some(&attack))
            .unwrap()
            .finish(deadline)
            .unwrap();
        assert!(fs::symlink_metadata(sandbox.work.join("passwd"))
            .unwrap()
            .file_type()
            .is_symlink());
        // Inspect the next client's namespace after its host-side bind setup.
        // Skip the budget monitor only in this test so rejection of the
        // synthetic symlink cannot hide a wrong bind source.
        let identity = Captured::start(
            sandbox
                .command(
                    "psql",
                    &[
                        "-X",
                        "-qAt",
                        "-h",
                        "/work/socket",
                        "-U",
                        "argosverify",
                        "-d",
                        "postgres",
                        "-c",
                        "\\! /bin/cat /etc/passwd /etc/group",
                    ],
                )
                .unwrap(),
            None,
        )
        .unwrap()
        .finish(deadline)
        .unwrap();
        let identity = String::from_utf8(identity).unwrap();
        assert!(identity.starts_with("argos:x:"));
        assert!(!identity.contains("SYNTHETIC-HOST-MARKER"));
        assert_eq!(
            workspace_budget(&fixture, plan.max_workspace_bytes, deadline)
                .unwrap_err()
                .code,
            "workspace_symlink_not_allowed"
        );
        fs::remove_file(sandbox.work.join("passwd")).unwrap();
        fs::remove_file(sandbox.work.join("group")).unwrap();
        sandbox.query("CREATE TABLE public.orders(id bigint PRIMARY KEY,secret text NOT NULL); INSERT INTO public.orders VALUES(1,'PRIVATE-PG-ROW'),(2,'another');",deadline).unwrap();
        sandbox
            .exec(
                "pg_dump",
                &[
                    "--format=custom",
                    "--file=/work/fixture.dump",
                    "--host=/work/socket",
                    "--username=argosverify",
                    "--dbname=postgres",
                    "--no-password",
                ],
                None,
                deadline,
            )
            .unwrap();
        fs::copy(sandbox.work.join("fixture.dump"), &plan.backup_path).unwrap();
        drop(server);
        let report = super::super::run(&plan, &root.join("drill")).unwrap();
        assert_eq!(report.status, "passed", "{report:?}");
        assert_eq!(report.rpo_ms, None);
        assert!(report
            .checks
            .iter()
            .any(|c| c.check_id == "argos-write-read-rollback" && c.passed));
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("PRIVATE-PG-ROW"));
        assert!(
            !root.join("drill/postgresql/socket/.s.PGSQL.5432").exists()
                || std::os::unix::net::UnixStream::connect(
                    root.join("drill/postgresql/socket/.s.PGSQL.5432")
                )
                .is_err()
        );
        plan.tables[0].min_rows = 3;
        let failed = super::super::run(&plan, &root.join("missing-rows")).unwrap();
        assert_eq!(
            failed.failure_code.as_deref(),
            Some("postgresql_row_expectation_failed")
        );
        // Keep this opt-in fixture for CLI integration tests only when requested.
        if std::env::var_os("ARGOS_KEEP_SERVICE_FIXTURE").is_some() {
            println!("fixture={}", root.display());
        } else {
            fs::remove_dir_all(&root).unwrap();
        }
    }
}
