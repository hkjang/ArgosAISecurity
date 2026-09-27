use super::*;
use crate::quota::{AgentCapacityLimit, CapacityUsage, WriterLock};
use std::{net::TcpListener, sync::mpsc, thread};

struct HttpServer {
    endpoint: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl HttpServer {
    fn start(application: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let (ready, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    ready.send(()).unwrap();
                    axum::serve(listener, application)
                        .with_graceful_shutdown(async move {
                            let _ = shutdown.await;
                        })
                        .await
                        .unwrap();
                });
        });
        rx.recv().unwrap();
        Self {
            endpoint,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
    fn post(
        &self,
        config: &ServerConfig,
        agent: &str,
        bytes: &[u8],
    ) -> reqwest::blocking::Response {
        reqwest::blocking::Client::new()
            .post(format!("{}/v1/objects/{}", self.endpoint, sha256(bytes)))
            .bearer_auth(&config.agent_tokens[agent])
            .header("X-Argos-Kind", "audit")
            .body(bytes.to_vec())
            .send()
            .unwrap()
    }
    fn usage(&self, config: &ServerConfig) -> CapacityUsage {
        reqwest::blocking::Client::new()
            .get(format!("{}/v1/usage", self.endpoint))
            .bearer_auth(&config.admin_token)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .unwrap()
    }
    fn body(&self, config: &ServerConfig, agent: &str, bytes: &[u8]) -> Vec<u8> {
        reqwest::blocking::Client::new()
            .get(format!(
                "{}/v1/objects/{}/{}",
                self.endpoint,
                agent,
                sha256(bytes)
            ))
            .bearer_auth(&config.admin_token)
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .bytes()
            .unwrap()
            .to_vec()
    }
}
impl Drop for HttpServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
struct Fixture {
    directory: PathBuf,
    config: ServerConfig,
}
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let directory = std::env::temp_dir().join(format!(
            "argos-vault-capacity-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let storage = directory.join("store");
        fs::DirBuilder::new().mode(0o700).create(&storage).unwrap();
        let key_path = directory.join("key");
        generate_signing_key_file(&key_path).unwrap();
        let mut config = ServerConfig {
            dir: storage,
            signing_key_file: key_path,
            admin_token: "capacity-admin-token-0123456".into(),
            agent_tokens: BTreeMap::from([
                ("host-a".into(), "capacity-agent-a-0123456".into()),
                ("host-b".into(), "capacity-agent-b-0123456".into()),
            ]),
            ..Default::default()
        };
        config.capacity.min_free_bytes = 0;
        Self { directory, config }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn quota_http_limits_idempotency_fetch_usage_auth_and_restart_reconstruction() {
    let mut fixture = Fixture::new();
    fixture.config.capacity.global_max_bytes = 6;
    fixture.config.capacity.global_max_objects = 2;
    fixture.config.capacity.agent_max_objects = 1;
    fixture.config.capacity.agent_overrides.insert(
        "host-a".into(),
        AgentCapacityLimit {
            max_bytes: 3,
            max_objects: 1,
        },
    );
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    let first = server
        .post(&fixture.config, "host-a", b"abc")
        .error_for_status()
        .unwrap()
        .json::<SignedReceipt>()
        .unwrap();
    assert_eq!(
        server
            .post(&fixture.config, "host-a", b"de")
            .status()
            .as_u16(),
        507
    );
    assert_eq!(
        server
            .post(&fixture.config, "host-a", b"abc")
            .json::<SignedReceipt>()
            .unwrap(),
        first
    );
    assert!(server
        .post(&fixture.config, "host-b", b"def")
        .status()
        .is_success());
    assert_eq!(
        server
            .post(&fixture.config, "host-b", b"g")
            .status()
            .as_u16(),
        507
    );
    let usage = server.usage(&fixture.config);
    assert_eq!(usage.total.logical_bytes, 6);
    assert_eq!(usage.total.objects, 2);
    assert_eq!(usage.total.receipted_objects, 2);
    assert_eq!(usage.agents["host-a"].usage.objects, 1);
    assert_eq!(usage.admission_rejections, 2);
    assert!(usage.new_uploads_blocked);
    assert!(usage.filesystem.supported && usage.filesystem.available_bytes.is_some());
    for token in ["", fixture.config.agent_tokens["host-a"].as_str()] {
        assert_eq!(
            reqwest::blocking::Client::new()
                .get(format!("{}/v1/usage", server.endpoint))
                .bearer_auth(token)
                .send()
                .unwrap()
                .status()
                .as_u16(),
            401
        );
    }
    assert_eq!(server.body(&fixture.config, "host-a", b"abc"), b"abc");
    drop(server);
    // 낮춘 한도를 이미 초과해도 기동·정상 객체 조회·동일 객체 재전송은 유지한다.
    fixture.config.capacity.global_max_bytes = 1;
    fixture.config.capacity.global_max_objects = 1;
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    let rebuilt = server.usage(&fixture.config);
    assert!(rebuilt.reconstruction_complete && rebuilt.storage_consistent);
    assert_eq!(rebuilt.total.logical_bytes, 6);
    assert_eq!(rebuilt.total.objects, 2);
    assert_eq!(rebuilt.admission_rejections, 0);
    assert_eq!(
        server
            .post(&fixture.config, "host-a", b"abc")
            .json::<SignedReceipt>()
            .unwrap(),
        first
    );
    assert_eq!(server.body(&fixture.config, "host-b", b"def"), b"def");
    assert_eq!(
        server
            .post(&fixture.config, "host-a", b"new")
            .status()
            .as_u16(),
        507
    );
}

#[test]
fn independent_byte_limits_reject_before_object_count_is_reached() {
    let mut fixture = Fixture::new();
    fixture.config.capacity.global_max_bytes = 5;
    fixture.config.capacity.agent_max_bytes = 3;
    fixture.config.capacity.global_max_objects = 10;
    fixture.config.capacity.agent_max_objects = 10;
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    // 전역에는 들어가지만 에이전트 바이트 한도를 넘는다.
    assert_eq!(
        server
            .post(&fixture.config, "host-a", b"abcd")
            .status()
            .as_u16(),
        507
    );
    assert_eq!(server.usage(&fixture.config).total.objects, 0);
    assert!(server
        .post(&fixture.config, "host-a", b"abc")
        .status()
        .is_success());
    assert!(server
        .post(&fixture.config, "host-b", b"de")
        .status()
        .is_success());
    // host-b는 3바이트가 되어 개별 한도에는 들어가지만 전역 5바이트를 넘는다.
    assert_eq!(
        server
            .post(&fixture.config, "host-b", b"f")
            .status()
            .as_u16(),
        507
    );
    let usage = server.usage(&fixture.config);
    assert_eq!(usage.total.logical_bytes, 5);
    assert_eq!(usage.total.objects, 2);
    assert_eq!(usage.admission_rejections, 2);
}

#[test]
fn failed_publication_keeps_reservation_and_reads_until_restart_reconstruction() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let fixture = Fixture::new();
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    assert!(server
        .post(&fixture.config, "host-a", b"kept")
        .status()
        .is_success());
    // 기동 후 별도 에이전트 디렉터리가 안전하지 않은 권한으로 생성된 저장 오류.
    let broken = fixture.config.dir.join("host-b");
    fs::DirBuilder::new().mode(0o755).create(&broken).unwrap();
    fs::set_permissions(&broken, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        server
            .post(&fixture.config, "host-b", b"lost")
            .status()
            .as_u16(),
        409
    );
    let usage = server.usage(&fixture.config);
    assert!(!usage.storage_consistent && usage.new_uploads_blocked);
    assert_eq!(usage.total.logical_bytes, 8);
    assert_eq!(usage.total.objects, 2);
    assert_eq!(usage.total.receipted_objects, 1);
    assert!(usage
        .reasons
        .iter()
        .any(|reason| reason == "publish_failed_restart_required"));
    assert_eq!(
        server
            .post(&fixture.config, "host-a", b"new")
            .status()
            .as_u16(),
        507
    );
    assert_eq!(server.body(&fixture.config, "host-a", b"kept"), b"kept");
    assert!(server
        .post(&fixture.config, "host-a", b"kept")
        .status()
        .is_success());
    assert_eq!(fs::read_dir(&broken).unwrap().count(), 0);
    drop(server);
    // 오류 원인을 고치고 재검사한 뒤에만 미게시 예약이 실제 디스크 계수로 대체된다.
    fs::set_permissions(&broken, fs::Permissions::from_mode(0o700)).unwrap();
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    let rebuilt = server.usage(&fixture.config);
    assert!(rebuilt.reconstruction_complete && rebuilt.storage_consistent);
    assert_eq!(rebuilt.total.logical_bytes, 4);
    assert_eq!(rebuilt.total.objects, 1);
    assert_eq!(rebuilt.agents["host-b"].usage.objects, 0);
    assert!(server
        .post(&fixture.config, "host-b", b"new")
        .status()
        .is_success());
}

#[test]
fn concurrent_http_uploads_cannot_exceed_global_object_reservation() {
    let mut fixture = Fixture::new();
    fixture.config.capacity.global_max_objects = 1;
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let handles: Vec<_> = [b"one".to_vec(), b"two".to_vec()]
        .into_iter()
        .map(|body| {
            let endpoint = server.endpoint.clone();
            let token = fixture.config.agent_tokens["host-a"].clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let client = reqwest::blocking::Client::new();
                barrier.wait();
                client
                    .post(format!("{endpoint}/v1/objects/{}", sha256(&body)))
                    .bearer_auth(token)
                    .header("X-Argos-Kind", "audit")
                    .body(body)
                    .send()
                    .unwrap()
                    .status()
                    .as_u16()
            })
        })
        .collect();
    barrier.wait();
    let mut status: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    status.sort();
    assert_eq!(status, vec![200, 507]);
    assert_eq!(server.usage(&fixture.config).total.objects, 1);
    assert_eq!(
        fs::read_dir(fixture.config.dir.join("host-a"))
            .unwrap()
            .count(),
        2
    );
}

#[test]
fn free_space_floor_blocks_only_new_uploads_and_usage_explains_the_cause() {
    let mut fixture = Fixture::new();
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    assert!(server
        .post(&fixture.config, "host-a", b"kept")
        .status()
        .is_success());
    drop(server);
    fixture.config.capacity.min_free_bytes = u64::MAX;
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    assert!(server
        .post(&fixture.config, "host-a", b"kept")
        .status()
        .is_success());
    assert_eq!(server.body(&fixture.config, "host-a", b"kept"), b"kept");
    assert_eq!(
        server
            .post(&fixture.config, "host-a", b"new")
            .status()
            .as_u16(),
        507
    );
    let usage = server.usage(&fixture.config);
    assert!(usage.new_uploads_blocked);
    assert!(usage
        .reasons
        .iter()
        .any(|code| code == "filesystem_free_floor_or_unavailable"));
    assert_eq!(usage.total.objects, 1);
}

#[test]
fn partial_or_temporary_files_stop_new_writes_but_leave_verified_reads_available() {
    let fixture = Fixture::new();
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    assert!(server
        .post(&fixture.config, "host-a", b"kept")
        .status()
        .is_success());
    drop(server);
    let orphan = fixture
        .config
        .dir
        .join("host-a")
        .join(format!("{}.blob", sha256(b"orphan")));
    write_new(&orphan, b"orphan").unwrap();
    let temporary = fixture.config.dir.join("host-a/.argos-vault-stale.tmp");
    write_new(&temporary, b"incomplete").unwrap();
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    let usage = server.usage(&fixture.config);
    assert!(!usage.storage_consistent && usage.new_uploads_blocked);
    assert_eq!(usage.total.objects, 2);
    assert_eq!(usage.total.logical_bytes, 10);
    assert_eq!(usage.total.receipted_objects, 1);
    assert_eq!(
        server
            .post(&fixture.config, "host-a", b"new")
            .status()
            .as_u16(),
        507
    );
    assert_eq!(server.body(&fixture.config, "host-a", b"kept"), b"kept");
    assert!(server
        .post(&fixture.config, "host-a", b"kept")
        .status()
        .is_success());
    assert!(orphan.exists() && temporary.exists());
}

#[test]
fn startup_scan_bound_and_receipt_tamper_fail_closed_without_deleting_objects() {
    let mut fixture = Fixture::new();
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    assert!(server
        .post(&fixture.config, "host-a", b"first")
        .status()
        .is_success());
    assert!(server
        .post(&fixture.config, "host-a", b"second")
        .status()
        .is_success());
    drop(server);
    fixture.config.capacity.max_scan_entries = 1;
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    let usage = server.usage(&fixture.config);
    assert!(!usage.reconstruction_complete && usage.new_uploads_blocked);
    assert_eq!(
        server
            .post(&fixture.config, "host-a", b"new")
            .status()
            .as_u16(),
        507
    );
    assert_eq!(server.body(&fixture.config, "host-a", b"first"), b"first");
    drop(server);
    fixture.config.capacity.max_scan_entries = 100;
    let path = fixture
        .config
        .dir
        .join("host-a")
        .join(format!("{}.receipt.json", sha256(b"second")));
    let mut receipt = read_receipt(&path).unwrap();
    receipt.receipt.agent_id = "host-b".into();
    fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    let usage = server.usage(&fixture.config);
    assert!(usage.reconstruction_complete);
    assert!(!usage.storage_consistent);
    assert_eq!(usage.total.objects, 2);
    assert_eq!(usage.total.receipted_objects, 1);
    assert_eq!(server.body(&fixture.config, "host-a", b"first"), b"first");
    assert_eq!(
        server
            .post(&fixture.config, "host-a", b"new")
            .status()
            .as_u16(),
        507
    );
    drop(server);
    // 유효한 서명이어도 경로와 에이전트가 다르면 재구성을 신뢰하지 않는다.
    let key = load_key(&fixture.config.signing_key_file).unwrap();
    let receipt = sign(receipt.receipt, &key).unwrap();
    fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    let usage = server.usage(&fixture.config);
    assert!(!usage.storage_consistent && usage.new_uploads_blocked);
    assert_eq!(usage.total.receipted_objects, 1);
    assert_eq!(server.body(&fixture.config, "host-a", b"first"), b"first");
}

#[test]
fn second_writer_process_is_rejected_until_owner_releases_lock() {
    let fixture = Fixture::new();
    let application = router(fixture.config.clone()).unwrap();
    let run_child = |locked: bool| {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "server::quota_tests::lock_probe_child",
                "--nocapture",
            ])
            .env("ARGOS_VAULT_LOCK_PROBE", &fixture.config.dir)
            .env(
                "ARGOS_VAULT_LOCK_EXPECTED",
                if locked { "locked" } else { "free" },
            )
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
    };
    run_child(true);
    assert!(router(fixture.config.clone()).is_err());
    drop(application);
    run_child(false);
    assert!(router(fixture.config.clone()).is_ok());
}

#[test]
fn lock_probe_child() {
    let Some(path) = std::env::var_os("ARGOS_VAULT_LOCK_PROBE") else {
        return;
    };
    let lock = WriterLock::acquire(Path::new(&path));
    assert_eq!(
        lock.is_err(),
        std::env::var("ARGOS_VAULT_LOCK_EXPECTED").unwrap() == "locked"
    );
}

#[test]
fn normal_uploads_preserve_a_separate_physical_revocation_cushion() {
    let mut fixture = Fixture::new();
    // 실제 디스크를 채우지 않고 측정 가용량보다 큰 쿠션으로 admission 경계를 시험한다.
    fixture.config.capacity.revocation_reserved_free_bytes = u64::MAX;
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    assert_eq!(
        server
            .post(&fixture.config, "host-a", b"new")
            .status()
            .as_u16(),
        507
    );
    assert!(server.usage(&fixture.config).new_uploads_blocked);
    assert_eq!(server.usage(&fixture.config).total.objects, 0);
    drop(server);
    // 논리 취소 예약의 명시적 비활성화는 v0.6의 min_free=0 동작으로 돌아간다.
    fixture.config.capacity.revocation_max_objects = 0;
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    assert!(server
        .post(&fixture.config, "host-a", b"new")
        .status()
        .is_success());
    assert_eq!(server.usage(&fixture.config).normal_usage.objects, 1);
    assert_eq!(server.usage(&fixture.config).revocation_usage.objects, 0);
}
