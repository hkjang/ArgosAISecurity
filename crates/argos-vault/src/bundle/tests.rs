use super::*;
use rand_core::{OsRng, RngCore};
use rusqlite::Connection;
use std::{net::TcpListener, path::PathBuf, sync::mpsc, thread};

struct Server {
    endpoint: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn start(config: ServerConfig) -> Self {
        let router = router(config).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (stop, rx) = tokio::sync::oneshot::channel();
        let (ready, wait) = mpsc::channel();
        let thread = thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    ready.send(()).unwrap();
                    axum::serve(listener, router)
                        .with_graceful_shutdown(async move {
                            let _ = rx.await;
                        })
                        .await
                        .unwrap();
                })
        });
        wait.recv().unwrap();
        Self {
            endpoint,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}
impl Drop for Server {
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
    root: PathBuf,
    server: ServerConfig,
    pubkey: String,
}
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let root = std::env::temp_dir().join(format!("argos-bundle-{}", hex::encode(random)));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let store = root.join("store");
        fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
        let key = root.join("key");
        let pubkey = generate_signing_key_file(&key).unwrap();
        let mut server = ServerConfig {
            dir: store,
            signing_key_file: key,
            admin_token: "administrator-token-unique".into(),
            ..Default::default()
        };
        server
            .agent_tokens
            .insert("agent-a".into(), "upload-agent-a-token".into());
        server
            .agent_tokens
            .insert("agent-b".into(), "upload-agent-b-token".into());
        server.capacity.min_free_bytes = 0;
        Self {
            root,
            server,
            pubkey,
        }
    }
    fn config(&self, server: &Server) -> VaultConfig {
        VaultConfig {
            endpoint: server.endpoint.clone(),
            agent_id: "agent-a".into(),
            upload_token: self.server.agent_tokens["agent-a"].clone(),
            admin_token: self.server.admin_token.clone(),
            pinned_pubkey: self.pubkey.clone(),
            allow_http_loopback: true,
            ..Default::default()
        }
    }
    fn prepare(&self, name: &str, bytes: &[u8]) -> (PathBuf, BundleManifest) {
        let source = self.root.join(format!("{name}.src"));
        write_new(&source, bytes).unwrap();
        let stage = self.root.join(name);
        let manifest = prepare(
            &source,
            &stage,
            BundleMetadata {
                original_path: "/original-host/orders.sqlite3".into(),
                version: Some(42),
                review_history: serde_json::json!({"claimed":"known_good"}),
                recovery_plan: Some("engine = \"sqlite\"\n".into()),
            },
        )
        .unwrap();
        fs::remove_file(source).unwrap();
        (stage, manifest)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn decision(id: &str, value: ReviewDecision) -> ReviewRequest {
    ReviewRequest {
        request_id: id.into(),
        decision: value,
        actor: "admin-reviewer".into(),
        reason: "독립 검토 근거".into(),
    }
}

#[test]
fn original_host_absent_unknown_good_revoked_and_atomic_reassembly() {
    let fixture = Fixture::new();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    let (stage, manifest) = fixture.prepare("stage", b"native backup bytes");
    let record = upload_prepared(&config, &stage).unwrap();
    assert!(record.completion.is_some());
    assert_eq!(record.current_review, "unknown");
    assert!(!record.recommended);
    fs::remove_dir_all(&stage).unwrap(); // 원본/준비/로컬 DB 없이 원격만 사용
    let destination = fixture.root.join("restored");
    assert!(fetch(&config, "agent-a", &manifest.bundle_id, &destination, false).is_err());
    assert!(!destination.exists());
    let approved = review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("approve-1", ReviewDecision::Good),
    )
    .unwrap();
    assert!(approved.recommended);
    let again = review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("approve-1", ReviewDecision::Good),
    )
    .unwrap();
    assert_eq!(again.reviews.len(), 1);
    fetch(&config, "agent-a", &manifest.bundle_id, &destination, false).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"native backup bytes");
    assert!(fetch(&config, "agent-a", &manifest.bundle_id, &destination, false).is_err());
    let revoked = review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("revoke-1", ReviewDecision::Revoked),
    )
    .unwrap();
    assert_eq!(revoked.current_review, "revoked");
    assert_eq!(revoked.reviews.len(), 2);
    assert!(!revoked.recommended);
    assert!(fetch(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &fixture.root.join("blocked"),
        false
    )
    .is_err());
    fetch(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &fixture.root.join("evidence"),
        true,
    )
    .unwrap();
    let mut forged = revoked;
    forged.reviews[0].value.request.reason = "forged".into();
    assert!(verify_record(&forged, &config.pinned_pubkey, &config.key_id).is_err());
}

#[test]
fn incomplete_missing_tampered_chunks_and_manifest_changes_are_rejected() {
    let fixture = Fixture::new();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    let (stage, manifest) = fixture.prepare("partial", b"original bytes");
    register_manifest(&config, &manifest).unwrap();
    assert!(complete(&config, &manifest.bundle_id).is_err());
    assert!(review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("early", ReviewDecision::Good)
    )
    .is_err());
    assert!(
        !get(&config, "agent-a", &manifest.bundle_id)
            .unwrap()
            .recommended
    );
    let mut changed = manifest.clone();
    changed.metadata.version = Some(99);
    assert!(register_manifest(&config, &changed).is_err());
    fs::write(
        stage
            .join("chunks")
            .join(format!("{}.bin", manifest.chunks[0].sha256)),
        b"tampered",
    )
    .unwrap();
    assert!(upload_prepared(&config, &stage).is_err());
    let (_, mut wrong) = fixture.prepare("wrong-full", b"otherwise valid chunk");
    wrong.sha256 = "0".repeat(64);
    register_manifest(&config, &wrong).unwrap();
    let chunk = fixture
        .root
        .join("wrong-full/chunks")
        .join(format!("{}.bin", wrong.chunks[0].sha256));
    upload_file(&config, &chunk, "backup").unwrap();
    assert!(complete(&config, &wrong.bundle_id).is_err());
    let usage = fetch_usage(&config).unwrap();
    assert_eq!(usage.total.objects, 3); // 두 manifest도 계수
}

#[test]
fn catalog_loss_and_truncated_latest_revocation_never_expose_old_good() {
    let fixture = Fixture::new();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    let (stage, manifest) = fixture.prepare("good", b"bytes");
    upload_prepared(&config, &stage).unwrap();
    review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("good", ReviewDecision::Good),
    )
    .unwrap();
    review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("revoke", ReviewDecision::Revoked),
    )
    .unwrap();
    let db = fixture.server.dir.join(".argos-bundles.sqlite3");
    Connection::open(&db)
        .unwrap()
        .execute("DELETE FROM reviews WHERE sequence=2", [])
        .unwrap();
    assert!(get(&config, "agent-a", &manifest.bundle_id).is_err());
    assert!(list(&config, "agent-a", None, 20).is_err());
    drop(server);
    fs::remove_file(&db).unwrap();
    fs::remove_file(fixture.server.dir.join(".argos-bundles.ready")).unwrap();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    assert!(get(&config, "agent-a", &manifest.bundle_id).is_err());
    assert!(register_manifest(&config, &manifest).is_err());
    assert!(!db.exists());
}

#[test]
fn completion_and_review_quota_failures_leave_current_state_unchanged() {
    let mut fixture = Fixture::new();
    fixture.server.capacity.global_max_objects = 2;
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    let (stage, manifest) = fixture.prepare("quota", b"bytes");
    assert!(upload_prepared(&config, &stage).is_err());
    let record = get(&config, "agent-a", &manifest.bundle_id).unwrap();
    assert!(record.completion.is_none());
    assert_eq!(fetch_usage(&config).unwrap().total.objects, 2);
    drop(server);
    fixture.server.capacity.global_max_objects = 4;
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    complete(&config, &manifest.bundle_id).unwrap();
    review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("good", ReviewDecision::Good),
    )
    .unwrap();
    assert!(review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("revoke", ReviewDecision::Revoked)
    )
    .is_err());
    assert!(get(&config, "agent-a", &manifest.bundle_id).is_err()); // 대기 중 취소가 있으면 과거 good를 추천하지 않는다.
    drop(server);
    fixture.server.capacity.global_max_objects = 5;
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    assert_eq!(
        review(
            &config,
            "agent-a",
            &manifest.bundle_id,
            &decision("revoke", ReviewDecision::Revoked)
        )
        .unwrap()
        .current_review,
        "revoked"
    );
}

#[test]
fn roles_pagination_and_internal_control_kind_are_enforced() {
    let fixture = Fixture::new();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    for name in ["a", "b", "c"] {
        let (_, manifest) = fixture.prepare(name, name.as_bytes());
        register_manifest(&config, &manifest).unwrap();
    }
    let first = list(&config, "agent-a", None, 2).unwrap();
    assert_eq!(first.items.len(), 2);
    let second = list(&config, "agent-a", first.next_cursor.as_deref(), 2).unwrap();
    assert_eq!(second.items.len(), 1);
    assert!(second.next_cursor.is_none());
    assert!(list(&config, "agent-a", None, 101).is_err());
    let mut wrong = config.clone();
    wrong.admin_token = wrong.upload_token.clone();
    assert!(list(&wrong, "agent-a", None, 20).is_err());
    assert!(review(
        &wrong,
        "agent-a",
        &first.items[0].bundle_id,
        &decision("bad", ReviewDecision::Good)
    )
    .is_err());
    wrong = config.clone();
    wrong.upload_token = wrong.admin_token.clone();
    let (_, manifest) = fixture.prepare("d", b"d");
    assert!(register_manifest(&wrong, &manifest).is_err());
    assert!(list(&config, "agent-b", None, 20).unwrap().items.is_empty());
    let response = reqwest::blocking::Client::new()
        .post(format!(
            "{}/v1/objects/{}",
            server.endpoint,
            sha256(b"fake")
        ))
        .bearer_auth(&config.upload_token)
        .header("X-Argos-Kind", "bundle-review")
        .body("fake")
        .send()
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
}

#[test]
fn sixteen_mebibyte_streaming_chunks_preserve_order_and_duplicates() {
    let fixture = Fixture::new();
    let data = vec![7u8; CHUNK_BYTES * 2 + 3];
    let (stage, manifest) = fixture.prepare("chunked", &data);
    assert_eq!(manifest.chunks.len(), 3);
    assert_eq!(manifest.chunks[0], manifest.chunks[1]);
    assert_eq!(manifest.chunks[2].size_bytes, 3);
    assert_eq!(manifest.sha256, sha256(&data));
    assert_eq!(fs::read_dir(stage.join("chunks")).unwrap().count(), 2);
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    upload_prepared(&config, &stage).unwrap();
    review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("good", ReviewDecision::Good),
    )
    .unwrap();
    let destination = fixture.root.join("streamed");
    fetch(&config, "agent-a", &manifest.bundle_id, &destination, false).unwrap();
    assert_eq!(sha256(&fs::read(destination).unwrap()), manifest.sha256);
}

#[test]
fn publication_interruption_resumes_same_signed_bytes_without_false_completion() {
    let fixture = Fixture::new();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    let (stage, manifest) = fixture.prepare("interrupted", b"stable chunk");
    register_manifest(&config, &manifest).unwrap();
    upload_file(
        &config,
        &stage
            .join("chunks")
            .join(format!("{}.bin", manifest.chunks[0].sha256)),
        "backup",
    )
    .unwrap();
    let db = fixture.server.dir.join(".argos-bundles.sqlite3");
    Connection::open(&db).unwrap().execute_batch("CREATE TRIGGER fail_complete BEFORE UPDATE OF completion_hash ON bundles BEGIN SELECT RAISE(FAIL,'interrupted'); END;").unwrap();
    assert!(complete(&config, &manifest.bundle_id).is_err());
    assert!(get(&config, "agent-a", &manifest.bundle_id).is_err());
    let count = fetch_usage(&config).unwrap().total.objects;
    Connection::open(&db)
        .unwrap()
        .execute_batch("DROP TRIGGER fail_complete;")
        .unwrap();
    // publish도 register→complete 순서라 동일 등록 재시도로 중단된 완료를 마친다.
    assert!(register_manifest(&config, &manifest)
        .unwrap()
        .completion
        .is_some());
    assert_eq!(fetch_usage(&config).unwrap().total.objects, count);
    Connection::open(&db).unwrap().execute_batch("CREATE TRIGGER fail_review BEFORE INSERT ON reviews BEGIN SELECT RAISE(FAIL,'interrupted'); END;").unwrap();
    let request = decision("good-after-interrupt", ReviewDecision::Good);
    assert!(review(&config, "agent-a", &manifest.bundle_id, &request).is_err());
    assert!(get(&config, "agent-a", &manifest.bundle_id).is_err());
    let count = fetch_usage(&config).unwrap().total.objects;
    Connection::open(&db)
        .unwrap()
        .execute_batch("DROP TRIGGER fail_review;")
        .unwrap();
    assert!(
        review(&config, "agent-a", &manifest.bundle_id, &request)
            .unwrap()
            .recommended
    );
    assert_eq!(fetch_usage(&config).unwrap().total.objects, count);
}

#[test]
fn corrupted_remote_chunk_never_publishes_destination() {
    let fixture = Fixture::new();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    let (stage, manifest) = fixture.prepare("corrupt-remote", b"original server object");
    upload_prepared(&config, &stage).unwrap();
    review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("good", ReviewDecision::Good),
    )
    .unwrap();
    fs::write(
        fixture
            .server
            .dir
            .join("agent-a")
            .join(format!("{}.blob", manifest.chunks[0].sha256)),
        b"corrupt",
    )
    .unwrap();
    let destination = fixture.root.join("must-not-exist");
    assert!(fetch(&config, "agent-a", &manifest.bundle_id, &destination, false).is_err());
    assert!(!destination.exists());
    assert!(!fs::read_dir(&fixture.root).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".argos-bundle-")));
}

#[test]
fn final_review_slot_is_reserved_for_revocation() {
    let fixture = Fixture::new();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    let (stage, manifest) = fixture.prepare("review-cap", b"bytes");
    let record = upload_prepared(&config, &stage).unwrap();
    drop(server);
    // 유효한 99개 검토 fixture를 디스크에 보존하고 실제 서버가 재구성하도록 한다.
    let key = load_key(&fixture.server.signing_key_file).unwrap();
    let completion_hash = sha256(&serde_json::to_vec(record.completion.as_ref().unwrap()).unwrap());
    let conn = Connection::open(fixture.server.dir.join(".argos-bundles.sqlite3")).unwrap();
    let mut previous = None;
    for sequence in 1..100u32 {
        let event = sign_value(
            ReviewEvent {
                format: "argos-bundle-review-v1".into(),
                key_id: config.key_id.clone(),
                agent_id: "agent-a".into(),
                bundle_id: manifest.bundle_id.clone(),
                manifest_sha256: record.manifest_receipt.receipt.sha256.clone(),
                completion_sha256: completion_hash.clone(),
                sequence,
                previous_sha256: previous,
                reviewed_at_ms: now_ms(),
                request: decision(&format!("cap-{sequence}"), ReviewDecision::Good),
            },
            &key,
        )
        .unwrap();
        let bytes = serde_json::to_vec(&event).unwrap();
        let hash = sha256(&bytes);
        let now = now_ms();
        let receipt = sign(
            Receipt {
                format: FORMAT.into(),
                key_id: config.key_id.clone(),
                agent_id: "agent-a".into(),
                kind: "bundle-review".into(),
                sha256: hash.clone(),
                size_bytes: bytes.len() as u64,
                received_at_ms: now,
                retention_until_ms: now + 86400000,
            },
            &key,
        )
        .unwrap();
        let directory = fixture.server.dir.join("agent-a");
        write_new(&directory.join(format!("{hash}.blob")), &bytes).unwrap();
        write_receipt_new(&directory.join(format!("{hash}.receipt.json")), &receipt).unwrap();
        conn.execute("INSERT INTO reviews(agent,bundle,sequence,hash,request_id) VALUES('agent-a',?1,?2,?3,?4)",rusqlite::params![manifest.bundle_id,sequence,hash,event.value.request.request_id]).unwrap();
        previous = Some(hash);
    }
    drop(conn);
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server);
    assert!(review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("forbidden-100-good", ReviewDecision::Good)
    )
    .is_err());
    let revoked = review(
        &config,
        "agent-a",
        &manifest.bundle_id,
        &decision("allowed-100-revoke", ReviewDecision::Revoked),
    )
    .unwrap();
    assert_eq!(revoked.reviews.len(), 100);
    assert!(!revoked.recommended);
    assert_eq!(revoked.current_review, "revoked");
}
