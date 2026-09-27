use super::*;
use crate::{generate_signing_key_file, router, ServerConfig};
use std::{net::TcpListener, sync::mpsc, thread};
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
        let root = std::env::temp_dir().join(format!("argos-job-{}", random_id().unwrap()));
        make_directory(&root).unwrap();
        let dir = root.join("store");
        make_directory(&dir).unwrap();
        let key = root.join("key");
        let pubkey = generate_signing_key_file(&key).unwrap();
        let mut server = ServerConfig {
            dir,
            signing_key_file: key,
            admin_token: "administrator-job-token-unique".into(),
            ..Default::default()
        };
        server
            .agent_tokens
            .insert("agent-job".into(), "upload-job-token-unique".into());
        server.capacity.min_free_bytes = 0;
        Self {
            root,
            server,
            pubkey,
        }
    }
    fn config(&self, endpoint: &str) -> VaultConfig {
        VaultConfig {
            endpoint: endpoint.into(),
            agent_id: "agent-job".into(),
            upload_token: self.server.agent_tokens["agent-job"].clone(),
            admin_token: self.server.admin_token.clone(),
            pinned_pubkey: self.pubkey.clone(),
            allow_http_loopback: true,
            timeout_secs: 1,
            ..Default::default()
        }
    }
    fn queue(&self) -> PathBuf {
        self.root.join("queue")
    }
    fn stage(&self, name: &str, data: &[u8]) -> (PathBuf, BundleManifest) {
        let source = self.root.join(format!("{name}.src"));
        write_new(&source, data).unwrap();
        let stage = self.root.join(name);
        let manifest = bundle::prepare(
            &source,
            &stage,
            bundle::BundleMetadata {
                original_path: "/original/orders.backup".into(),
                version: Some(1),
                review_history: serde_json::json!({"source_claim":"good"}),
                recovery_plan: None,
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
fn ready(fixture: &Fixture, config: &VaultConfig) -> BundleJob {
    let (stage, manifest) = fixture.stage("stage", b"fixed native-backup bytes");
    enqueue_bundle(&fixture.queue(), config, &stage, &QueueLimits::default()).unwrap();
    fs::remove_dir_all(stage).unwrap();
    let sent = drain_once(&fixture.queue(), config, &DrainOptions { max_items: 1 }).unwrap();
    assert_eq!(sent.sent, 1);
    assert_eq!(sent.remaining_jobs, 1);
    bundle_job(&fixture.queue(), &manifest.bundle_id).unwrap()
}
#[test]
fn stage_deleted_job_resumes_each_persistent_phase_and_never_marks_good() {
    let fixture = Fixture::new();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server.endpoint);
    let job = ready(&fixture, &config);
    assert_eq!(job.phase, "register");
    assert_eq!(job.state, "pending");
    let registered = drain_once(&fixture.queue(), &config, &DrainOptions { max_items: 1 }).unwrap();
    assert_eq!(registered.attempted, 0);
    assert_eq!(registered.attempted_jobs, 1);
    assert_eq!(registered.completed_jobs, 0);
    let middle = bundle_job(&fixture.queue(), &job.bundle_id).unwrap();
    assert_eq!(middle.phase, "complete");
    assert!(middle.manifest_receipt.is_some());
    assert!(middle.completion.is_none());
    let completed = drain_once(&fixture.queue(), &config, &DrainOptions { max_items: 1 }).unwrap();
    assert_eq!(completed.completed_jobs, 1);
    assert_eq!(completed.remaining_jobs, 0);
    let done = bundle_job(&fixture.queue(), &job.bundle_id).unwrap();
    assert_eq!(done.state, "complete");
    assert!(!done.recommended);
    assert!(done.completion.is_some());
    let remote = bundle::get(&config, &config.agent_id, &job.bundle_id).unwrap();
    assert_eq!(remote.current_review, "unknown");
    assert!(!remote.recommended);
    assert_eq!(remote.manifest, job.manifest);
    let status = status(&fixture.queue()).unwrap();
    assert_eq!(status.bundle_jobs.complete, 1);
    assert_eq!(status.pending_items, 0);
}
#[test]
fn signed_ack_lost_after_remote_complete_is_idempotent_after_lease_expiry() {
    let fixture = Fixture::new();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server.endpoint);
    let job = ready(&fixture, &config);
    drain_once(&fixture.queue(), &config, &DrainOptions { max_items: 1 }).unwrap();
    let target = QueueTarget::from_config(&config).unwrap();
    let stale = claim_job(&fixture.queue(), &target, 1, crate::now_ms())
        .unwrap()
        .unwrap();
    let remote = bundle::complete(&config, &job.bundle_id).unwrap(); // 원격 저장 후 로컬 ACK 처리 전 종료
    assert_eq!(
        bundle_job(&fixture.queue(), &job.bundle_id).unwrap().state,
        "pending"
    );
    let expired = stale.job.created_at_ms + 100_000;
    let next = claim_job(&fixture.queue(), &target, 1, expired)
        .unwrap()
        .unwrap();
    assert_ne!(stale.token, next.token);
    assert!(!finish_job(
        &fixture.queue(),
        &target,
        &stale,
        &Ok(remote.clone()),
        expired + 1
    )
    .unwrap());
    let replay = bundle::complete(&config, &job.bundle_id).unwrap();
    assert_eq!(remote.completion, replay.completion);
    assert!(finish_job(&fixture.queue(), &target, &next, &Ok(replay), expired + 2).unwrap());
    assert_eq!(
        bundle_job(&fixture.queue(), &job.bundle_id).unwrap().state,
        "complete"
    );
}
#[test]
fn registration_is_atomic_for_all_chunk_limits_hashes_and_id_binding() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let (stage, manifest) = fixture.stage("large", &vec![13u8; bundle::CHUNK_BYTES + 1]);
    assert!(enqueue_bundle(
        &fixture.queue(),
        &config,
        &stage,
        &QueueLimits {
            max_items: 1,
            max_bytes: 64 * 1024 * 1024
        }
    )
    .is_err());
    assert_eq!(status(&fixture.queue()).unwrap().items_total, 0);
    assert_eq!(bundle_jobs(&fixture.queue()).unwrap().total, 0);
    assert!(enqueue_bundle(
        &fixture.queue(),
        &config,
        &stage,
        &QueueLimits {
            max_items: 10,
            max_bytes: 10
        }
    )
    .is_err());
    assert_eq!(status(&fixture.queue()).unwrap().items_total, 0);
    let path = stage
        .join("chunks")
        .join(format!("{}.bin", manifest.chunks[1].sha256));
    fs::write(&path, b"bad").unwrap();
    assert!(enqueue_bundle(&fixture.queue(), &config, &stage, &QueueLimits::default()).is_err());
    assert_eq!(status(&fixture.queue()).unwrap().items_total, 0);
    fs::write(&path, [13u8]).unwrap();
    let first = enqueue_bundle(&fixture.queue(), &config, &stage, &QueueLimits::default()).unwrap();
    let again = enqueue_bundle(&fixture.queue(), &config, &stage, &QueueLimits::default()).unwrap();
    assert_eq!(first.bundle_id, again.bundle_id);
    assert_eq!(first.chunk_items, again.chunk_items);
    assert_eq!(status(&fixture.queue()).unwrap().items_total, 2);
    let mut altered = manifest.clone();
    altered.metadata.version = Some(2);
    fs::write(
        stage.join("manifest.json"),
        serde_json::to_vec(&altered).unwrap(),
    )
    .unwrap();
    assert!(enqueue_bundle(&fixture.queue(), &config, &stage, &QueueLimits::default()).is_err());
    let mut wrong = config.clone();
    wrong.key_id = "different-key".into();
    assert!(drain_once(&fixture.queue(), &wrong, &DrainOptions::default()).is_err());
    assert_eq!(
        bundle_job(&fixture.queue(), &first.bundle_id)
            .unwrap()
            .attempts,
        0
    );
}
#[test]
fn changed_full_file_hash_does_not_publish_any_job_or_queue_item() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let (stage, mut manifest) = fixture.stage("bad-hash", b"exact bytes");
    manifest.sha256 = "0".repeat(64);
    fs::write(
        stage.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    assert!(enqueue_bundle(&fixture.queue(), &config, &stage, &QueueLimits::default()).is_err());
    assert_eq!(status(&fixture.queue()).unwrap().items_total, 0);
    assert_eq!(bundle_jobs(&fixture.queue()).unwrap().total, 0);
}
fn broken_pending_snapshot_rejects_registration(remove: bool) {
    for existing_job in [false, true] {
        let fixture = Fixture::new();
        let config = fixture.config("http://127.0.0.1:1");
        let data = b"healthy stage survives a damaged pending snapshot";
        let (stage, manifest) = fixture.stage("first-stage", data);
        let item_id = if existing_job {
            enqueue_bundle(&fixture.queue(), &config, &stage, &QueueLimits::default())
                .unwrap()
                .chunk_items[0]
                .item_id
                .clone()
        } else {
            enqueue(
                &fixture.queue(),
                &config,
                &stage
                    .join("chunks")
                    .join(format!("{}.bin", manifest.chunks[0].sha256)),
                "backup",
                &QueueLimits::default(),
            )
            .unwrap()
            .id
        };
        let path = snapshot(&fixture.queue(), &item_id).unwrap();
        if remove {
            fs::remove_file(&path).unwrap();
        } else {
            fs::write(&path, vec![0x9a; data.len()]).unwrap();
        }
        let before = fs::read(fixture.queue().join(DB)).unwrap();
        // 같은 ID의 빠른 반환과 다른 번들의 청크 재사용 모두 성공을 거부한다.
        assert!(
            enqueue_bundle(&fixture.queue(), &config, &stage, &QueueLimits::default()).is_err()
        );
        let (other_stage, other_manifest) = fixture.stage("other-stage", data);
        assert!(enqueue_bundle(
            &fixture.queue(),
            &config,
            &other_stage,
            &QueueLimits::default()
        )
        .is_err());
        assert_eq!(before, fs::read(fixture.queue().join(DB)).unwrap());
        assert_eq!(status(&fixture.queue()).unwrap().pending_items, 1);
        assert_eq!(
            bundle_jobs(&fixture.queue()).unwrap().total,
            u64::from(existing_job)
        );
        assert!(bundle_job(&fixture.queue(), &other_manifest.bundle_id).is_err());
        assert_eq!(
            fs::read(
                other_stage
                    .join("chunks")
                    .join(format!("{}.bin", manifest.chunks[0].sha256))
            )
            .unwrap(),
            data
        );
        assert!(stage.join("manifest.json").exists());
        assert!(!fs::read_dir(fixture.queue()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".bundle-spool-")));
    }
}
#[test]
fn missing_pending_snapshot_never_accepts_new_or_repeated_bundle() {
    broken_pending_snapshot_rejects_registration(true);
}
#[test]
fn same_size_corrupted_pending_snapshot_never_accepts_new_or_repeated_bundle() {
    broken_pending_snapshot_rejects_registration(false);
}
#[test]
fn pending_preflight_rechecks_identity_but_accepts_concurrent_verified_archive() {
    let fixture = Fixture::new();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server.endpoint);
    let target = QueueTarget::from_config(&config).unwrap();
    let data = b"pending reference transition fixture";
    let (stage, manifest) = fixture.stage("stage", data);
    let job = enqueue_bundle(&fixture.queue(), &config, &stage, &QueueLimits::default()).unwrap();
    let chunks = unique_chunks(&manifest).unwrap();
    let checked = verify_pending_snapshots(&fixture.queue(), &chunks, &target).unwrap();
    let path = snapshot(&fixture.queue(), &job.chunk_items[0].item_id).unwrap();
    let replacement = fixture.root.join("replacement");
    write_new(&replacement, data).unwrap();
    fs::rename(replacement, &path).unwrap();
    {
        let (_lock, conn) = open_mutating(&fixture.queue(), None).unwrap();
        assert!(check_reused_snapshots(
            &conn,
            &fixture.queue(),
            &job.chunk_items,
            &checked,
            &target,
            true
        )
        .is_err());
    }
    let checked = verify_pending_snapshots(&fixture.queue(), &chunks, &target).unwrap();
    assert_eq!(
        drain_once(&fixture.queue(), &config, &DrainOptions { max_items: 1 })
            .unwrap()
            .sent,
        1
    );
    assert!(!path.exists());
    let (_lock, conn) = open_mutating(&fixture.queue(), None).unwrap();
    check_reused_snapshots(
        &conn,
        &fixture.queue(),
        &job.chunk_items,
        &checked,
        &target,
        true,
    )
    .unwrap();
}
#[test]
fn v2_readonly_then_migration_preserves_old_archive_and_rejects_missing_v3_schema() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let source = fixture.root.join("ordinary");
    write_new(&source, b"legacy object").unwrap();
    let old = enqueue(
        &fixture.queue(),
        &config,
        &source,
        "audit",
        &QueueLimits::default(),
    )
    .unwrap();
    let target = QueueTarget::from_config(&config).unwrap();
    let object_lease = super::super::claim(&fixture.queue(), &target, 1, crate::now_ms())
        .unwrap()
        .unwrap();
    let receipt = crate::sign(
        crate::Receipt {
            format: crate::FORMAT.into(),
            key_id: config.key_id.clone(),
            agent_id: config.agent_id.clone(),
            kind: "audit".into(),
            sha256: old.sha256.clone(),
            size_bytes: old.size_bytes,
            received_at_ms: 1,
            retention_until_ms: 9_000_000_000_000,
        },
        &crate::load_key(&fixture.server.signing_key_file).unwrap(),
    )
    .unwrap();
    super::super::finish(
        &fixture.queue(),
        &target,
        &object_lease,
        &Ok(receipt.clone()),
        crate::now_ms(),
    )
    .unwrap();
    fs::write(&source, b"legacy pending").unwrap();
    let pending = enqueue(
        &fixture.queue(),
        &config,
        &source,
        "audit",
        &QueueLimits::default(),
    )
    .unwrap();
    let conn = Connection::open(fixture.queue().join(DB)).unwrap();
    conn.execute_batch("DROP TABLE bundle_refs;DROP TABLE bundle_jobs;PRAGMA user_version=2;")
        .unwrap();
    drop(conn);
    let before = fs::read(fixture.queue().join(DB)).unwrap();
    assert_eq!(status(&fixture.queue()).unwrap().bundle_jobs.total, 0);
    assert_eq!(before, fs::read(fixture.queue().join(DB)).unwrap());
    let (stage, _) = fixture.stage("new", b"new backup");
    enqueue_bundle(&fixture.queue(), &config, &stage, &QueueLimits::default()).unwrap();
    assert_eq!(
        item(&fixture.queue(), &old.id).unwrap().sha256,
        sha256(b"legacy object")
    );
    assert_eq!(
        item(&fixture.queue(), &old.id).unwrap().receipt,
        Some(receipt)
    );
    assert!(snapshot(&fixture.queue(), &pending.id).unwrap().exists());
    Connection::open(fixture.queue().join(DB))
        .unwrap()
        .execute_batch("DROP TABLE bundle_jobs;")
        .unwrap();
    let before = fs::read(fixture.queue().join(DB)).unwrap();
    assert!(drain_once(&fixture.queue(), &config, &DrainOptions::default()).is_err());
    assert_eq!(before, fs::read(fixture.queue().join(DB)).unwrap());
    assert!(snapshot(&fixture.queue(), &pending.id).unwrap().exists());
}
#[test]
fn job_failure_is_persisted_without_credentials_and_ready_leases_are_exclusive() {
    let fixture = Fixture::new();
    let server = Server::start(fixture.server.clone());
    let config = fixture.config(&server.endpoint);
    let job = ready(&fixture, &config);
    let target = QueueTarget::from_config(&config).unwrap();
    let first = claim_job(&fixture.queue(), &target, 1, crate::now_ms())
        .unwrap()
        .unwrap();
    assert!(claim_job(&fixture.queue(), &target, 1, crate::now_ms())
        .unwrap()
        .is_none());
    finish_job(
        &fixture.queue(),
        &target,
        &first,
        &Err("authentication"),
        crate::now_ms(),
    )
    .unwrap();
    let loaded = bundle_job(&fixture.queue(), &job.bundle_id).unwrap();
    assert_eq!(loaded.last_error.as_deref(), Some("authentication"));
    assert!(loaded.next_retry_ms > crate::now_ms());
    assert!(loaded.completion.is_none());
    let db = fs::read(fixture.queue().join(DB)).unwrap();
    assert!(!db
        .windows(config.upload_token.len())
        .any(|b| b == config.upload_token.as_bytes()));
}

#[test]
fn interrupted_registration_rolls_back_all_refs_and_next_enqueue_cleans_orphan() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let target = QueueTarget::from_config(&config).unwrap();
    drop(open_mutating(&fixture.queue(), Some((&target, &QueueLimits::default()))).unwrap());
    let (stage, manifest) = fixture.stage("interrupted", b"registration interruption fixture");
    Connection::open(fixture.queue().join(DB)).unwrap().execute_batch("CREATE TRIGGER fail_bundle_refs BEFORE INSERT ON bundle_refs BEGIN SELECT RAISE(FAIL,'simulated interruption'); END;").unwrap();
    assert!(enqueue_bundle(&fixture.queue(), &config, &stage, &QueueLimits::default()).is_err());
    assert_eq!(status(&fixture.queue()).unwrap().items_total, 0);
    assert_eq!(bundle_jobs(&fixture.queue()).unwrap().total, 0);
    assert!(fs::read_dir(fixture.queue().join(OBJECTS)).unwrap().count() > 0);
    assert!(!fs::read_dir(fixture.queue()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".bundle-spool-")));
    Connection::open(fixture.queue().join(DB))
        .unwrap()
        .execute_batch("DROP TRIGGER fail_bundle_refs;")
        .unwrap();
    let accepted =
        enqueue_bundle(&fixture.queue(), &config, &stage, &QueueLimits::default()).unwrap();
    assert_eq!(accepted.bundle_id, manifest.bundle_id);
    assert_eq!(status(&fixture.queue()).unwrap().items_total, 1);
    assert_eq!(
        fs::read_dir(fixture.queue().join(OBJECTS)).unwrap().count(),
        1
    );
}
