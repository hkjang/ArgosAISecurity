use super::*;
use crate::{Receipt, FORMAT};
use ed25519_dalek::SigningKey;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

struct Fixture {
    dir: PathBuf,
    source: PathBuf,
    key: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let dir = std::env::temp_dir().join(format!("argos-vault-queue-{}", hex::encode(bytes)));
        make_directory(&dir).unwrap();
        let source = dir.join("source.bin");
        fs::write(&source, b"original snapshot").unwrap();
        Self {
            dir,
            source,
            key: SigningKey::from_bytes(&[7; 32]),
        }
    }
    fn queue(&self) -> PathBuf {
        self.dir.join("queue")
    }
    fn config(&self, endpoint: &str) -> VaultConfig {
        VaultConfig {
            endpoint: endpoint.into(),
            agent_id: "agent-queue".into(),
            upload_token: "queue-token-never-persist-this".into(),
            pinned_pubkey: hex::encode(self.key.verifying_key().to_bytes()),
            key_id: "queue-key".into(),
            allow_http_loopback: true,
            ..Default::default()
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0);
        received.extend_from_slice(&chunk[..n]);
        if let Some(split) = received.windows(4).position(|p| p == b"\r\n\r\n") {
            let header = String::from_utf8(received[..split].to_vec()).unwrap();
            let size: usize = header
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .unwrap()
                .parse()
                .unwrap();
            if received.len() >= split + 4 + size {
                return (header, received[split + 4..split + 4 + size].to_vec());
            }
        }
    }
}
fn receipt(bytes: &[u8], key: &SigningKey) -> SignedReceipt {
    crate::sign(
        Receipt {
            format: FORMAT.into(),
            key_id: "queue-key".into(),
            agent_id: "agent-queue".into(),
            kind: "evidence".into(),
            sha256: sha256(bytes),
            size_bytes: bytes.len() as u64,
            received_at_ms: 1000,
            retention_until_ms: 9_000_000_000_000,
        },
        key,
    )
    .unwrap()
}
fn respond(stream: &mut TcpStream, receipt: &SignedReceipt) {
    let body = serde_json::to_vec(receipt).unwrap();
    write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
    stream.write_all(&body).unwrap();
}
fn due(directory: &Path) {
    Connection::open(directory.join(DB))
        .unwrap()
        .execute(
            "UPDATE queue_items SET next_retry_ms=0 WHERE state='pending'",
            [],
        )
        .unwrap();
}

#[test]
fn stable_snapshot_survives_source_change_and_only_verified_ack_removes_it() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = fixture.config(&format!("http://{}", listener.local_addr().unwrap()));
    let queued = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    fs::write(&fixture.source, b"source changed after enqueue").unwrap();
    let key = fixture.key.clone();
    let received = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let (header, bytes) = request(&mut socket);
        assert!(header.starts_with(&format!("POST /v1/objects/{} ", sha256(&bytes))));
        respond(&mut socket, &receipt(&bytes, &key));
        bytes
    });
    let drained = drain_once(&fixture.queue(), &config, &DrainOptions::default()).unwrap();
    assert_eq!(drained.sent, 1);
    assert_eq!(received.join().unwrap(), b"original snapshot");
    assert!(!snapshot(&fixture.queue(), &queued.id).unwrap().exists());
    let state = status(&fixture.queue()).unwrap();
    assert_eq!(state.sent_items, 1);
    assert_eq!(state.pending_bytes, 0);
    let ack = state.items[0].receipt.as_ref().unwrap();
    verify_receipt(ack, &config.pinned_pubkey).unwrap();
    assert_eq!(ack.receipt.sha256, queued.sha256);
    let raw = fs::read(fixture.queue().join(DB)).unwrap();
    assert!(!raw
        .windows(config.upload_token.len())
        .any(|w| w == config.upload_token.as_bytes()));
}

#[test]
fn lost_ack_then_restart_retries_same_bytes_and_target_with_backoff() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = fixture.config(&format!("http://{}", listener.local_addr().unwrap()));
    enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    let key = fixture.key.clone();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let output = seen.clone();
    let server = thread::spawn(move || {
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().unwrap();
            let (_, bytes) = request(&mut socket);
            output.lock().unwrap().push(bytes.clone());
            if attempt == 1 {
                respond(&mut socket, &receipt(&bytes, &key));
            }
        }
    });
    let failure = drain_once(&fixture.queue(), &config, &DrainOptions::default()).unwrap();
    assert_eq!(failure.failed, 1);
    let persisted = status(&fixture.queue()).unwrap();
    assert_eq!(persisted.items[0].attempts, 1);
    assert!(persisted.items[0].next_retry_ms > crate::now_ms());
    assert_eq!(persisted.pending_items, 1);
    assert!(persisted.items[0].receipt.is_none());
    let deferred = drain_once(&fixture.queue(), &config, &DrainOptions::default()).unwrap();
    assert_eq!(deferred.attempted, 0);
    assert_eq!(deferred.remaining_pending, 1);
    // 종료된 첫 drain의 핸들은 없다. 저장된 큐를 다시 열어 재시도한다.
    due(&fixture.queue());
    let success = drain_once(&fixture.queue(), &config, &DrainOptions::default()).unwrap();
    assert_eq!(success.sent, 1);
    assert_eq!(status(&fixture.queue()).unwrap().items[0].attempts, 2);
    server.join().unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], seen[1]);
}

#[test]
fn forged_receipt_and_wrong_target_cannot_complete_or_retarget_queue() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = fixture.config(&format!("http://{}", listener.local_addr().unwrap()));
    let item = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    for changed in 0..4 {
        let mut wrong = config.clone();
        match changed {
            0 => wrong.endpoint = "http://127.0.0.1:1".into(),
            1 => wrong.agent_id = "different-agent".into(),
            2 => wrong.key_id = "different-key".into(),
            _ => {
                wrong.pinned_pubkey =
                    hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes())
            }
        };
        assert!(drain_once(&fixture.queue(), &wrong, &DrainOptions::default()).is_err());
        assert!(enqueue(
            &fixture.queue(),
            &wrong,
            &fixture.source,
            "evidence",
            &QueueLimits::default()
        )
        .is_err());
    }
    assert_eq!(status(&fixture.queue()).unwrap().items[0].attempts, 0);
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let (_, bytes) = request(&mut socket);
        respond(
            &mut socket,
            &receipt(&bytes, &SigningKey::from_bytes(&[9; 32])),
        );
    });
    assert_eq!(
        drain_once(&fixture.queue(), &config, &DrainOptions::default())
            .unwrap()
            .failed,
        1
    );
    server.join().unwrap();
    assert!(snapshot(&fixture.queue(), &item.id).unwrap().exists());
    assert_eq!(status(&fixture.queue()).unwrap().pending_items, 1);
}

#[test]
fn corrupt_snapshot_is_not_uploaded_and_status_does_not_mutate_queue() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut config = fixture.config(&format!("http://{}", listener.local_addr().unwrap()));
    config.timeout_secs = 1;
    let item = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    let db_before = fs::read(fixture.queue().join(DB)).unwrap();
    let state = status(&fixture.queue()).unwrap();
    assert_eq!(state.items_total, 1);
    assert_eq!(db_before, fs::read(fixture.queue().join(DB)).unwrap());
    fs::write(snapshot(&fixture.queue(), &item.id).unwrap(), b"corrupt").unwrap();
    assert_eq!(
        drain_once(&fixture.queue(), &config, &DrainOptions::default())
            .unwrap()
            .failed,
        1
    );
    assert_eq!(
        status(&fixture.queue()).unwrap().items[0]
            .last_error
            .as_deref(),
        Some("queue_local")
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn quotas_count_only_active_rows_and_dedup_includes_archive() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let limits = QueueLimits {
        max_items: 1,
        max_bytes: 17,
    };
    let first = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &limits,
    )
    .unwrap();
    let again = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &limits,
    )
    .unwrap();
    assert_eq!(first.id, again.id);
    assert_eq!(status(&fixture.queue()).unwrap().items_total, 1);
    fs::write(&fixture.source, b"another").unwrap();
    assert!(enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &limits
    )
    .is_err());
    let target = QueueTarget::from_config(&config).unwrap();
    let lease = claim(&fixture.queue(), &target, 30, crate::now_ms())
        .unwrap()
        .unwrap();
    finish(
        &fixture.queue(),
        &target,
        &lease,
        &Ok(receipt(b"original snapshot", &fixture.key)),
        crate::now_ms(),
    )
    .unwrap();
    let next = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &limits,
    )
    .unwrap();
    assert_ne!(next.id, first.id);
    assert!(!snapshot(&fixture.queue(), &first.id).unwrap().exists());
    assert_eq!(status(&fixture.queue()).unwrap().sent_items, 1);
    fs::write(&fixture.source, b"original snapshot").unwrap();
    assert_eq!(
        enqueue(
            &fixture.queue(),
            &config,
            &fixture.source,
            "evidence",
            &limits
        )
        .unwrap()
        .id,
        first.id
    );
    let other = fixture.dir.join("byte-queue");
    fs::write(&fixture.source, b"too big").unwrap();
    assert!(enqueue(
        &other,
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits {
            max_items: 2,
            max_bytes: 1
        }
    )
    .is_err());
    assert_eq!(status(&other).unwrap().items_total, 0);
}

#[test]
fn existing_snapshots_without_database_or_lock_are_never_reinitialized() {
    for missing in [DB, "queue.lock"] {
        let fixture = Fixture::new();
        let config = fixture.config("http://127.0.0.1:1");
        let entry = enqueue(
            &fixture.queue(),
            &config,
            &fixture.source,
            "evidence",
            &QueueLimits::default(),
        )
        .unwrap();
        let payload = snapshot(&fixture.queue(), &entry.id).unwrap();
        let original = fs::read(&payload).unwrap();
        fs::remove_file(fixture.queue().join(missing)).unwrap();
        assert!(enqueue(
            &fixture.queue(),
            &config,
            &fixture.source,
            "evidence",
            &QueueLimits::default()
        )
        .is_err());
        assert!(drain_once(&fixture.queue(), &config, &DrainOptions::default()).is_err());
        assert!(!fixture.queue().join(missing).exists());
        assert_eq!(fs::read(payload).unwrap(), original);
    }

    // 최초 등록 전부터 objects만 남은 경로도 새 잠금/DB를 만들지 않는다.
    let fixture = Fixture::new();
    make_directory(&fixture.queue()).unwrap();
    make_directory(&fixture.queue().join(OBJECTS)).unwrap();
    let orphan = snapshot(&fixture.queue(), &"a".repeat(32)).unwrap();
    write_new(&orphan, b"unindexed previous snapshot").unwrap();
    assert!(enqueue(
        &fixture.queue(),
        &fixture.config("http://127.0.0.1:1"),
        &fixture.source,
        "evidence",
        &QueueLimits::default()
    )
    .is_err());
    assert_eq!(fs::read(orphan).unwrap(), b"unindexed previous snapshot");
    assert!(!fixture.queue().join(DB).exists());
    assert!(!fixture.queue().join("queue.lock").exists());
}

#[test]
fn empty_foreign_and_incomplete_databases_preserve_all_existing_files() {
    for damage in [
        "empty",
        "foreign",
        "foreign-versioned",
        "missing-meta",
        "missing-table",
    ] {
        let fixture = Fixture::new();
        let config = fixture.config("http://127.0.0.1:1");
        let entry = enqueue(
            &fixture.queue(),
            &config,
            &fixture.source,
            "evidence",
            &QueueLimits::default(),
        )
        .unwrap();
        let payload = snapshot(&fixture.queue(), &entry.id).unwrap();
        let orphan = snapshot(&fixture.queue(), &"a".repeat(32)).unwrap();
        write_new(&orphan, b"must remain until DB is trustworthy").unwrap();
        let db = fixture.queue().join(DB);
        match damage {
            "empty" | "foreign" | "foreign-versioned" => {
                fs::write(&db, []).unwrap();
                if damage != "empty" {
                    let conn = Connection::open(&db).unwrap();
                    conn.execute_batch("CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('preserve');").unwrap();
                    if damage == "foreign-versioned" {
                        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
                            .unwrap();
                    }
                }
            }
            "missing-meta" => {
                Connection::open(&db)
                    .unwrap()
                    .execute("DELETE FROM queue_meta", [])
                    .unwrap();
            }
            "missing-table" => {
                Connection::open(&db)
                    .unwrap()
                    .execute("DROP TABLE queue_items", [])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let db_before = fs::read(&db).unwrap();
        assert!(
            enqueue(
                &fixture.queue(),
                &config,
                &fixture.source,
                "evidence",
                &QueueLimits::default()
            )
            .is_err(),
            "{damage}"
        );
        assert!(
            drain_once(&fixture.queue(), &config, &DrainOptions::default()).is_err(),
            "{damage}"
        );
        assert_eq!(fs::read(&db).unwrap(), db_before, "{damage}");
        assert_eq!(fs::read(payload).unwrap(), b"original snapshot", "{damage}");
        assert_eq!(
            fs::read(orphan).unwrap(),
            b"must remain until DB is trustworthy",
            "{damage}"
        );
    }
}

#[test]
fn interrupted_initialization_is_not_repaired_but_empty_directory_can_initialize() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    make_directory(&fixture.queue()).unwrap();
    let lock = Lock::acquire(&fixture.queue(), true).unwrap();
    drop(lock); // lock 작성 뒤 중단된 초기화
    assert!(enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default()
    )
    .is_err());
    assert!(!fixture.queue().join(DB).exists());
    assert!(!fixture.queue().join(OBJECTS).exists());
    assert_eq!(fs::read_dir(fixture.queue()).unwrap().count(), 1);

    let empty = fixture.dir.join("empty");
    make_directory(&empty).unwrap();
    enqueue(
        &empty,
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    assert_eq!(status(&empty).unwrap().pending_items, 1);
}

#[test]
fn interrupted_snapshot_publication_and_sent_cleanup_resume_without_deleting_pending() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let pending = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    let orphan = fixture
        .queue()
        .join(OBJECTS)
        .join(format!("{}.bin", "a".repeat(32)));
    write_new(&orphan, b"orphan-before-db-commit").unwrap();
    let temporary = fixture
        .queue()
        .join(OBJECTS)
        .join(".argos-vault-crashed.tmp");
    fs::write(&temporary, b"partial").unwrap();
    status(&fixture.queue()).unwrap();
    assert!(orphan.exists() && temporary.exists());
    enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    assert!(!orphan.exists() && !temporary.exists());
    assert!(snapshot(&fixture.queue(), &pending.id).unwrap().exists());
}

#[test]
#[cfg(unix)]
fn privacy_and_nonblocking_cross_process_style_flock_are_enforced() {
    if let Some(directory) = std::env::var_os("ARGOS_QUEUE_LOCK_TEST_DIR") {
        assert!(Lock::acquire(Path::new(&directory), false).is_err());
        return;
    }
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    assert_eq!(fs::metadata(fixture.queue()).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(fixture.queue().join(DB)).unwrap().mode() & 0o777,
        0o600
    );
    let held = Lock::acquire(&fixture.queue(), false).unwrap();
    assert!(Lock::acquire(&fixture.queue(), false).is_err());
    assert!(drain_once(&fixture.queue(), &config, &DrainOptions::default()).is_err());
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "queue::tests::privacy_and_nonblocking_cross_process_style_flock_are_enforced",
            "--nocapture",
        ])
        .env("ARGOS_QUEUE_LOCK_TEST_DIR", fixture.queue())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    drop(held);
    let alias = fixture.dir.join("alias");
    symlink(fixture.queue(), &alias).unwrap();
    assert!(status(&alias).is_err());
    fs::set_permissions(fixture.queue().join(DB), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(status(&fixture.queue()).is_err());
}

#[test]
fn retry_is_bounded_and_batch_limit_rejected_before_work() {
    assert_eq!(retry_delay(1), 5000);
    assert_eq!(retry_delay(2), 10000);
    assert_eq!(retry_delay(u32::MAX), 3_600_000);
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    assert!(drain_once(&fixture.queue(), &config, &DrainOptions { max_items: 0 }).is_err());
    assert!(drain_once(&fixture.queue(), &config, &DrainOptions { max_items: 101 }).is_err());
}

#[test]
fn invalid_directory_paths_are_rejected_before_creating_anything() {
    if std::env::var_os("ARGOS_QUEUE_RELATIVE_TEST").is_some() {
        let directory = Path::new("relative-queue");
        assert!(!directory.exists());
        assert!(make_directory(directory).is_err());
        assert!(!directory.exists());
        let absolute = std::env::current_dir()
            .unwrap()
            .join("unused/../unexpected-queue");
        fs::create_dir("unused").unwrap();
        assert!(make_directory(&absolute).is_err());
        assert!(!Path::new("unexpected-queue").exists());
        return;
    }
    // 다른 병렬 테스트의 cwd를 바꾸지 않고 단일 상대 경로를 실제로 검사한다.
    let fixture = Fixture::new();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "queue::tests::invalid_directory_paths_are_rejected_before_creating_anything",
            "--nocapture",
        ])
        .current_dir(&fixture.dir)
        .env("ARGOS_QUEUE_RELATIVE_TEST", "1")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
}

#[test]
fn old_completed_receipt_can_be_read_beyond_status_page_without_mutation() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let mut all = Vec::new();
    for index in 0..101 {
        let payload = format!("history-{index}").into_bytes();
        fs::write(&fixture.source, &payload).unwrap();
        let entry = enqueue(
            &fixture.queue(),
            &config,
            &fixture.source,
            "evidence",
            &QueueLimits::default(),
        )
        .unwrap();
        all.push((entry, payload));
    }
    let summary = status(&fixture.queue()).unwrap();
    assert_eq!(summary.items.len(), 100);
    assert!(summary.items_truncated);
    let (older, bytes) = all
        .iter()
        .find(|(entry, _)| !summary.items.iter().any(|current| current.id == entry.id))
        .unwrap();
    let ack = receipt(bytes, &fixture.key);
    let target = QueueTarget::from_config(&config).unwrap();
    // 가장 오래된 항목이 첫 임대 대상이다.
    let lease = claim(&fixture.queue(), &target, 30, crate::now_ms())
        .unwrap()
        .unwrap();
    assert_eq!(lease.item.id, older.id);
    finish(
        &fixture.queue(),
        &target,
        &lease,
        &Ok(ack.clone()),
        crate::now_ms(),
    )
    .unwrap();
    let before = fs::read(fixture.queue().join(DB)).unwrap();
    let loaded = item(&fixture.queue(), &older.id).unwrap();
    assert_eq!(loaded.receipt, Some(ack));
    assert_eq!(loaded.sha256, older.sha256);
    assert_eq!(before, fs::read(fixture.queue().join(DB)).unwrap());
    assert!(!snapshot(&fixture.queue(), &older.id).unwrap().exists()); // archived payload already cleaned
    assert!(item(&fixture.queue(), "../queue.sqlite3").is_err());
}

#[test]
fn each_drain_respects_its_batch_and_no_network_for_remaining_not_selected() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = fixture.config(&format!("http://{}", listener.local_addr().unwrap()));
    for bytes in [b"first".as_slice(), b"second".as_slice()] {
        fs::write(&fixture.source, bytes).unwrap();
        enqueue(
            &fixture.queue(),
            &config,
            &fixture.source,
            "evidence",
            &QueueLimits::default(),
        )
        .unwrap();
    }
    let key = fixture.key.clone();
    let server = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().unwrap();
            let (_, bytes) = request(&mut socket);
            respond(&mut socket, &receipt(&bytes, &key));
            seen.push(bytes);
        }
        seen
    });
    let first = drain_once(&fixture.queue(), &config, &DrainOptions { max_items: 1 }).unwrap();
    assert_eq!(first.attempted, 1);
    assert_eq!(first.sent, 1);
    assert_eq!(first.remaining_pending, 1);
    let second = drain_once(&fixture.queue(), &config, &DrainOptions { max_items: 1 }).unwrap();
    assert_eq!(second.attempted, 1);
    assert_eq!(second.remaining_pending, 0);
    let seen = server.join().unwrap();
    assert_eq!(seen.len(), 2);
    assert_ne!(seen[0], seen[1]);
}

#[test]
fn lease_expiry_reclaim_and_late_ack_cannot_complete_another_workers_item() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let entry = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    let target = QueueTarget::from_config(&config).unwrap();
    let now = crate::now_ms();
    let first = claim(&fixture.queue(), &target, 1, now).unwrap().unwrap();
    assert!(claim(&fixture.queue(), &target, 1, now + 1000)
        .unwrap()
        .is_none());
    let expires: u64 = Connection::open(fixture.queue().join(DB))
        .unwrap()
        .query_row(
            "SELECT lease_expires_ms FROM queue_items WHERE id=?1",
            [&entry.id],
            |r| r.get(0),
        )
        .unwrap();
    let second = claim(&fixture.queue(), &target, 1, expires + 1)
        .unwrap()
        .unwrap();
    assert_ne!(first.token, second.token);
    assert!(!finish(
        &fixture.queue(),
        &target,
        &first,
        &Ok(receipt(b"original snapshot", &fixture.key)),
        expires + 2
    )
    .unwrap());
    assert!(snapshot(&fixture.queue(), &entry.id).unwrap().exists());
    assert_eq!(status(&fixture.queue()).unwrap().archive_items, 0);
    assert!(finish(
        &fixture.queue(),
        &target,
        &second,
        &Ok(receipt(b"original snapshot", &fixture.key)),
        expires + 3
    )
    .unwrap());
    assert_eq!(status(&fixture.queue()).unwrap().archive_items, 1);
    assert!(!snapshot(&fixture.queue(), &entry.id).unwrap().exists());
}

#[test]
fn worker_process_exit_leaves_reclaimable_lease() {
    if let Some(dir) = std::env::var_os("ARGOS_QUEUE_LEASE_TEST_DIR") {
        let directory = Path::new(&dir);
        let conn = open_readonly(directory).unwrap();
        let target = metadata(&conn).unwrap().unwrap().0;
        drop(conn);
        claim(directory, &target, 1, crate::now_ms())
            .unwrap()
            .unwrap();
        return;
    }
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "queue::tests::worker_process_exit_leaves_reclaimable_lease",
        ])
        .env("ARGOS_QUEUE_LEASE_TEST_DIR", fixture.queue())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(status(&fixture.queue()).unwrap().leased_items, 1);
    let target = QueueTarget::from_config(&config).unwrap();
    assert!(claim(&fixture.queue(), &target, 1, crate::now_ms())
        .unwrap()
        .is_none());
    let reclaimed = claim(&fixture.queue(), &target, 1, crate::now_ms() + 32_000)
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.item.attempts, 2);
}

#[test]
fn network_wait_allows_cross_process_enqueue_and_other_workers_skip_lease() {
    if let Some(dir) = std::env::var_os("ARGOS_QUEUE_ENQUEUE_TEST_DIR") {
        let config: VaultConfig =
            serde_json::from_str(&std::env::var("ARGOS_QUEUE_ENQUEUE_TEST_CONFIG").unwrap())
                .unwrap();
        enqueue(
            Path::new(&dir),
            &config,
            Path::new(&std::env::var_os("ARGOS_QUEUE_ENQUEUE_TEST_SOURCE").unwrap()),
            "evidence",
            &QueueLimits::default(),
        )
        .unwrap();
        return;
    }
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = fixture.config(&format!("http://{}", listener.local_addr().unwrap()));
    enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    let (waiting, started) = std::sync::mpsc::channel();
    let (resume, go) = std::sync::mpsc::channel();
    let key = fixture.key.clone();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let (_, bytes) = request(&mut socket);
        waiting.send(()).unwrap();
        go.recv().unwrap();
        respond(&mut socket, &receipt(&bytes, &key));
    });
    let directory = fixture.queue();
    let worker_config = config.clone();
    let worker = thread::spawn(move || {
        drain_once(&directory, &worker_config, &DrainOptions { max_items: 1 }).unwrap()
    });
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        drain_once(&fixture.queue(), &config, &DrainOptions { max_items: 1 })
            .unwrap()
            .attempted,
        0
    );
    fs::write(&fixture.source, b"registered during blocked HTTP").unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "queue::tests::network_wait_allows_cross_process_enqueue_and_other_workers_skip_lease",
        ])
        .env("ARGOS_QUEUE_ENQUEUE_TEST_DIR", fixture.queue())
        .env("ARGOS_QUEUE_ENQUEUE_TEST_SOURCE", &fixture.source)
        .env(
            "ARGOS_QUEUE_ENQUEUE_TEST_CONFIG",
            serde_json::to_string(&config).unwrap(),
        )
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(status(&fixture.queue()).unwrap().pending_items, 2);
    resume.send(()).unwrap();
    assert_eq!(worker.join().unwrap().sent, 1);
    server.join().unwrap();
}

fn downgrade_v1(directory: &Path, sent: &QueueItem, ack: &SignedReceipt) {
    let conn = Connection::open(directory.join(DB)).unwrap();
    conn.execute_batch("DROP TABLE receipt_archive; ALTER TABLE queue_items DROP COLUMN lease_token; ALTER TABLE queue_items DROP COLUMN lease_expires_ms; PRAGMA user_version=1;").unwrap();
    conn.execute("UPDATE queue_items SET state='sent',receipt_json=?1,sent_at_ms=1001,next_retry_ms=0 WHERE id=?2",params![serde_json::to_string(ack).unwrap(),sent.id]).unwrap();
}
#[test]
fn v1_migration_preserves_receipts_pending_snapshots_and_dedup() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let sent = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    fs::write(&fixture.source, b"pending version").unwrap();
    let pending = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    downgrade_v1(
        &fixture.queue(),
        &sent,
        &receipt(b"original snapshot", &fixture.key),
    );
    let before = fs::read(fixture.queue().join(DB)).unwrap();
    assert_eq!(status(&fixture.queue()).unwrap().sent_items, 1);
    assert_eq!(fs::read(fixture.queue().join(DB)).unwrap(), before);
    assert_eq!(
        enqueue(
            &fixture.queue(),
            &config,
            &fixture.source,
            "evidence",
            &QueueLimits::default()
        )
        .unwrap()
        .id,
        pending.id
    );
    assert!(snapshot(&fixture.queue(), &pending.id).unwrap().exists());
    assert!(!snapshot(&fixture.queue(), &sent.id).unwrap().exists());
    assert_eq!(item(&fixture.queue(), &sent.id).unwrap().state, "sent");
    let conn = Connection::open(fixture.queue().join(DB)).unwrap();
    let version: u32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 2);
    fs::write(&fixture.source, b"original snapshot").unwrap();
    assert_eq!(
        enqueue(
            &fixture.queue(),
            &config,
            &fixture.source,
            "evidence",
            &QueueLimits::default()
        )
        .unwrap()
        .id,
        sent.id
    );
}
#[test]
fn corrupt_v1_receipt_refuses_migration_without_erasing_snapshots_or_db() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let entry = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    downgrade_v1(
        &fixture.queue(),
        &entry,
        &receipt(b"original snapshot", &SigningKey::from_bytes(&[9; 32])),
    );
    let before = fs::read(fixture.queue().join(DB)).unwrap();
    assert!(enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default()
    )
    .is_err());
    assert_eq!(fs::read(fixture.queue().join(DB)).unwrap(), before);
    assert!(snapshot(&fixture.queue(), &entry.id).unwrap().exists());
}
#[test]
fn archive_export_is_non_destructive_independently_verified_and_rejects_truncation() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let entry = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    let target = QueueTarget::from_config(&config).unwrap();
    let lease = claim(&fixture.queue(), &target, 1, crate::now_ms())
        .unwrap()
        .unwrap();
    finish(
        &fixture.queue(),
        &target,
        &lease,
        &Ok(receipt(b"original snapshot", &fixture.key)),
        crate::now_ms(),
    )
    .unwrap();
    let before = fs::read(fixture.queue().join(DB)).unwrap();
    let output = fixture.dir.join("archive.jsonl");
    let exported = export_archive(&fixture.queue(), &output).unwrap();
    assert_eq!(exported.archived_items, 1);
    assert_eq!(
        verify_archive(&output, &config.pinned_pubkey)
            .unwrap()
            .sha256,
        exported.sha256
    );
    assert!(
        !verify_archive(&output, &config.pinned_pubkey)
            .unwrap()
            .archive_authenticated
    );
    assert_eq!(fs::read(fixture.queue().join(DB)).unwrap(), before);
    assert_eq!(item(&fixture.queue(), &entry.id).unwrap().state, "sent");
    assert!(export_archive(&fixture.queue(), &output).is_err());
    assert!(verify_archive(
        &output,
        &hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes())
    )
    .is_err());
    let original = fs::read(&output).unwrap();
    let truncated = original
        .split_inclusive(|b| *b == b'\n')
        .take(2)
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    fs::write(&output, truncated).unwrap();
    assert!(verify_archive(&output, &config.pinned_pubkey).is_err());
    fs::write(&output, [original, b"{}\n".to_vec()].concat()).unwrap();
    assert!(verify_archive(&output, &config.pinned_pubkey).is_err());
}

#[test]
fn over_one_thousand_deliveries_reuse_active_slots_and_keep_old_dedup() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = fixture.config(&format!("http://{}", listener.local_addr().unwrap()));
    let key = fixture.key.clone();
    let server = thread::spawn(move || {
        for _ in 0..1001 {
            let (mut socket, _) = listener.accept().unwrap();
            let (_, bytes) = request(&mut socket);
            respond(&mut socket, &receipt(&bytes, &key));
        }
    });
    let limits = QueueLimits {
        max_items: 20,
        max_bytes: 1024,
    };
    let mut first = String::new();
    for offset in (0..1001).step_by(20) {
        for index in offset..(offset + 20).min(1001) {
            fs::write(&fixture.source, format!("long-running-{index}")).unwrap();
            let entry = enqueue(
                &fixture.queue(),
                &config,
                &fixture.source,
                "evidence",
                &limits,
            )
            .unwrap();
            if index == 0 {
                first = entry.id;
            }
        }
        let report =
            drain_once(&fixture.queue(), &config, &DrainOptions { max_items: 20 }).unwrap();
        assert_eq!(report.failed, 0);
        assert_eq!(report.remaining_pending, 0);
    }
    server.join().unwrap();
    let summary = status(&fixture.queue()).unwrap();
    assert_eq!(summary.archive_items, 1001);
    assert_eq!(summary.pending_items, 0);
    assert_eq!(summary.limits.unwrap().max_items, 20);
    fs::write(&fixture.source, b"long-running-0").unwrap();
    assert_eq!(
        enqueue(
            &fixture.queue(),
            &config,
            &fixture.source,
            "evidence",
            &limits
        )
        .unwrap()
        .id,
        first
    );
    assert!(item(&fixture.queue(), &first).unwrap().receipt.is_some());
}

#[test]
fn corrupt_archived_ack_preserves_leftover_payload_on_next_mutation() {
    let fixture = Fixture::new();
    let config = fixture.config("http://127.0.0.1:1");
    let entry = enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default(),
    )
    .unwrap();
    let target = QueueTarget::from_config(&config).unwrap();
    let lease = claim(&fixture.queue(), &target, 1, crate::now_ms())
        .unwrap()
        .unwrap();
    finish(
        &fixture.queue(),
        &target,
        &lease,
        &Ok(receipt(b"original snapshot", &fixture.key)),
        crate::now_ms(),
    )
    .unwrap();
    let payload = snapshot(&fixture.queue(), &entry.id).unwrap();
    write_new(&payload, b"original snapshot").unwrap();
    let forged = receipt(b"original snapshot", &SigningKey::from_bytes(&[9; 32]));
    Connection::open(fixture.queue().join(DB))
        .unwrap()
        .execute(
            "UPDATE receipt_archive SET receipt_json=?1",
            [serde_json::to_string(&forged).unwrap()],
        )
        .unwrap();
    let before = fs::read(fixture.queue().join(DB)).unwrap();
    assert!(enqueue(
        &fixture.queue(),
        &config,
        &fixture.source,
        "evidence",
        &QueueLimits::default()
    )
    .is_err());
    assert!(item(&fixture.queue(), &entry.id).is_err());
    assert!(export_archive(&fixture.queue(), &fixture.dir.join("forged.jsonl")).is_err());
    assert!(!fixture.dir.join("forged.jsonl").exists());
    assert_eq!(fs::read(payload).unwrap(), b"original snapshot");
    assert_eq!(fs::read(fixture.queue().join(DB)).unwrap(), before);
}
