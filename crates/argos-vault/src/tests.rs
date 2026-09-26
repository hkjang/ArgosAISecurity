use super::*;
use axum::{routing::post, Router};
use std::{collections::BTreeMap, net::TcpListener, path::PathBuf, sync::mpsc, thread};

struct HttpServer {
    endpoint: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl HttpServer {
    fn start(application: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let (ready, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
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
    dir: PathBuf,
    config: ServerConfig,
    client: VaultConfig,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "argos-vault-test-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).unwrap();
        let public = generate_signing_key_file(&dir.join("signing.key")).unwrap();
        let config = ServerConfig {
            dir: dir.clone(),
            signing_key_file: dir.join("signing.key"),
            agent_tokens: BTreeMap::from([
                ("host-a".into(), "agent-a-token-0123456789".into()),
                ("host-b".into(), "agent-b-token-0123456789".into()),
            ]),
            admin_token: "admin-token-0123456789".into(),
            ..Default::default()
        };
        let client = VaultConfig {
            agent_id: "host-a".into(),
            upload_token: config.agent_tokens["host-a"].clone(),
            admin_token: config.admin_token.clone(),
            pinned_pubkey: public,
            allow_http_loopback: true,
            ..Default::default()
        };
        Self {
            dir,
            config,
            client,
        }
    }
    fn source(&self, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(format!(
            "source-{}",
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn real_http_upload_idempotency_signed_proof_and_recovery_after_local_loss() {
    let mut fixture = Fixture::new();
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    fixture.client.endpoint = server.endpoint.clone();
    let source = fixture.source(b"reviewed backup bytes\n");
    let receipt = upload_file(&fixture.client, &source, "backup").unwrap();
    assert_eq!(receipt.receipt.agent_id, "host-a");
    assert_eq!(
        receipt.receipt.retention_until_ms - receipt.receipt.received_at_ms,
        fixture.config.retention_secs * 1000
    );
    verify_file(&source, &receipt, &fixture.client.pinned_pubkey).unwrap();
    assert_eq!(
        upload_file(&fixture.client, &source, "backup").unwrap(),
        receipt
    );
    assert!(upload_file(&fixture.client, &source, "audit").is_err());
    let proof = fixture.dir.join("local-receipt.json");
    write_receipt_new(&proof, &receipt).unwrap();
    assert!(write_receipt_new(&proof, &receipt).is_err());
    assert_eq!(read_receipt(&proof).unwrap(), receipt);
    drop(server);
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    fixture.client.endpoint = server.endpoint.clone();
    assert_eq!(
        upload_file(&fixture.client, &source, "backup").unwrap(),
        receipt
    );
    fs::remove_file(&source).unwrap();
    let recovered = fixture.dir.join("recovered");
    let remote = fetch_file(
        &fixture.client,
        "host-a",
        &receipt.receipt.sha256,
        &recovered,
    )
    .unwrap();
    assert_eq!(receipt, remote);
    assert_eq!(fs::read(&recovered).unwrap(), b"reviewed backup bytes\n");
    assert!(fetch_file(
        &fixture.client,
        "host-a",
        &receipt.receipt.sha256,
        &recovered
    )
    .is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(fs::metadata(&recovered).unwrap().mode() & 0o777, 0o600);
    }
}

#[test]
fn real_http_rejects_body_tamper_cross_agent_spoof_and_delete_or_overwrite() {
    let mut fixture = Fixture::new();
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    fixture.client.endpoint = server.endpoint.clone();
    let source = fixture.source(b"evidence bytes");
    let original = upload_file(&fixture.client, &source, "evidence").unwrap();
    let client = reqwest::blocking::Client::new();
    let url = format!("{}/v1/objects/{}", server.endpoint, original.receipt.sha256);
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(&fixture.client.upload_token)
            .header("X-Argos-Kind", "evidence")
            .body("tampered")
            .send()
            .unwrap()
            .status()
            .as_u16(),
        422
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(&fixture.client.upload_token)
            .header("X-Argos-Kind", "evidence")
            .header("X-Argos-Agent-ID", "host-b")
            .body("evidence bytes")
            .send()
            .unwrap()
            .status()
            .as_u16(),
        400
    );
    assert_eq!(
        client
            .delete(&url)
            .bearer_auth(&fixture.client.admin_token)
            .send()
            .unwrap()
            .status()
            .as_u16(),
        405
    );
    assert_eq!(
        client
            .put(&url)
            .bearer_auth(&fixture.client.admin_token)
            .body("replace")
            .send()
            .unwrap()
            .status()
            .as_u16(),
        405
    );
    let mut impersonated = fixture.client.clone();
    impersonated.agent_id = "host-b".into();
    assert!(upload_file(&impersonated, &source, "evidence").is_err());
    impersonated.admin_token = fixture.client.upload_token.clone();
    assert!(fetch_file(
        &impersonated,
        "host-a",
        &original.receipt.sha256,
        &fixture.dir.join("denied")
    )
    .is_err());
    assert!(!fixture.dir.join("denied").exists());
    // 별도 유효 토큰의 같은 해시는 그 에이전트의 별도 영수증으로 저장된다.
    impersonated.upload_token = fixture.config.agent_tokens["host-b"].clone();
    let second = upload_file(&impersonated, &source, "evidence").unwrap();
    assert_eq!(second.receipt.agent_id, "host-b");
    assert_eq!(
        upload_file(&fixture.client, &source, "evidence").unwrap(),
        original
    );
    // 관리자는 읽기 전용이며 관리자 토큰을 수집 권한으로 사용할 수 없다.
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(&fixture.client.admin_token)
            .header("X-Argos-Kind", "evidence")
            .body("evidence bytes")
            .send()
            .unwrap()
            .status()
            .as_u16(),
        401
    );
}

#[test]
fn signature_binds_all_metadata_and_rejects_wrong_key_and_body() {
    let fixture = Fixture::new();
    let key = load_key(&fixture.config.signing_key_file).unwrap();
    let body = fixture.source(b"receipt content");
    let receipt = sign(
        Receipt {
            format: FORMAT.into(),
            key_id: "vault-1".into(),
            agent_id: "host-a".into(),
            kind: "audit".into(),
            sha256: sha256(b"receipt content"),
            size_bytes: 15,
            received_at_ms: 100,
            retention_until_ms: 200,
        },
        &key,
    )
    .unwrap();
    verify_file(&body, &receipt, &fixture.client.pinned_pubkey).unwrap();
    let wrong = SigningKey::generate(&mut rand_core::OsRng);
    assert!(verify_receipt(&receipt, &hex::encode(wrong.verifying_key().to_bytes())).is_err());
    for change in 0..8 {
        let mut altered = receipt.clone();
        match change {
            0 => altered.receipt.agent_id = "host-b".into(),
            1 => altered.receipt.key_id = "other".into(),
            2 => altered.receipt.kind = "backup".into(),
            3 => altered.receipt.size_bytes += 1,
            4 => altered.receipt.received_at_ms += 1,
            5 => altered.receipt.retention_until_ms += 1,
            6 => altered.receipt.sha256 = sha256(b"other"),
            _ => altered.receipt.format = "future".into(),
        }
        assert!(verify_receipt(&altered, &fixture.client.pinned_pubkey).is_err());
    }
    fs::write(&body, b"tamper").unwrap();
    assert!(verify_file(&body, &receipt, &fixture.client.pinned_pubkey).is_err());
}

#[test]
fn client_rejects_redirects_untrusted_transport_and_mismatched_signed_metadata() {
    let mut fixture = Fixture::new();
    let source = fixture.source(b"sample");
    let key = load_key(&fixture.config.signing_key_file).unwrap();
    let wrong_kind = sign(
        Receipt {
            format: FORMAT.into(),
            key_id: "vault-1".into(),
            agent_id: "host-a".into(),
            kind: "backup".into(),
            sha256: sha256(b"sample"),
            size_bytes: 6,
            received_at_ms: 100,
            retention_until_ms: 200,
        },
        &key,
    )
    .unwrap();
    let server = HttpServer::start(Router::new().route(
        "/v1/objects/:hash",
        post(move || {
            let value = wrong_kind.clone();
            async { axum::Json(value) }
        }),
    ));
    fixture.client.endpoint = server.endpoint.clone();
    assert!(upload_file(&fixture.client, &source, "evidence").is_err());
    drop(server);
    let server = HttpServer::start(Router::new().route(
        "/v1/objects/:hash",
        post(|| async {
            (
                axum::http::StatusCode::TEMPORARY_REDIRECT,
                [("Location", "http://127.0.0.1:1/stolen")],
            )
        }),
    ));
    fixture.client.endpoint = server.endpoint.clone();
    assert!(upload_file(&fixture.client, &source, "audit")
        .unwrap_err()
        .to_string()
        .contains("307"));
    fixture.client.allow_http_loopback = false;
    assert!(upload_file(&fixture.client, &source, "audit").is_err());
    fixture.client.allow_http_loopback = true;
    for endpoint in [
        "http://192.0.2.1",
        "http://localhost",
        "https://user:secret@example.com",
        "https://example.com/?token=secret",
    ] {
        fixture.client.endpoint = endpoint.into();
        assert!(upload_file(&fixture.client, &source, "audit").is_err());
    }
    assert!(!format!("{:?}", fixture.client).contains(&fixture.client.upload_token));
    assert!(!format!("{:?}", fixture.config).contains(&fixture.config.admin_token));
}

#[test]
fn server_rejects_ambiguous_tokens_invalid_names_and_bounded_payloads() {
    let mut fixture = Fixture::new();
    let mut bad = fixture.config.clone();
    bad.agent_tokens
        .insert("host-b".into(), bad.agent_tokens["host-a"].clone());
    assert!(router(bad).is_err());
    let mut bad = fixture.config.clone();
    bad.admin_token = bad.agent_tokens["host-a"].clone();
    assert!(router(bad).is_err());
    let mut bad = fixture.config.clone();
    bad.agent_tokens
        .insert("../outside".into(), "separate-token-0123456789".into());
    assert!(router(bad).is_err());
    let mut bad = fixture.config.clone();
    bad.admin_token.clear();
    assert!(router(bad).is_err());
    fixture.config.max_object_bytes = 2;
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    fixture.client.endpoint = server.endpoint.clone();
    assert!(
        upload_file(&fixture.client, &fixture.source(b"large"), "audit")
            .unwrap_err()
            .to_string()
            .contains("413")
    );
    assert!(!fixture.dir.join("host-a").exists());
}

#[cfg(unix)]
#[test]
fn nofollow_private_keys_special_files_mutation_and_remote_tamper_are_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let mut fixture = Fixture::new();
    let source = fixture.source(b"original");
    let link = fixture.dir.join("source-link");
    symlink(&source, &link).unwrap();
    assert!(read_bounded(&link, 100).is_err());
    let fifo = fixture.dir.join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(read_bounded(&fifo, 100).is_err());
    assert!(read_bounded_with_check(&source, 100, || {
        fs::write(&source, b"different-length").unwrap();
    })
    .is_err());
    let mut bad = fixture.config.clone();
    let key_link = fixture.dir.join("key-link");
    symlink(&fixture.config.signing_key_file, &key_link).unwrap();
    bad.signing_key_file = key_link;
    assert!(router(bad).is_err());
    fs::set_permissions(
        &fixture.config.signing_key_file,
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(router(fixture.config.clone()).is_err());
    fs::set_permissions(
        &fixture.config.signing_key_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let hard = fixture.dir.join("key-hard");
    fs::hard_link(&fixture.config.signing_key_file, &hard).unwrap();
    assert!(router(fixture.config.clone()).is_err());
    fs::remove_file(hard).unwrap();
    let server = HttpServer::start(router(fixture.config.clone()).unwrap());
    fixture.client.endpoint = server.endpoint.clone();
    let receipt = upload_file(&fixture.client, &source, "backup").unwrap();
    let object = fixture
        .dir
        .join("host-a")
        .join(format!("{}.blob", receipt.receipt.sha256));
    fs::write(&object, b"disk administrator tamper").unwrap();
    assert!(fetch_file(
        &fixture.client,
        "host-a",
        &receipt.receipt.sha256,
        &fixture.dir.join("bad-restore")
    )
    .is_err());
    assert!(!fixture.dir.join("bad-restore").exists());
}
