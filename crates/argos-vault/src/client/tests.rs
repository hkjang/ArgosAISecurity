use super::*;
use std::{
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

const SECRET: &str = "remote-token-private-endpoint-secret";

#[test]
fn tls_trust_list_is_bounded_explicit_and_never_enabled_over_http() {
    let mut configured = config("https://127.0.0.1:443".into());
    assert_eq!(tls_ca_sha256(&configured).unwrap(), None);
    for pem in [
        String::new(),
        "not a PEM certificate".into(),
        "x".repeat(65537),
    ] {
        configured.tls_ca_pem = Some(pem);
        assert!(validated_endpoint(&configured).is_err());
        assert!(tls_ca_sha256(&configured).is_err());
    }
    configured.endpoint = "http://127.0.0.1:443".into();
    assert!(validated_endpoint(&configured).is_err());
    assert!(!format!("{configured:?}").contains("not a PEM"));
}

fn config(endpoint: String) -> VaultConfig {
    let key = SigningKey::from_bytes(&[23; 32]);
    VaultConfig {
        endpoint,
        agent_id: "client-test".into(),
        upload_token: SECRET.into(),
        admin_token: SECRET.into(),
        pinned_pubkey: hex::encode(key.verifying_key().to_bytes()),
        allow_http_loopback: true,
        timeout_secs: 1,
        ..Default::default()
    }
}

fn consume_request(socket: &mut TcpStream) {
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let count = socket.read(&mut chunk).unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(split) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..split]).to_ascii_lowercase();
            let size = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map(|value| value.parse::<usize>().unwrap())
                .unwrap_or(0);
            if bytes.len() >= split + 4 + size {
                break;
            }
        }
    }
}

fn server(
    action: impl FnOnce(TcpStream) + Send + 'static,
) -> (VaultConfig, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = config(format!("http://{}", listener.local_addr().unwrap()));
    let handle = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        consume_request(&mut socket);
        action(socket);
    });
    (config, handle)
}

fn respond(mut socket: TcpStream, status: u16, body: &[u8]) {
    write!(socket, "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    socket.write_all(body).unwrap();
}

fn assert_safe(error: Box<dyn std::error::Error + Send + Sync>, code: &str) {
    assert_eq!(error_code(error.as_ref()), code, "{error:?}");
    assert!(!error.to_string().contains(SECRET));
    assert!(!format!("{error:?}").contains(SECRET));
    // URL/본문을 가진 하위 오류를 디버그 로깅으로 우회해 출력할 수도 없어야 한다.
    assert!(error.source().is_none());
}

fn signed(bytes: &[u8]) -> SignedReceipt {
    sign(
        Receipt {
            format: FORMAT.into(),
            key_id: "vault-1".into(),
            agent_id: "client-test".into(),
            kind: "audit".into(),
            sha256: sha256(bytes),
            size_bytes: bytes.len() as u64,
            received_at_ms: 1,
            retention_until_ms: 2,
        },
        &SigningKey::from_bytes(&[23; 32]),
    )
    .unwrap()
}

#[test]
fn http_failure_classes_never_include_remote_body() {
    for (status, code) in [
        (401, "authentication"),
        (403, "authentication"),
        (507, "capacity"),
        (429, "rate_limit"),
        (500, "server_transient"),
        (503, "server_transient"),
        (400, "request_rejected"),
        (409, "request_rejected"),
        (413, "request_rejected"),
        (302, "request_rejected"),
    ] {
        let (config, handle) = server(move |socket| respond(socket, status, SECRET.as_bytes()));
        assert_safe(
            upload_bytes(&config, b"audit".to_vec(), "audit").unwrap_err(),
            code,
        );
        handle.join().unwrap();
    }
}

#[test]
fn request_and_body_timeout_are_classified_without_url_or_token() {
    for headers_first in [false, true] {
        let (config, handle) = server(move |mut socket| {
            if headers_first {
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: 128\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                socket.flush().unwrap();
            }
            thread::sleep(Duration::from_millis(1250));
        });
        assert_safe(
            upload_bytes(&config, b"audit".to_vec(), "audit").unwrap_err(),
            "timeout",
        );
        handle.join().unwrap();
    }
}

#[test]
fn refused_connection_and_incomplete_response_are_distinct_failures() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let unreachable = config(format!("http://{}", listener.local_addr().unwrap()));
    drop(listener);
    assert_safe(
        upload_bytes(&unreachable, b"audit".to_vec(), "audit").unwrap_err(),
        "connect",
    );

    let (config, handle) = server(|mut socket| {
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{SECRET}"
        )
        .unwrap();
    });
    assert_safe(
        upload_bytes(&config, b"audit".to_vec(), "audit").unwrap_err(),
        "transport",
    );
    handle.join().unwrap();
}

#[test]
fn malformed_oversized_and_forged_receipts_do_not_reflect_fields() {
    let mut forged = signed(b"audit");
    forged.signature_hex = "00".repeat(64);
    let mut unknown_field = serde_json::to_value(signed(b"audit")).unwrap();
    unknown_field[SECRET] = serde_json::json!(SECRET);
    for body in [
        SECRET.as_bytes().to_vec(),
        serde_json::to_vec(&unknown_field).unwrap(),
        serde_json::to_vec(&forged).unwrap(),
        vec![b'a'; MAX_RECEIPT_BYTES + 1],
    ] {
        let (config, handle) = server(move |socket| respond(socket, 200, &body));
        assert_safe(
            upload_bytes(&config, b"audit".to_vec(), "audit").unwrap_err(),
            "response_integrity",
        );
        handle.join().unwrap();
    }
}

#[test]
fn valid_signature_cannot_ack_different_request_and_valid_ack_still_passes() {
    for field in ["agent", "hash", "kind", "size", "key"] {
        let mut receipt = signed(b"audit").receipt;
        match field {
            "agent" => receipt.agent_id = "different-agent".into(),
            "hash" => receipt.sha256 = sha256(b"different-body"),
            "kind" => receipt.kind = "backup".into(),
            "size" => receipt.size_bytes += 1,
            "key" => receipt.key_id = "different-key".into(),
            _ => unreachable!(),
        }
        let receipt = sign(receipt, &SigningKey::from_bytes(&[23; 32])).unwrap();
        let (config, handle) =
            server(move |socket| respond(socket, 200, &serde_json::to_vec(&receipt).unwrap()));
        assert_safe(
            upload_bytes(&config, b"audit".to_vec(), "audit").unwrap_err(),
            "response_integrity",
        );
        handle.join().unwrap();
    }
    let (config, handle) =
        server(|socket| respond(socket, 200, &serde_json::to_vec(&signed(b"audit")).unwrap()));
    assert_eq!(
        upload_bytes(&config, b"audit".to_vec(), "audit").unwrap(),
        signed(b"audit")
    );
    handle.join().unwrap();
}

#[test]
fn invalid_settings_and_missing_snapshot_are_secret_safe() {
    let base = config("http://127.0.0.1:9".into());
    for endpoint in [
        format!("http://{SECRET}@127.0.0.1:9"),
        format!("http://127.0.0.1:9/?token={SECRET}"),
        format!("{SECRET}://\n"),
    ] {
        let mut config = base.clone();
        config.endpoint = endpoint;
        assert_safe(
            upload_bytes(&config, vec![], "audit").unwrap_err(),
            "client_settings",
        );
    }
    let mut config = base.clone();
    config.upload_token = format!("{SECRET}\n");
    assert_safe(
        upload_bytes(&config, vec![], "audit").unwrap_err(),
        "client_settings",
    );
    config = base.clone();
    config.pinned_pubkey = SECRET.into();
    assert_safe(
        upload_bytes(&config, vec![], "audit").unwrap_err(),
        "client_settings",
    );
    assert_safe(
        upload_file(
            &base,
            Path::new("/missing-argos-client-test")
                .join(SECRET)
                .as_path(),
            "audit",
        )
        .unwrap_err(),
        "snapshot_read",
    );
    let unclassified: Box<dyn std::error::Error + Send + Sync> =
        "unclassified local failure".into();
    assert_eq!(error_code(unclassified.as_ref()), "unknown");
}

#[test]
fn read_apis_use_same_secret_safe_failure_mapping() {
    let (config, handle) = server(|socket| respond(socket, 403, SECRET.as_bytes()));
    assert_safe(fetch_usage(&config).unwrap_err(), "authentication");
    handle.join().unwrap();
    let (config, handle) =
        server(|socket| respond(socket, 200, format!("{{\"{SECRET}\":true}}").as_bytes()));
    assert_safe(fetch_usage(&config).unwrap_err(), "response_integrity");
    handle.join().unwrap();
}
