use super::*;
use argos_common::{FileAction, FileEvent};
use argos_storage::{EvidenceBundle, EvidencePage, FileEventRow, ResponseAudit, ResponseAuditRow};
use serde_json::{json, Value};
use std::io::{Read, Write};

fn page<T>(rows: Vec<T>) -> EvidencePage<T> {
    EvidencePage {
        total_rows: rows.len() as u64,
        truncated: false,
        rows,
    }
}

fn bundle() -> EvidenceBundle {
    EvidenceBundle {
        from_ms: 1000,
        to_ms: 2000,
        pid: Some(42),
        files: page(vec![FileEventRow {
            id: 7,
            event: FileEvent {
                timestamp_ms: 1500,
                pid: 42,
                path: "/data/actual".into(),
                action: FileAction::Modify,
                size: None,
                entropy: None,
                content: None,
                process: None,
            },
        }]),
        detections: page(vec![]),
        processes: page(vec![]),
    }
}

fn response_page() -> EvidencePage<ResponseAuditRow> {
    page(vec![ResponseAuditRow {
        id: 7,
        result: ResponseAudit {
            timestamp_ms: 1600,
            pid: 42,
            start_time_ticks: Some(100),
            boot_id: Some("boot".into()),
            score: 90.0,
            action: "kill_process_instance".into(),
            outcome: "observed_threshold".into(),
            error: None,
        },
    }])
}

fn answer() -> Value {
    json!({"facts":[{"text":"파일 변경이 관측되었습니다.","evidence":[{
        "kind":"files","id":7,"host":"local","timestamp_ms":1500}],"absence_claim":false}],
        "inferences":[],"unknowns":[{"text":"차단 성공 여부는 추가 확인이 필요합니다.","evidence":[],"absence_claim":false}]})
}

/// 실제 HTTP 요청/응답을 사용하되 모델이나 외부 네트워크에는 접근하지 않는다.
fn mock(
    provider: &str,
    model_answer: Value,
    status: u16,
) -> (ThreatExplainer, std::thread::JoinHandle<Value>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/test", listener.local_addr().unwrap());
    let provider_name = provider.to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut data = Vec::new();
        let mut buffer = [0; 4096];
        let end = loop {
            let n = stream.read(&mut buffer).unwrap();
            assert!(n > 0);
            data.extend_from_slice(&buffer[..n]);
            if let Some(end) = data.windows(4).position(|p| p == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&data[..end]);
                let length: usize = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .unwrap()
                    .parse()
                    .unwrap();
                if data.len() >= end + 4 + length {
                    break end;
                }
            }
        };
        let headers = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
        let request: Value = serde_json::from_slice(&data[end + 4..]).unwrap();
        let content = model_answer
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| model_answer.to_string());
        let body = if provider_name == "ollama" {
            assert!(!headers.contains("authorization:"));
            assert_eq!(request["stream"], false);
            json!({"message":{"role":"assistant","content":content},"done":true})
        } else {
            assert!(headers.contains("x-api-key: test-key"));
            assert!(headers.contains("anthropic-version: 2023-06-01"));
            json!({"content":[{"type":"text","text":content}]})
        }
        .to_string();
        write!(stream,"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        request
    });
    let explainer = ThreatExplainer {
        api_key: if provider == "anthropic" {
            "test-key".into()
        } else {
            String::new()
        },
        model: "mock-model".into(),
        provider: provider.into(),
        endpoint,
        client: reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    };
    (explainer, server)
}

#[test]
fn both_providers_validate_and_render_citations_with_coverage() {
    for provider in ["anthropic", "ollama"] {
        let (explainer, server) = mock(provider, answer(), 200);
        let rendered = explainer
            .ask_investigation("상태?", &bundle(), &response_page())
            .unwrap();
        assert!(rendered.contains("확인된 사실 (AI 분류)"));
        assert!(rendered.contains("[files.id:7@local]"));
        assert!(rendered.contains("1000~2000ms"));
        assert!(rendered.contains("의미적 정확성은 자동 검증하지 못"));
        let request = server.join().unwrap();
        let prompt = if provider == "ollama" {
            &request["messages"][1]["content"]
        } else {
            &request["messages"][0]["content"]
        };
        assert!(prompt.as_str().unwrap().contains("allowed_citations"));
        assert!(prompt.as_str().unwrap().contains("observed_threshold"));
    }
}

#[test]
fn both_providers_reject_unknown_ids_wrong_kinds_hosts_and_timestamps() {
    for provider in ["anthropic", "ollama"] {
        for (field, value) in [
            ("id", json!(99)),
            ("kind", json!("detections")),
            ("host", json!("other-host")),
            ("timestamp_ms", json!(900)),
            ("timestamp_ms", Value::Null),
        ] {
            let mut reply = answer();
            reply["facts"][0]["evidence"][0][field] = value;
            let (explainer, server) = mock(provider, reply, 200);
            assert!(matches!(
                explainer.ask_investigation("상태?", &bundle(), &response_page()),
                Err(BrainError::Validation(_))
            ));
            server.join().unwrap();
        }
    }
}

#[test]
fn incomplete_query_is_always_qualified_and_absence_facts_rejected() {
    let mut evidence = bundle();
    evidence.files.total_rows = 9000;
    evidence.files.truncated = true;
    for provider in ["anthropic", "ollama"] {
        let (explainer, server) = mock(provider, answer(), 200);
        let output = explainer
            .ask_investigation("공격이 없나?", &evidence, &response_page())
            .unwrap();
        assert!(output.contains("1/9000건"));
        assert!(output.contains("일부 근거만 조회"));
        assert!(output.contains("위협 부재를 확인할 수 없습니다"));
        server.join().unwrap();
        let mut reply = answer();
        reply["facts"][0]["text"] = json!("위협이 전혀 없습니다.");
        reply["facts"][0]["absence_claim"] = json!(true);
        let (explainer, server) = mock(provider, reply, 200);
        assert!(matches!(
            explainer.ask_investigation("공격이 없나?", &evidence, &response_page()),
            Err(BrainError::Validation(_))
        ));
        server.join().unwrap();
    }
}

#[test]
fn invalid_inputs_cannot_supply_out_of_scope_evidence() {
    let mut evidence = bundle();
    evidence.files.rows[0].event.timestamp_ms = 999;
    assert!(Catalog::evidence(&evidence, Some(&response_page())).is_err());
    evidence.files.rows[0].event.timestamp_ms = 1500;
    evidence.files.rows[0].event.pid = 43;
    assert!(Catalog::evidence(&evidence, Some(&response_page())).is_err());
    evidence.files.rows[0].event.pid = 42;
    evidence.files.total_rows = 900;
    assert!(Catalog::evidence(&evidence, Some(&response_page())).is_err());
    let mut responses = response_page();
    responses.rows[0].result.timestamp_ms = 2001;
    assert!(Catalog::evidence(&bundle(), Some(&responses)).is_err());
}

#[test]
fn schema_enforced_and_provider_errors_not_echoed() {
    for provider in ["anthropic", "ollama"] {
        for reply in [
            json!("무근거 자유 형식"),
            json!({"facts":[],"inferences":[],"unknowns":[],"execute":"kill"}),
        ] {
            let (explainer, server) = mock(provider, reply, 200);
            assert!(matches!(
                explainer.ask_evidence("상태?", &bundle()),
                Err(BrainError::Validation(_))
            ));
            server.join().unwrap();
        }
        let (explainer, server) = mock(provider, json!("secret-token-echo"), 429);
        let error = explainer.ask_evidence("상태?", &bundle()).unwrap_err();
        assert!(matches!(error, BrainError::Api { status: 429, .. }));
        assert!(!error.to_string().contains("secret-token-echo"));
        server.join().unwrap();
    }
}

#[test]
fn duplicate_ids_per_kind_rejected_but_cross_kind_ids_are_distinct() {
    let mut evidence = bundle();
    evidence.files.rows.push(evidence.files.rows[0].clone());
    evidence.files.total_rows = 2;
    assert!(Catalog::evidence(&evidence, None).is_err());
    let catalog = Catalog::evidence(&bundle(), Some(&response_page())).unwrap();
    let mut reply = answer();
    reply["facts"][0]["evidence"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind":"responses","id":7,"host":"local","timestamp_ms":1600}));
    assert!(catalog
        .validate_render(&reply.to_string())
        .unwrap()
        .contains("responses.id:7@local"));
}

#[test]
fn claims_require_citations_and_legacy_context_cannot_be_confirmed_fact() {
    let catalog = Catalog::evidence(&bundle(), None).unwrap();
    let mut reply = answer();
    reply["facts"][0]["evidence"] = json!([]);
    assert!(catalog.validate_render(&reply.to_string()).is_err());
    reply["facts"][0]["evidence"] =
        json!([{"kind":"context","id":1,"host":"local","timestamp_ms":null}]);
    assert!(Catalog::legacy()
        .validate_render(&reply.to_string())
        .is_err());
    reply["inferences"] = reply["facts"].take();
    reply["facts"] = json!([]);
    assert!(Catalog::legacy()
        .validate_render(&reply.to_string())
        .unwrap()
        .contains("DB ID·선택 기간 미확인"));
}

#[test]
fn oversized_response_is_rejected() {
    let (explainer, server) = mock(
        "ollama",
        json!("x".repeat(MAX_RESPONSE_BYTES as usize + 1)),
        200,
    );
    assert!(matches!(
        explainer.ask_evidence("상태?", &bundle()),
        Err(BrainError::SizeLimit(_))
    ));
    // 클라이언트가 크기 헤더를 보고 즉시 닫으면 서버 쓰기가 BrokenPipe일 수 있다.
    let _ = server.join();
}

#[test]
fn oversized_request_fails_before_network_access() {
    let config = AiConfig {
        provider: "ollama".into(),
        model: "test".into(),
        endpoint: "http://127.0.0.1:1/api/chat".into(),
        ..AiConfig::default()
    };
    let explainer = ThreatExplainer::from_config(&config).unwrap();
    assert!(matches!(
        explainer.ask_evidence(&"x".repeat(MAX_REQUEST_BYTES), &bundle()),
        Err(BrainError::SizeLimit(_))
    ));
}

#[test]
fn absence_is_allowed_only_as_unknown_and_remains_qualified() {
    let catalog = Catalog::evidence(&bundle(), Some(&response_page())).unwrap();
    let reply = json!({"facts":[],"inferences":[],"unknowns":[{
        "text":"제공된 기록만으로 위협이 없다고 결론 내릴 수 없습니다.","evidence":[],"absence_claim":true}]});
    assert!(catalog
        .validate_render(&reply.to_string())
        .unwrap()
        .contains("위협 부재는 확인할 수 없습니다"));
}
