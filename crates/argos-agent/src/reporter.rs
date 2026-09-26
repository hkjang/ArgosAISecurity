//! 영속 전송 대기열 재시도와 주기적 생존 신호. 네트워크 I/O는 전용 스레드에서 실행한다.

use argos_common::config::CentralConfig;
use argos_storage::{EventStore, OutboxEntry};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, SyncSender},
    Arc,
};
use std::time::{Duration, Instant};

pub struct Reporter {
    agent_id: String,
    wake: SyncSender<()>,
    sensor_healthy: Arc<AtomicBool>,
}

impl Reporter {
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
    /// 데이터는 이미 SQLite에 있다. 메모리 신호는 하나로 합쳐도 유실되지 않는다.
    pub fn notify(&self) {
        let _ = self.wake.try_send(());
    }
    pub fn set_sensor_healthy(&self, healthy: bool) {
        self.sensor_healthy.store(healthy, Ordering::Relaxed);
        self.notify();
    }
}

#[derive(Clone, Copy)]
struct Timing {
    poll: Duration,
    retry: Duration,
    max_retry: Duration,
    heartbeat: Duration,
    request: Duration,
}
impl Default for Timing {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(1),
            retry: Duration::from_secs(1),
            max_retry: Duration::from_secs(60),
            heartbeat: Duration::from_secs(30),
            request: Duration::from_secs(5),
        }
    }
}

/// 탐지는 insert_detection_with_outbox로 먼저 저장한 뒤 notify한다.
pub fn spawn(
    config: &CentralConfig,
    db_path: &Path,
) -> Result<Option<Reporter>, Box<dyn std::error::Error>> {
    spawn_with_timing(config, db_path, Timing::default())
}

fn spawn_with_timing(
    config: &CentralConfig,
    db_path: &Path,
    timing: Timing,
) -> Result<Option<Reporter>, Box<dyn std::error::Error>> {
    if config.url.is_empty() {
        return Ok(None);
    }
    let url = config.url.trim_end_matches('/').to_string();
    let token = config.token.clone();
    let agent_id = if config.agent_id.is_empty() {
        hostname()
    } else {
        config.agent_id.clone()
    };
    let store = EventStore::open(db_path)?;
    let (tx, rx) = mpsc::sync_channel(1);
    let sensor_healthy = Arc::new(AtomicBool::new(true));
    let worker_health = sensor_healthy.clone();
    let worker_id = agent_id.clone();
    std::thread::Builder::new()
        .name("argos-reporter".into())
        .spawn(move || run(url, token, worker_id, store, rx, worker_health, timing))?;
    Ok(Some(Reporter {
        agent_id,
        wake: tx,
        sensor_healthy,
    }))
}

fn run(
    url: String,
    token: String,
    agent_id: String,
    store: EventStore,
    rx: mpsc::Receiver<()>,
    healthy: Arc<AtomicBool>,
    timing: Timing,
) {
    let client = match reqwest::blocking::Client::builder()
        .timeout(timing.request)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(%error, "중앙 보고 클라이언트 시작 실패 — 대기열 보존");
            return;
        }
    };
    let mut registered = false;
    let mut retry = timing.retry;
    let mut next_attempt = Instant::now();
    let mut next_heartbeat = Instant::now();
    let mut last_health = true;
    loop {
        if Instant::now() >= next_attempt {
            let result = (|| -> Result<(), Box<dyn std::error::Error>> {
                if !registered {
                    post(
                        &client,
                        &url,
                        "/api/v1/agents/register",
                        &token,
                        &serde_json::json!({"agent_id": agent_id, "hostname": hostname(), "tags": Vec::<String>::new()}),
                    )?;
                    registered = true;
                }
                let current_health = healthy.load(Ordering::Relaxed);
                if Instant::now() >= next_heartbeat || current_health != last_health {
                    let stats = store.outbox_stats(&agent_id)?;
                    post(
                        &client,
                        &url,
                        "/api/v1/agents/heartbeat",
                        &token,
                        &serde_json::json!({
                            "agent_id": agent_id, "sensor_healthy": current_health,
                            "outbox_pending": stats.pending, "failed_attempts": stats.failed_attempts,
                        }),
                    )?;
                    next_heartbeat = Instant::now() + timing.heartbeat;
                    last_health = current_health;
                }
                // 1회 하나씩 처리해 긴 적체 중에도 생존 신호와 종료 신호를 확인한다.
                if let Some(entry) = store.pending_deliveries(&agent_id, 1)?.into_iter().next() {
                    match post(
                        &client,
                        &url,
                        "/api/v1/detections",
                        &token,
                        &delivery_body(&entry),
                    ) {
                        Ok(()) => store.acknowledge_delivery(&entry.delivery_id, &agent_id)?,
                        Err(error) => {
                            store.record_delivery_failure(
                                &entry.delivery_id,
                                &agent_id,
                                &error.to_string(),
                            )?;
                            return Err(error.into());
                        }
                    }
                }
                Ok(())
            })();
            match result {
                Ok(()) => {
                    retry = timing.retry;
                    next_attempt = Instant::now();
                }
                Err(error) => {
                    tracing::warn!(%error, "중앙 보고 실패 — 디스크 대기열 보존 후 재시도");
                    registered = false;
                    next_attempt = Instant::now() + retry;
                    retry = retry.saturating_mul(2).min(timing.max_retry);
                }
            }
        }
        let pending = store
            .outbox_stats(&agent_id)
            .map(|s| s.pending > 0)
            .unwrap_or(false);
        let wait = if registered && pending && Instant::now() >= next_attempt {
            Duration::from_millis(1)
        } else {
            timing.poll
        };
        match rx.recv_timeout(wait) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn delivery_body(entry: &OutboxEntry) -> serde_json::Value {
    let d = &entry.detection;
    serde_json::json!({"delivery_id": entry.delivery_id, "agent_id": entry.agent_id, "timestamp_ms": d.timestamp_ms,
        "rule": d.rule, "score": d.score, "severity": d.severity.as_str(), "summary": d.summary, "pid": d.pid, "paths": d.paths})
}

fn post(
    client: &reqwest::blocking::Client,
    base: &str,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut req = client.post(format!("{base}{path}")).json(body);
    if !token.is_empty() {
        req = req.bearer_auth(token);
    }
    let status = req.send()?.status();
    // 리다이렉트는 수집 확인이 아니다. 3xx를 성공으로 취급해 대기열을 지우지 않는다.
    if !status.is_success() {
        return Err(format!("중앙 서버 응답 HTTP {}", status.as_u16()).into());
    }
    Ok(())
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use argos_common::{Detection, Severity};
    use std::{
        collections::HashSet,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::Mutex,
    };

    fn read_request(stream: &mut TcpStream) -> (String, serde_json::Value) {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 2048];
        let (header_end, length) = loop {
            let n = stream.read(&mut buffer).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buffer[..n]);
            if let Some(offset) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..offset]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                break (offset + 4, length);
            }
        };
        while bytes.len() < header_end + length {
            let n = stream.read(&mut buffer).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buffer[..n]);
        }
        (
            String::from_utf8_lossy(&bytes[..header_end]).into_owned(),
            serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap(),
        )
    }

    #[test]
    fn retries_registration_and_lost_ack_with_stable_id_and_heartbeats_when_idle() {
        let dir = std::env::temp_dir().join(format!("argos-reporter-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("events.db");
        let store = EventStore::open(&path).unwrap();
        store
            .insert_detection_with_outbox(
                &Detection {
                    timestamp_ms: 1,
                    rule: "test".into(),
                    score: 90.0,
                    severity: Severity::Critical,
                    summary: "test".into(),
                    pid: 42,
                    paths: vec![],
                },
                "agent-a",
            )
            .unwrap();
        // 시작 전 저장된 대기열은 재시작을 거쳐도 notify 없이 자동 전송된다.
        drop(store);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let counters = Arc::new(Mutex::new((
            0usize,
            0usize,
            0usize,
            HashSet::<String>::new(),
        )));
        let observed = counters.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let server = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                };
                let (headers, body) = read_request(&mut stream);
                assert!(headers
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-token"));
                let mut state = observed.lock().unwrap();
                let status = if headers.starts_with("POST /api/v1/agents/register ") {
                    state.0 += 1;
                    match state.0 {
                        1 => 503,
                        2 => 302,
                        _ => 200,
                    }
                } else if headers.starts_with("POST /api/v1/agents/heartbeat ") {
                    state.1 += 1;
                    200
                } else {
                    state.2 += 1;
                    state
                        .3
                        .insert(body["delivery_id"].as_str().unwrap().to_string());
                    if state.2 == 1 {
                        continue;
                    } // 원격 저장 뒤 ACK가 사라진 상황.
                    200
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            }
        });
        let config = CentralConfig {
            url: format!("http://{address}"),
            token: "test-token".into(),
            agent_id: "agent-a".into(),
        };
        let timing = Timing {
            poll: Duration::from_millis(5),
            retry: Duration::from_millis(5),
            max_retry: Duration::from_millis(20),
            heartbeat: Duration::from_millis(20),
            request: Duration::from_millis(200),
        };
        let reporter = spawn_with_timing(&config, &path, timing).unwrap().unwrap();
        let store = EventStore::open(&path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let state = counters.lock().unwrap();
            if state.1 >= 3 && store.outbox_stats("agent-a").unwrap().pending == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "보고 재시도 제한 시간 초과");
            drop(state);
            std::thread::sleep(Duration::from_millis(5));
        }
        let state = counters.lock().unwrap();
        assert!(state.0 >= 4);
        assert_eq!(state.2, 2);
        assert_eq!(state.3.len(), 1);
        drop(state);
        assert_eq!(store.outbox_stats("agent-a").unwrap().failed_attempts, 1);
        drop(reporter);
        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
}
