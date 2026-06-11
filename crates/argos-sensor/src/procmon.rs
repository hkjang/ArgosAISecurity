//! 프로세스 감시: /proc 폴링 기반 exec 추적 (Linux 전용).
//!
//! 주기적으로 /proc의 숫자 디렉터리를 스캔해 새 pid를 찾고
//! comm/cmdline/ppid/uid를 읽어 ProcessEvent로 보고한다.
//! 첫 스캔은 베이스라인으로 삼아 이벤트를 내지 않는다 (기동 시 폭주 방지).
//!
//! 한계: 폴링 간격보다 짧게 살다 죽는 프로세스는 놓친다 — Phase 3 후반
//! eBPF(sched_process_exec tracepoint)로 교체 시 해소된다.

use argos_common::{now_ms, ProcessEvent};
use std::collections::HashSet;
use std::path::Path;
use tokio::sync::mpsc::Sender;

pub fn spawn_proc_monitor(interval_ms: u64, tx: Sender<ProcessEvent>) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("argos-procmon".into())
        .spawn(move || run(interval_ms, tx))?;
    Ok(())
}

fn run(interval_ms: u64, tx: Sender<ProcessEvent>) {
    let interval = std::time::Duration::from_millis(interval_ms.max(100));
    let mut known: HashSet<u32> = scan_pids();
    tracing::info!(baseline = known.len(), "프로세스 감시 시작 (/proc 폴링)");

    loop {
        std::thread::sleep(interval);
        let current = scan_pids();

        for &pid in current.difference(&known) {
            if let Some(event) = read_process(pid) {
                if tx.blocking_send(event).is_err() {
                    return; // 수신측 종료.
                }
            }
        }
        known = current;
    }
}

fn scan_pids() -> HashSet<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return HashSet::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()))
        .collect()
}

fn read_process(pid: u32) -> Option<ProcessEvent> {
    let proc_dir = format!("/proc/{pid}");
    // 스캔과 읽기 사이에 죽었을 수 있다 — 조용히 건너뛴다.
    if !Path::new(&proc_dir).exists() {
        return None;
    }

    let comm = std::fs::read_to_string(format!("{proc_dir}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let cmdline = std::fs::read(format!("{proc_dir}/cmdline"))
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();

    let status = std::fs::read_to_string(format!("{proc_dir}/status")).ok()?;
    let mut ppid = 0u32;
    let mut uid = 0u32;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("PPid:") {
            ppid = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("Uid:") {
            // "Uid: real effective saved fs" — real uid 사용.
            uid = v.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
        }
    }

    Some(ProcessEvent {
        timestamp_ms: now_ms(),
        pid,
        ppid,
        uid,
        comm,
        cmdline,
    })
}
