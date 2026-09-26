//! /proc 폴링으로 프로세스 생성과 관측 가능한 실행 변경을 추적한다.
//!
//! PID + 시작 clock ticks + boot_id가 프로세스 식별자다. 첫 스캔은 베이스라인으로
//! 저장한다. 폴링 사이에 끝난 프로세스나 같은 실행 파일/인자로 재실행한 exec는 놓칠 수 있다.

use crate::health::{LivenessGuard, SensorHealth};
use crate::SensorHealthSnapshot;
use argos_common::{now_ms, ProcessEvent};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

pub struct ProcessMonitorHandle {
    stop: Arc<AtomicBool>,
    thread: std::thread::Thread,
    health: SensorHealth,
}

impl ProcessMonitorHandle {
    pub fn health(&self) -> SensorHealthSnapshot {
        self.health.snapshot()
    }
}

impl Drop for ProcessMonitorHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.health.stop();
        self.thread.unpark();
    }
}

pub fn spawn_proc_monitor(
    interval_ms: u64,
    tx: Sender<ProcessEvent>,
) -> io::Result<ProcessMonitorHandle> {
    let health = SensorHealth::default();
    health.start();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = stop.clone();
    let worker_health = health.clone();
    let thread = std::thread::Builder::new()
        .name("argos-procmon".into())
        .spawn(move || run(interval_ms, tx, worker_stop, worker_health))?;
    Ok(ProcessMonitorHandle {
        stop,
        thread: thread.thread().clone(),
        health,
    })
}

fn run(interval_ms: u64, tx: Sender<ProcessEvent>, stop: Arc<AtomicBool>, health: SensorHealth) {
    let _guard = LivenessGuard(health.clone());
    let proc_root = Path::new("/proc");
    let boot_id = read_boot_id(proc_root).ok();
    if boot_id.is_none() {
        health.error();
    }
    let interval = std::time::Duration::from_millis(interval_ms.max(100));
    let mut known = match scan_processes(proc_root, boot_id.as_deref(), &health) {
        Ok(processes) => processes,
        Err(error) => {
            health.error();
            tracing::error!(%error, "프로세스 기준 상태 수집 실패 — 센서 중단");
            return;
        }
    };
    tracing::info!(baseline = known.len(), "프로세스 감시 시작 (/proc 폴링)");
    while !stop.load(Ordering::Acquire) && !tx.is_closed() {
        std::thread::park_timeout(interval);
        if stop.load(Ordering::Acquire) || tx.is_closed() {
            return;
        }
        let current = match scan_processes(proc_root, boot_id.as_deref(), &health) {
            Ok(processes) => processes,
            Err(error) => {
                health.error();
                tracing::error!(%error, "프로세스 스캔 실패 — 센서 중단");
                return;
            }
        };
        for event in changed_processes(&known, &current) {
            if !health.deliver(&tx, event) {
                return;
            }
        }
        known = current;
    }
}

fn read_boot_id(proc_root: &Path) -> io::Result<String> {
    let value = std::fs::read_to_string(proc_root.join("sys/kernel/random/boot_id"))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "boot_id 없음"));
    }
    Ok(value.to_owned())
}

fn scan_processes(
    proc_root: &Path,
    boot_id: Option<&str>,
    health: &SensorHealth,
) -> io::Result<HashMap<u32, ProcessEvent>> {
    let mut processes = HashMap::new();
    for entry in std::fs::read_dir(proc_root)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                health.error();
                continue;
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        match read_process_at(proc_root, pid, boot_id) {
            Ok(event) => {
                processes.insert(pid, event);
            }
            // 수집 도중 종료되거나 PID가 재사용된 경우에는 다음 스캔을 기다린다.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => health.error(),
        }
    }
    Ok(processes)
}

fn changed_processes(
    previous: &HashMap<u32, ProcessEvent>,
    current: &HashMap<u32, ProcessEvent>,
) -> Vec<ProcessEvent> {
    let mut changes = current
        .values()
        .filter(|event| {
            previous.get(&event.pid).map_or(true, |old| {
                old.start_time_ticks != event.start_time_ticks
                    || old.boot_id != event.boot_id
                    || old.exe != event.exe
                    || old.comm != event.comm
                    || old.cmdline != event.cmdline
                    || old.uid != event.uid
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    changes.sort_by_key(|event| event.pid);
    changes
}

#[derive(Debug, PartialEq)]
struct ProcessStat {
    ppid: u32,
    comm: String,
    start_time_ticks: u64,
}

/// comm에는 공백과 괄호가 들어갈 수 있으므로 마지막 ')' 이후의 필드만 분리한다.
fn parse_stat(stat: &str, expected_pid: u32) -> io::Result<ProcessStat> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "잘못된 /proc stat 형식");
    let open = stat.find('(').ok_or_else(invalid)?;
    let close = stat
        .rfind(')')
        .filter(|&close| close > open)
        .ok_or_else(invalid)?;
    let pid: u32 = stat[..open].trim().parse().map_err(|_| invalid())?;
    if pid != expected_pid {
        return Err(invalid());
    }
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    // 괄호 이후 fields[0]은 stat의 3번(state), fields[19]는 22번(starttime).
    let ppid = fields
        .get(1)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    let start_time_ticks = fields
        .get(19)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    Ok(ProcessStat {
        ppid,
        comm: stat[open + 1..close].to_owned(),
        start_time_ticks,
    })
}

fn parse_uid(status: &str) -> io::Result<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|value| value.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "프로세스 유효 UID 없음"))
}

/// 수집 시점의 프로세스 정보를 읽는다. 종료·접근 거부·신원 변경은 None으로 반환한다.
pub fn read_process(pid: u32) -> Option<ProcessEvent> {
    if pid == 0 {
        return None;
    }
    let proc_root = Path::new("/proc");
    let boot_id = read_boot_id(proc_root).ok();
    read_process_at(proc_root, pid, boot_id.as_deref()).ok()
}

/// 파일 이벤트를 보강하는 완전한 프로세스 맥락. 신원을 확인하지 못하면 정책 예외를 허용하지 않는다.
pub fn read_file_process_context(pid: u32) -> Option<argos_common::FileProcessContext> {
    let process = read_process(pid)?;
    Some(argos_common::FileProcessContext {
        uid: process.uid,
        exe: process.exe?,
        start_time_ticks: process.start_time_ticks?,
        boot_id: process.boot_id?,
    })
}

fn read_process_at(proc_root: &Path, pid: u32, boot_id: Option<&str>) -> io::Result<ProcessEvent> {
    let dir = proc_root.join(pid.to_string());
    let before = parse_stat(&std::fs::read_to_string(dir.join("stat"))?, pid)?;
    let uid = parse_uid(&std::fs::read_to_string(dir.join("status"))?)?;
    let command = std::fs::read(dir.join("cmdline"))?;
    let cmdline = command
        .split(|&byte| byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let exe = std::fs::read_link(dir.join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let after = parse_stat(&std::fs::read_to_string(dir.join("stat"))?, pid)?;
    let confirmed_exe = std::fs::read_link(dir.join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let confirmed_uid = parse_uid(&std::fs::read_to_string(dir.join("status"))?)?;
    if before.start_time_ticks != after.start_time_ticks
        || before.comm != after.comm
        || exe != confirmed_exe
        || uid != confirmed_uid
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "수집 도중 프로세스 신원 변경",
        ));
    }
    Ok(ProcessEvent {
        timestamp_ms: now_ms(),
        pid,
        ppid: after.ppid,
        uid,
        start_time_ticks: Some(after.start_time_ticks),
        boot_id: boot_id.map(str::to_owned),
        exe,
        comm: after.comm,
        cmdline,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(pid: u32, comm: &str, start: u64) -> String {
        let mut fields = vec!["0".to_owned(); 20];
        fields[0] = "S".into();
        fields[1] = "17".into();
        fields[19] = start.to_string();
        format!("{pid} ({comm}) {}", fields.join(" "))
    }

    fn process(pid: u32, start: u64) -> ProcessEvent {
        ProcessEvent {
            timestamp_ms: 100,
            pid,
            ppid: 1,
            uid: 1000,
            start_time_ticks: Some(start),
            boot_id: Some("boot-a".into()),
            exe: Some("/usr/bin/job".into()),
            comm: "job".into(),
            cmdline: "job --run".into(),
        }
    }

    #[test]
    fn stat_parser_handles_spaces_and_nested_parentheses_in_comm() {
        let value = parse_stat(&stat(42, "job ) (name)", 987654), 42).unwrap();
        assert_eq!(value.comm, "job ) (name)");
        assert_eq!(value.ppid, 17);
        assert_eq!(value.start_time_ticks, 987654);
        assert!(parse_stat(&stat(42, "job", 1), 43).is_err());
        assert!(parse_stat("42 (job) S 1", 42).is_err());
        assert!(parse_stat("42 job S 1", 42).is_err());
    }

    #[test]
    fn effective_uid_is_required_and_never_invented() {
        assert_eq!(parse_uid("Name: job\nUid:\t1000\t0\t0\t0\n").unwrap(), 0);
        assert!(parse_uid("Name: job\n").is_err());
        assert!(parse_uid("Uid: invalid").is_err());
        assert!(parse_uid("Uid: 1000").is_err());
    }

    #[test]
    fn reused_pid_and_changed_exec_are_reported_but_same_process_is_quiet() {
        let baseline = HashMap::from([(42, process(42, 10))]);
        let mut current = baseline.clone();
        current.get_mut(&42).unwrap().timestamp_ms = 200;
        assert!(changed_processes(&baseline, &current).is_empty());
        current.get_mut(&42).unwrap().start_time_ticks = Some(11);
        assert_eq!(changed_processes(&baseline, &current).len(), 1);
        current = baseline.clone();
        current.get_mut(&42).unwrap().exe = Some("/usr/bin/other".into());
        assert_eq!(changed_processes(&baseline, &current).len(), 1);
        current = baseline.clone();
        current.get_mut(&42).unwrap().cmdline = "job --different".into();
        assert_eq!(changed_processes(&baseline, &current).len(), 1);
        current = baseline.clone();
        current.get_mut(&42).unwrap().boot_id = Some("boot-b".into());
        assert_eq!(changed_processes(&baseline, &current).len(), 1);
    }

    #[test]
    fn initial_baseline_does_not_synthesize_start_events() {
        let baseline = HashMap::from([(42, process(42, 10))]);
        assert!(changed_processes(&baseline, &baseline).is_empty());
        let mut next = baseline.clone();
        next.insert(43, process(43, 11));
        assert_eq!(changed_processes(&baseline, &next)[0].pid, 43);
    }

    #[test]
    fn closed_receiver_stops_monitor_even_without_new_processes() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let handle = spawn_proc_monitor(100, tx).unwrap();
        drop(rx);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while handle.health().alive && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!handle.health().alive);
    }

    #[test]
    fn fixture_reads_stable_identity_and_effective_account() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("argos-proc-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let process_dir = root.join("42");
        std::fs::create_dir_all(&process_dir).unwrap();
        std::fs::write(process_dir.join("stat"), stat(42, "job ) worker", 200)).unwrap();
        std::fs::write(process_dir.join("status"), "Uid: 1000 1234 1234 1234\n").unwrap();
        std::fs::write(process_dir.join("cmdline"), b"job\0--run\0").unwrap();
        symlink("/usr/bin/job", process_dir.join("exe")).unwrap();
        let event = read_process_at(&root, 42, Some("boot-test")).unwrap();
        assert_eq!(event.start_time_ticks, Some(200));
        assert_eq!(event.boot_id.as_deref(), Some("boot-test"));
        assert_eq!(event.exe.as_deref(), Some("/usr/bin/job"));
        assert_eq!(event.uid, 1234);
        assert_eq!(event.cmdline, "job --run");
        assert_eq!(event.comm, "job ) worker");
        let _ = std::fs::remove_dir_all(&root);
    }
}
