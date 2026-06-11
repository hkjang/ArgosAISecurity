//! argos CLI: 에이전트 상태·이벤트·위협 조회, 복구, AI 분석 (요건서 14장).
//!
//! 구현: status, events, threats, scan, doctor, restore, explain.
//! isolate/policy/update는 Phase 3+에서 채워진다.

use argos_brain::{DetectionContext, ThreatExplainer};
use argos_common::config::AgentConfig;
use argos_recovery::BackupStore;
use argos_storage::EventStore;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "argos", about = "Argos AI Security CLI", version)]
struct Cli {
    /// 설정 파일 경로
    #[arg(short, long, default_value = "argos.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 에이전트 상태 확인
    Status,
    /// 최근 이벤트 조회
    Events {
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
    },
    /// 탐지된 위협 조회
    Threats {
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
    },
    /// 특정 경로 수동 검사 (엔트로피 기반)
    Scan { path: PathBuf },
    /// 설치 및 환경 진단
    Doctor,
    /// 특정 탐지 이벤트 AI 분석 (ANTHROPIC_API_KEY 필요)
    Explain {
        /// `argos threats`에 표시되는 탐지 ID
        id: i64,
    },
    /// 파일 복구 (백업본에서)
    Restore {
        path: PathBuf,
        /// 이 시각(epoch ms) 이전의 마지막 버전으로 복구. 생략 시 최신 버전.
        #[arg(long)]
        before_ms: Option<u64>,
        /// 버전 목록만 출력하고 복구는 하지 않음
        #[arg(long)]
        list: bool,
    },
    /// 최근 프로세스 실행 이력 조회 (Linux 프로세스 감시)
    Processes {
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
    },
    /// 자연어로 보안 현황 질의 — AI Copilot (ANTHROPIC_API_KEY 필요)
    Ask {
        /// 질문 (예: "지난 1시간 동안 위험한 활동 있었어?")
        question: Vec<String>,
    },
    /// 서버 네트워크 격리 (Linux, root 필요)
    Isolate {
        /// 격리 해제
        #[arg(long)]
        release: bool,
        /// 격리 중에도 허용할 호스트/CIDR (반복 지정 가능)
        #[arg(long)]
        allow: Vec<String>,
    },
    /// 정책 관리: 조회·키 생성·서명·검증
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// 룰·에이전트 업데이트 (Phase 4)
    Update,
}

#[derive(Subcommand)]
enum PolicyAction {
    /// 현재 적용 정책과 서명 검증 상태 표시
    Show,
    /// Ed25519 키쌍 생성 (서명키는 안전한 곳에 보관)
    GenKey,
    /// 정책 파일 서명 → <policy>.sig 생성
    Sign {
        /// 정책 파일 경로
        policy: PathBuf,
        /// 서명키(hex 64자)가 담긴 파일
        #[arg(long)]
        key_file: PathBuf,
    },
    /// 정책 파일 서명 검증 (argos.toml [policy] 설정 사용)
    Verify,
}

fn main() {
    let cli = Cli::parse();
    let config = AgentConfig::load(&cli.config).unwrap_or_default();

    let result = match cli.command {
        Command::Status => cmd_status(&config),
        Command::Events { limit } => cmd_events(&config, limit),
        Command::Threats { limit } => cmd_threats(&config, limit),
        Command::Scan { path } => cmd_scan(&config, &path),
        Command::Doctor => cmd_doctor(&cli.config, &config),
        Command::Explain { id } => cmd_explain(&config, id),
        Command::Restore {
            path,
            before_ms,
            list,
        } => cmd_restore(&config, &path, before_ms, list),
        Command::Processes { limit } => cmd_processes(&config, limit),
        Command::Ask { question } => cmd_ask(&config, &question.join(" ")),
        Command::Isolate { release, allow } => cmd_isolate(&config, release, &allow),
        Command::Policy { action } => cmd_policy(&config, action),
        Command::Update => not_yet("update", "업데이트 채널 (Phase 4)"),
    };

    if let Err(e) = result {
        eprintln!("오류: {e}");
        std::process::exit(1);
    }
}

type CmdResult = Result<(), Box<dyn std::error::Error>>;

fn open_store(config: &AgentConfig) -> Result<EventStore, Box<dyn std::error::Error>> {
    if !config.db_path.exists() {
        return Err(format!(
            "DB가 없습니다: {} — 에이전트(argos-agent)가 실행된 적이 있는지 확인하세요.",
            config.db_path.display()
        )
        .into());
    }
    Ok(EventStore::open_readonly(&config.db_path)?)
}

fn cmd_status(config: &AgentConfig) -> CmdResult {
    println!("Argos Agent 상태");
    println!("  DB 경로     : {}", config.db_path.display());
    println!(
        "  감시 경로   : {}",
        config
            .watch_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  센서        : {:?}", config.sensor);
    println!(
        "  자동 차단   : {}",
        if config.response.auto_block { "활성" } else { "비활성 (탐지 전용)" }
    );
    println!(
        "  백업        : {}",
        if config.backup.enabled {
            format!("활성 ({})", config.backup.dir.display())
        } else {
            "비활성".to_string()
        }
    );
    println!(
        "  중앙 서버   : {}",
        if config.central.url.is_empty() { "미연동 (standalone)" } else { &config.central.url }
    );
    match open_store(config) {
        Ok(store) => {
            println!("  누적 이벤트 : {}", store.event_count()?);
            println!("  누적 탐지   : {}", store.detection_count()?);
        }
        Err(e) => println!("  저장소      : {e}"),
    }
    Ok(())
}

fn cmd_events(config: &AgentConfig, limit: usize) -> CmdResult {
    let store = open_store(config)?;
    let rows = store.recent_events(limit)?;
    if rows.is_empty() {
        println!("기록된 이벤트가 없습니다.");
        return Ok(());
    }
    println!("{:<15} {:<8} {:<8} PATH", "TIMESTAMP(ms)", "PID", "ACTION");
    for (ts, pid, path, action) in rows {
        println!("{ts:<15} {pid:<8} {action:<8} {path}");
    }
    Ok(())
}

fn cmd_threats(config: &AgentConfig, limit: usize) -> CmdResult {
    let store = open_store(config)?;
    let rows = store.recent_detections_with_id(limit)?;
    if rows.is_empty() {
        println!("탐지된 위협이 없습니다.");
        return Ok(());
    }
    println!(
        "{:<6} {:<15} {:<10} {:<6} {:<30} SUMMARY",
        "ID", "TIMESTAMP(ms)", "SEVERITY", "SCORE", "RULE"
    );
    for d in rows {
        println!(
            "{:<6} {:<15} {:<10} {:<6.0} {:<30} {}",
            d.id, d.timestamp_ms, d.severity, d.score, d.rule, d.summary
        );
    }
    println!("\n상세 AI 분석: argos explain <ID>");
    Ok(())
}

fn cmd_explain(config: &AgentConfig, id: i64) -> CmdResult {
    let store = open_store(config)?;
    let Some(detection) = store.detection_by_id(id)? else {
        return Err(format!("탐지 ID {id}를 찾을 수 없습니다. `argos threats`로 ID를 확인하세요.").into());
    };

    // 탐지 전 윈도우 + 후 5초의 이벤트를 근거로 수집.
    let window_ms = (config.detection.window_secs * 1000) as i64;
    let events = store.events_between(
        detection.timestamp_ms - window_ms,
        detection.timestamp_ms + 5000,
        100,
    )?;
    let recent_events: Vec<String> = events
        .into_iter()
        .map(|(ts, pid, action, path)| format!("{ts} pid={pid} {action} {path}"))
        .collect();

    let ctx = DetectionContext {
        rule: detection.rule,
        score: detection.score,
        severity: detection.severity,
        summary: detection.summary,
        timestamp_ms: detection.timestamp_ms as u64,
        pid: detection.pid,
        paths: detection.paths,
        recent_events,
    };

    eprintln!("AI 분석 중... (모델 호출)");
    let explainer = ThreatExplainer::from_env()?;
    let analysis = explainer.explain(&ctx)?;
    println!("{analysis}");
    Ok(())
}

fn cmd_restore(
    config: &AgentConfig,
    path: &PathBuf,
    before_ms: Option<u64>,
    list: bool,
) -> CmdResult {
    if !config.backup.enabled {
        return Err("백업이 비활성화되어 있습니다 (argos.toml [backup] enabled).".into());
    }
    let store = BackupStore::open(&config.backup.dir, config.backup.max_file_bytes)?;

    // 에이전트가 기록한 경로 표기와 맞추기 위해 가능하면 정규화한다.
    let lookup = path.canonicalize().unwrap_or_else(|_| path.clone());

    if list {
        let versions = store.versions(&lookup)?;
        if versions.is_empty() {
            println!("백업 버전이 없습니다: {}", lookup.display());
            return Ok(());
        }
        println!("{:<6} {:<15} {:<10} HASH", "ID", "TIMESTAMP(ms)", "SIZE");
        for v in versions {
            println!("{:<6} {:<15} {:<10} {}", v.id, v.timestamp_ms, v.size, &v.hash[..16]);
        }
        return Ok(());
    }

    let version = store.restore(&lookup, before_ms)?;
    println!(
        "복구 완료: {} ← 버전 {} (시각 {}ms, 해시 {} 검증됨)",
        lookup.display(),
        version.id,
        version.timestamp_ms,
        &version.hash[..16]
    );
    Ok(())
}

fn cmd_processes(config: &AgentConfig, limit: usize) -> CmdResult {
    let store = open_store(config)?;
    let rows = store.recent_processes(limit)?;
    if rows.is_empty() {
        println!("기록된 프로세스 이벤트가 없습니다 (프로세스 감시는 Linux 전용).");
        return Ok(());
    }
    println!(
        "{:<15} {:<8} {:<8} {:<6} {:<16} CMDLINE",
        "TIMESTAMP(ms)", "PID", "PPID", "UID", "COMM"
    );
    for (ts, pid, ppid, uid, comm, cmdline) in rows {
        println!("{ts:<15} {pid:<8} {ppid:<8} {uid:<6} {comm:<16} {cmdline}");
    }
    Ok(())
}

fn cmd_ask(config: &AgentConfig, question: &str) -> CmdResult {
    if question.trim().is_empty() {
        return Err("질문을 입력하세요. 예: argos ask \"지난 1시간 동안 위험한 활동 있었어?\"".into());
    }
    let store = open_store(config)?;

    let status_summary = format!(
        "감시 경로: {} / 자동 차단: {} / 누적 이벤트: {} / 누적 탐지: {}",
        config
            .watch_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        if config.response.auto_block { "활성" } else { "비활성" },
        store.event_count()?,
        store.detection_count()?,
    );
    let recent_detections = store
        .recent_detections_with_id(30)?
        .into_iter()
        .map(|d| {
            format!(
                "[{}] ts={} severity={} score={:.0} rule={} pid={} {}",
                d.id, d.timestamp_ms, d.severity, d.score, d.rule, d.pid, d.summary
            )
        })
        .collect();
    let recent_events = store
        .recent_events(80)?
        .into_iter()
        .map(|(ts, pid, path, action)| format!("ts={ts} pid={pid} {action} {path}"))
        .collect();
    let recent_processes = store
        .recent_processes(40)?
        .into_iter()
        .map(|(ts, pid, ppid, uid, comm, cmdline)| {
            format!("ts={ts} pid={pid} ppid={ppid} uid={uid} {comm} :: {cmdline}")
        })
        .collect();

    let ctx = argos_brain::CopilotContext {
        status_summary,
        recent_detections,
        recent_events,
        recent_processes,
    };

    eprintln!("AI 분석 중... (모델 호출)");
    let explainer = ThreatExplainer::from_env()?;
    println!("{}", explainer.ask(question, &ctx)?);
    Ok(())
}

fn cmd_isolate(config: &AgentConfig, release: bool, allow: &[String]) -> CmdResult {
    use argos_response::isolate;
    if release {
        isolate::release_isolation()?;
        println!("네트워크 격리를 해제했습니다.");
        return Ok(());
    }
    // 중앙 서버 호스트는 항상 허용 목록에 포함시킨다 (격리 중에도 보고 유지).
    let mut allow_hosts: Vec<String> = allow.to_vec();
    if !config.central.url.is_empty() {
        if let Some(host) = extract_host(&config.central.url) {
            if !allow_hosts.contains(&host) {
                allow_hosts.push(host);
            }
        }
    }
    println!("서버를 격리합니다 — loopback/기존 연결/허용 호스트({})만 통과", allow_hosts.len());
    isolate::isolate_host(&allow_hosts)?;
    println!("격리 적용 완료. 해제: argos isolate --release");
    Ok(())
}

fn extract_host(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host_port = rest.split('/').next()?;
    let host = host_port.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn cmd_policy(config: &AgentConfig, action: PolicyAction) -> CmdResult {
    match action {
        PolicyAction::GenKey => {
            let (secret, public) = argos_policy::gen_keypair();
            println!("서명키(비밀, 관리 머신에만 보관):\n{secret}\n");
            println!("검증키(공개, argos.toml [policy] pubkey에 설정):\n{public}");
            Ok(())
        }
        PolicyAction::Sign { policy, key_file } => {
            let secret = std::fs::read_to_string(&key_file)?;
            let sig_path = argos_policy::sign_file(&policy, secret.trim())?;
            println!("서명 완료: {}", sig_path.display());
            Ok(())
        }
        PolicyAction::Verify => {
            if !config.policy.is_enabled() {
                return Err("argos.toml에 [policy] path/pubkey가 설정되어 있지 않습니다.".into());
            }
            argos_policy::verify_file(&config.policy.path, &config.policy.pubkey)?;
            println!("서명 검증 성공: {}", config.policy.path.display());
            Ok(())
        }
        PolicyAction::Show => {
            if !config.policy.is_enabled() {
                println!("서명 정책 미사용 — argos.toml의 [detection]/[response]가 그대로 적용됩니다.");
            } else {
                match argos_policy::load_verified(&config.policy.path, &config.policy.pubkey) {
                    Ok(p) => {
                        println!("정책 파일   : {} (서명 검증 OK)", config.policy.path.display());
                        println!("정책 버전   : {}", p.version);
                        println!("탐지 설정   : {:?}", p.detection);
                        println!("대응 설정   : {:?}", p.response);
                        return Ok(());
                    }
                    Err(e) => {
                        println!("정책 파일   : {} — 검증 실패: {e}", config.policy.path.display());
                        println!("(에이전트는 이 정책을 적용하지 않습니다)");
                    }
                }
            }
            println!("\n[현재 유효 탐지 설정]\n{:?}", config.detection);
            println!("\n[현재 유효 대응 설정]\n{:?}", config.response);
            Ok(())
        }
    }
}

/// 경로 하위 파일들의 엔트로피를 검사해 암호화 의심 파일을 나열한다.
fn cmd_scan(config: &AgentConfig, path: &PathBuf) -> CmdResult {
    if !path.exists() {
        return Err(format!("경로가 없습니다: {}", path.display()).into());
    }
    let threshold = config.detection.entropy_threshold;
    let sample = config.detection.entropy_sample_bytes;
    let mut scanned = 0usize;
    let mut suspicious = 0usize;
    let mut stack = vec![path.clone()];
    while let Some(dir) = stack.pop() {
        if dir.is_file() {
            scan_one(&dir, threshold, sample, &mut scanned, &mut suspicious);
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                scan_one(&p, threshold, sample, &mut scanned, &mut suspicious);
            }
        }
    }
    println!("검사 완료: 파일 {scanned}개, 고엔트로피(>= {threshold}) {suspicious}개");
    Ok(())
}

fn scan_one(path: &PathBuf, threshold: f64, sample: usize, scanned: &mut usize, suspicious: &mut usize) {
    *scanned += 1;
    if let Ok(e) = argos_detect::file_entropy(path, sample) {
        if e >= threshold {
            *suspicious += 1;
            println!("의심: {} (entropy {:.2})", path.display(), e);
        }
    }
}

fn cmd_doctor(config_path: &PathBuf, config: &AgentConfig) -> CmdResult {
    println!("Argos 환경 진단");
    println!("  OS               : {}", std::env::consts::OS);
    check("설정 파일", config_path.exists(), &config_path.display().to_string());
    check("DB 파일", config.db_path.exists(), &config.db_path.display().to_string());
    if config.backup.enabled {
        check("백업 디렉터리", config.backup.dir.exists(), &config.backup.dir.display().to_string());
    }
    for p in &config.watch_paths {
        check("감시 경로", p.exists(), &p.display().to_string());
    }
    check(
        "ANTHROPIC_API_KEY",
        std::env::var("ANTHROPIC_API_KEY").map(|v| !v.is_empty()).unwrap_or(false),
        "argos explain에 필요",
    );
    if std::env::consts::OS != "linux" {
        println!("  [참고] 비 Linux 환경 — 자동 차단·fanotify 미지원 (개발 모드)");
    }
    Ok(())
}

fn check(name: &str, ok: bool, detail: &str) {
    println!("  {:<16} : {} ({detail})", name, if ok { "OK" } else { "없음" });
}

fn not_yet(cmd: &str, feature: &str) -> CmdResult {
    println!("`argos {cmd}`는 아직 구현되지 않았습니다 — 로드맵: {feature}");
    Ok(())
}
