//! argos CLI: 에이전트 상태·이벤트·위협 조회, 복구, AI 분석 (요건서 14장).
//!
//! 구현: status, events, threats, scan, doctor, restore, explain.
//! isolate/policy/update는 Phase 3+에서 채워진다.

mod investigation;
mod reports;

use argos_brain::ThreatExplainer;
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
        /// 이 시각(epoch ms) 이전의 정상 판정 버전으로 복구. 생략 시 최신 정상본.
        #[arg(long)]
        before_ms: Option<u64>,
        /// 버전 목록만 출력하고 복구는 하지 않음
        #[arg(long, conflicts_with_all = ["mark_good", "revoke_good", "preview", "recommend", "version"])]
        list: bool,
        /// 검토한 버전을 정상 복구 지점으로 지정 (해시는 무결성만 검증)
        #[arg(long, requires = "note", conflicts_with_all = ["revoke_good", "preview", "recommend", "version", "before_ms"])]
        mark_good: Option<i64>,
        /// 정상 판정 취소
        #[arg(long, requires = "note", conflicts_with_all = ["preview", "recommend", "version", "before_ms"])]
        revoke_good: Option<i64>,
        /// 정상 판정/취소 근거
        #[arg(long)]
        note: Option<String>,
        /// 별도 새 파일로 복구 미리보기 (원본 유지)
        #[arg(long, requires = "version", conflicts_with_all = ["recommend", "before_ms"])]
        preview: Option<PathBuf>,
        /// 미리볼 버전 ID
        #[arg(long, requires = "preview")]
        version: Option<i64>,
        /// 정상 복구 지점 추천만 표시
        #[arg(long)]
        recommend: bool,
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
        #[arg(long, requires = "to_ms")]
        from_ms: Option<u64>,
        #[arg(long, requires = "from_ms")]
        to_ms: Option<u64>,
        #[arg(long)]
        pid: Option<u32>,
    },
    /// 기간/프로세스별 근거 JSON 조회 (AI 호출 없음)
    Evidence {
        #[arg(long)]
        from_ms: u64,
        #[arg(long)]
        to_ms: u64,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// 로컬 호스트 근거만 조회하는 MCP stdio 서버
    Mcp,
    /// 경로별 정상 복구 지점, 누락, 마지막 복구 시험 결과
    RecoveryStatus {
        /// 정상본을 별도 임시 파일에 복구하고 검증 (원본 유지)
        #[arg(long)]
        test: Option<PathBuf>,
        #[arg(long, requires = "test")]
        before_ms: Option<u64>,
        /// 복구 준비도 HTML 보고서 (새 파일)
        #[arg(long)]
        html: Option<PathBuf>,
    },
    /// 탐지 사건의 기간별 증거와 프로세스 식별자를 시간순으로 조회
    Incident {
        id: i64,
        #[arg(long, default_value_t = 300)]
        window_secs: u64,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
        /// 독립형 HTML 조사 화면 (새 파일)
        #[arg(long)]
        html: Option<PathBuf>,
    },
    /// 설정된 미끼 파일을 새로 생성 (기존 파일 덮어쓰기 금지)
    CanaryInit { path: PathBuf },
    /// 서버 네트워크 격리 (Linux, root 필요)
    Isolate {
        /// 격리 해제
        #[arg(long)]
        release: bool,
        /// 관리 TCP 연결: in:192.0.2.20:22 / out:[2001:db8::10]:443 (반복 가능)
        #[arg(long)]
        allow: Vec<String>,
        /// 적용 전 IPv4/IPv6 방화벽 계획만 출력
        #[arg(long)]
        dry_run: bool,
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
    /// 과거 이벤트에 후보 정책 재생 (조회만 수행, 정책 적용/차단 없음)
    Simulate {
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        from_ms: u64,
        #[arg(long)]
        to_ms: u64,
        #[arg(long, default_value_t = 100_000)]
        max_events: usize,
    },
}

fn main() {
    let cli = Cli::parse();
    let config = match AgentConfig::load(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("설정 오류: {e}");
            std::process::exit(1);
        }
    };

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
            mark_good,
            revoke_good,
            note,
            preview,
            version,
            recommend,
        } => cmd_restore(
            &config,
            &path,
            before_ms,
            list,
            mark_good,
            revoke_good,
            note.as_deref(),
            preview.as_deref(),
            version,
            recommend,
        ),
        Command::Processes { limit } => cmd_processes(&config, limit),
        Command::Ask {
            question,
            from_ms,
            to_ms,
            pid,
        } => cmd_ask(&config, &question.join(" "), from_ms, to_ms, pid),
        Command::Evidence {
            from_ms,
            to_ms,
            pid,
            limit,
        } => (|| {
            let store = open_store(&config)?;
            let query = argos_storage::EvidenceQuery {
                from_ms,
                to_ms,
                pid,
                limit,
            };
            let mut evidence = serde_json::to_value(store.query_evidence(&query)?)?;
            evidence["response_results"] = serde_json::to_value(store.response_results(&query)?)?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
            Ok(())
        })(),
        Command::Mcp => (|| investigation::serve_mcp(&open_store(&config)?))(),
        Command::RecoveryStatus {
            test,
            before_ms,
            html,
        } => cmd_recovery_status(&config, test.as_deref(), before_ms, html.as_deref()),
        Command::Incident {
            id,
            window_secs,
            limit,
            html,
        } => cmd_incident(&config, id, window_secs, limit, html.as_deref()),
        Command::CanaryInit { path } => cmd_canary(&config, &path),
        Command::Isolate {
            release,
            allow,
            dry_run,
        } => cmd_isolate(release, &allow, dry_run),
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
    println!(r"    ___    ____   ______ ____   _____");
    println!(r"   /   |  / __ \ / ____// __ \ / ___/");
    println!(r"  / /| | / /_/ // / __ / / / / \__ \ ");
    println!(r" / ___ |/ _, _// /_/ // /_/ / ___/ / ");
    println!(r"/_/  |_|/_/ |_| \____/ \____/ /____/  AI SECURITY");
    println!();
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
    match std::fs::read(config.db_path.with_extension("health.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    {
        Some(health) => {
            let age =
                argos_common::now_ms().saturating_sub(health["timestamp_ms"].as_u64().unwrap_or(0));
            println!(
                "  생존 신호   : {}ms 전 ({})",
                age,
                if age > 60_000 {
                    "오래됨/감시 중단 가능"
                } else {
                    "최근"
                }
            );
            println!("  보호 지표   : {health}");
        }
        None => println!("  생존 신호   : 미확인 — 위협 없음으로 해석하지 마세요"),
    }
    println!(
        "  자동 차단   : {}",
        if config.response.auto_block {
            "활성"
        } else {
            "비활성 (탐지 전용)"
        }
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
        if config.central.url.is_empty() {
            "미연동 (standalone)"
        } else {
            &config.central.url
        }
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
        return Err(
            format!("탐지 ID {id}를 찾을 수 없습니다. `argos threats`로 ID를 확인하세요.").into(),
        );
    };

    let timestamp = u64::try_from(detection.timestamp_ms)?;
    let window = config
        .detection
        .window_secs
        .checked_mul(1000)
        .ok_or("탐지 시간 범위 초과")?;
    cmd_ask(config, &format!("탐지 ID {}의 원인·영향·오탐 가능성·대응 결과를 근거 ID와 함께 설명해 주세요. 탐지 메타데이터: {}", id, serde_json::to_string(&detection)?), Some(timestamp.saturating_sub(window)), Some(timestamp.saturating_add(5000).min(i64::MAX as u64)), None)
}

#[allow(clippy::too_many_arguments)]
fn cmd_restore(
    config: &AgentConfig,
    path: &PathBuf,
    before_ms: Option<u64>,
    list: bool,
    mark_good: Option<i64>,
    revoke_good: Option<i64>,
    note: Option<&str>,
    preview: Option<&std::path::Path>,
    version_id: Option<i64>,
    recommend: bool,
) -> CmdResult {
    if !config.backup.enabled {
        return Err("백업이 비활성화되어 있습니다 (argos.toml [backup] enabled).".into());
    }
    let store = BackupStore::open(&config.backup.dir, config.backup.max_file_bytes)?;

    // 마지막 경로 성분의 심볼릭 링크를 따라 원치 않는 파일을 덮어쓰지 않는다.
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("복구 대상은 심볼릭 링크일 수 없습니다. 실제 파일 경로를 지정하세요".into());
    }
    let lookup = if path.exists() {
        path.canonicalize()?
    } else {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        parent
            .canonicalize()?
            .join(path.file_name().ok_or("파일 경로가 필요합니다")?)
    };

    if list {
        let versions = store.versions(&lookup)?;
        if versions.is_empty() {
            println!("백업 버전이 없습니다: {}", lookup.display());
            return Ok(());
        }
        println!(
            "{:<6} {:<15} {:<10} {:<12} HASH / 판정 근거",
            "ID", "TIMESTAMP(ms)", "SIZE", "TRUST"
        );
        for v in versions {
            println!(
                "{:<6} {:<15} {:<10} {:<12} {} / {}",
                v.id,
                v.timestamp_ms,
                v.size,
                if v.known_good {
                    "known-good"
                } else {
                    "unverified"
                },
                &v.hash[..16],
                v.trust_note.as_deref().unwrap_or("-")
            );
        }
        return Ok(());
    }

    if let Some(id) = mark_good {
        let v = store.mark_known_good(&lookup, id, note.unwrap_or(""))?;
        println!(
            "정상 복구 지점 지정: 버전 {} (무결성 검증 완료, 정상 판정은 운영자 검토 근거)",
            v.id
        );
        return Ok(());
    }
    if let Some(id) = revoke_good {
        store.revoke_known_good(&lookup, id, note.unwrap_or(""))?;
        println!("정상 판정 취소: 버전 {id}");
        return Ok(());
    }
    if let Some(destination) = preview {
        let v = store.preview(
            &lookup,
            version_id.ok_or("미리보기에는 --version이 필요합니다")?,
            destination,
        )?;
        println!(
            "미리보기 완료: {} ← 버전 {} (정상 판정: {})",
            destination.display(),
            v.id,
            v.known_good
        );
        return Ok(());
    }
    if recommend {
        let v = store.recommend(&lookup, before_ms)?;
        println!(
            "추천 정상 복구 지점: 버전 {} 시각 {}ms 해시 {}",
            v.id, v.timestamp_ms, v.hash
        );
        return Ok(());
    }
    if note.is_some() {
        return Err("--note는 --mark-good/--revoke-good과 함께 사용하세요".into());
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

fn cmd_ask(
    config: &AgentConfig,
    question: &str,
    from_ms: Option<u64>,
    to_ms: Option<u64>,
    pid: Option<u32>,
) -> CmdResult {
    if question.trim().is_empty() {
        return Err("질문을 입력하세요".into());
    }
    let (from_ms, to_ms, source) =
        investigation::time_range(question, from_ms, to_ms, argos_common::now_ms())?;
    let store = open_store(config)?;
    let query = argos_storage::EvidenceQuery {
        from_ms,
        to_ms,
        pid,
        limit: config.ai.evidence_limit,
    };
    let evidence = store.query_evidence(&query)?;
    let responses = store.response_results(&query)?;
    eprintln!(
        "조회: {from_ms}~{to_ms}ms ({source}), 로컬 DB {}, PID {:?}",
        config.db_path.display(),
        pid
    );
    for (name, loaded, total, truncated) in [
        (
            "파일",
            evidence.files.rows.len(),
            evidence.files.total_rows,
            evidence.files.truncated,
        ),
        (
            "탐지",
            evidence.detections.rows.len(),
            evidence.detections.total_rows,
            evidence.detections.truncated,
        ),
        (
            "프로세스",
            evidence.processes.rows.len(),
            evidence.processes.total_rows,
            evidence.processes.truncated,
        ),
    ] {
        eprintln!("{name}: {loaded}/{total}건, 조회 누락: {truncated}");
    }
    eprintln!(
        "대응 결과: {}/{}건, 조회 누락: {}",
        responses.rows.len(),
        responses.total_rows,
        responses.truncated
    );
    let explainer = ThreatExplainer::from_config(&config.ai)?;
    println!(
        "{}",
        explainer.ask_investigation(question, &evidence, &responses)?
    );
    Ok(())
}

fn cmd_recovery_status(
    config: &AgentConfig,
    test: Option<&std::path::Path>,
    before_ms: Option<u64>,
    html: Option<&std::path::Path>,
) -> CmdResult {
    if !config.backup.enabled {
        return Err("백업이 비활성화되어 있습니다".into());
    }
    let store = BackupStore::open(&config.backup.dir, config.backup.max_file_bytes)?;
    if let Some(path) = test {
        let lookup = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let version = store.test_restore(&lookup, before_ms)?;
        println!("원본 유지 복구 시험 성공: 버전 {}", version.id);
    }
    let paths = store.readiness()?;
    let tracked: std::collections::HashSet<_> = paths.iter().map(|p| p.path.as_str()).collect();
    let mut stack = config.watch_paths.clone();
    let mut scanned_files = 0;
    let mut untracked_paths = Vec::new();
    let mut scan_truncated = false;
    let mut visited = 0;
    while let Some(path) = stack.pop() {
        visited += 1;
        if visited > 10_000 {
            scan_truncated = true;
            break;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            scan_truncated = true;
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            match std::fs::read_dir(path) {
                Ok(entries) => {
                    for entry in entries {
                        match entry {
                            Ok(entry) if stack.len() + visited < 10_000 => stack.push(entry.path()),
                            _ => {
                                scan_truncated = true;
                            }
                        }
                    }
                }
                Err(_) => {
                    scan_truncated = true;
                }
            }
        } else if meta.is_file() {
            scanned_files += 1;
            let full = path.canonicalize()?.display().to_string();
            if !tracked.contains(full.as_str()) {
                untracked_paths.push(full);
            }
        }
    }
    let data = serde_json::json!({"generated_at_ms":argos_common::now_ms(),"watch_paths":config.watch_paths,"scanned_files":scanned_files,"untracked_paths":untracked_paths,"scan_truncated":scan_truncated,"paths":paths});
    if let Some(path) = html {
        reports::write_report(path, "recovery", data)?;
        println!("복구 준비도 보고서: {}", path.display());
    } else {
        println!("{}", serde_json::to_string_pretty(&data)?);
    }
    Ok(())
}

fn cmd_incident(
    config: &AgentConfig,
    id: i64,
    window_secs: u64,
    limit: usize,
    html: Option<&std::path::Path>,
) -> CmdResult {
    let store = open_store(config)?;
    let detection = store.detection_by_id(id)?.ok_or("탐지 ID가 없습니다")?;
    let span = window_secs
        .checked_mul(1000)
        .filter(|v| *v > 0)
        .ok_or("window-secs는 밀리초로 변환 가능한 양수여야 합니다")?;
    let timestamp = u64::try_from(detection.timestamp_ms)?;
    let query = argos_storage::EvidenceQuery {
        from_ms: timestamp.saturating_sub(span),
        to_ms: timestamp.saturating_add(span).min(i64::MAX as u64),
        pid: None,
        limit,
    };
    let evidence = store.query_evidence(&query)?;
    let responses = store.response_results(&query)?;
    let data =
        serde_json::json!({"detection":detection,"evidence":evidence,"response_results":responses});
    if let Some(path) = html {
        reports::write_report(path, "incident", data)?;
        println!("사건 조사 보고서: {}", path.display());
    } else {
        println!("{}", serde_json::to_string_pretty(&data)?);
    }
    Ok(())
}

fn cmd_canary(config: &AgentConfig, path: &std::path::Path) -> CmdResult {
    use std::io::Write;
    if !path.is_absolute() || !config.detection.canary_paths.iter().any(|p| p == path) {
        return Err("먼저 절대 경로를 [detection] canary_paths에 지정하세요".into());
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(b"Argos canary: unauthorized modification triggers a high-risk detection.\n")?;
    file.sync_all()?;
    println!("미끼 파일 생성: {} (센서 기동 전에 설치)", path.display());
    Ok(())
}

fn cmd_isolate(release: bool, allow: &[String], dry_run: bool) -> CmdResult {
    use argos_response::isolate;
    if release && !allow.is_empty() {
        return Err("--release와 --allow를 함께 지정할 수 없습니다".into());
    }
    if dry_run {
        let commands = if release {
            isolate::release_commands()
        } else {
            isolate::isolation_commands(allow)?
        };
        for command in commands {
            println!(
                "{} {}\n{}",
                command.program,
                command.args.join(" "),
                command.input
            );
        }
        return Ok(());
    }
    if release {
        isolate::release_isolation()?;
        println!("IPv4/IPv6 네트워크 격리를 해제했습니다.");
    } else {
        isolate::isolate_host(allow)?;
        println!("IPv4/IPv6 INPUT/OUTPUT/FORWARD 격리 적용·규칙 확인 완료. 명시한 관리 연결만 허용합니다. 해제: argos isolate --release");
    }
    Ok(())
}

fn cmd_policy(config: &AgentConfig, action: PolicyAction) -> CmdResult {
    match action {
        PolicyAction::Simulate {
            candidate,
            from_ms,
            to_ms,
            max_events,
        } => {
            let baseline = if config.policy.is_enabled() {
                argos_policy::load_verified(&config.policy.path, &config.policy.pubkey)?
            } else {
                argos_policy::Policy {
                    version: 0,
                    detection: config.detection.clone(),
                    response: config.response.clone(),
                }
            };
            // 후보는 아직 서명 전일 수 있다. 재생만 허용하며 활성화 경로로 전달하지 않는다.
            let candidate: argos_policy::Policy =
                toml::from_str(&std::fs::read_to_string(candidate)?)?;
            let options = argos_policy::SimulationOptions {
                from_ms,
                to_ms,
                max_events,
                sensor: config.sensor,
            };
            let report =
                argos_policy::simulate(&open_store(config)?, &baseline, &candidate, &options)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
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
                println!(
                    "서명 정책 미사용 — argos.toml의 [detection]/[response]가 그대로 적용됩니다."
                );
            } else {
                match argos_policy::load_verified(&config.policy.path, &config.policy.pubkey) {
                    Ok(p) => {
                        println!(
                            "정책 파일   : {} (서명 검증 OK)",
                            config.policy.path.display()
                        );
                        println!("정책 버전   : {}", p.version);
                        println!("탐지 설정   : {:?}", p.detection);
                        println!("대응 설정   : {:?}", p.response);
                        return Ok(());
                    }
                    Err(e) => {
                        println!(
                            "정책 파일   : {} — 검증 실패: {e}",
                            config.policy.path.display()
                        );
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
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
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

fn scan_one(
    path: &PathBuf,
    threshold: f64,
    sample: usize,
    scanned: &mut usize,
    suspicious: &mut usize,
) {
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
    for warning in
        argos_detect::validate_configuration(&config.detection, &config.response, config.sensor)?
    {
        println!("  [경고] {warning}");
    }
    println!("  OS               : {}", std::env::consts::OS);
    check(
        "설정 파일",
        config_path.exists(),
        &config_path.display().to_string(),
    );
    check(
        "DB 파일",
        config.db_path.exists(),
        &config.db_path.display().to_string(),
    );
    if config.backup.enabled {
        check(
            "백업 디렉터리",
            config.backup.dir.exists(),
            &config.backup.dir.display().to_string(),
        );
    }
    for p in &config.watch_paths {
        check("감시 경로", p.exists(), &p.display().to_string());
    }
    check(
        "ANTHROPIC_API_KEY",
        std::env::var("ANTHROPIC_API_KEY")
            .map(|v| !v.is_empty())
            .unwrap_or(false),
        "argos explain에 필요",
    );
    if std::env::consts::OS != "linux" {
        println!("  [참고] 비 Linux 환경 — 자동 차단·fanotify 미지원 (개발 모드)");
    }
    Ok(())
}

fn check(name: &str, ok: bool, detail: &str) {
    println!(
        "  {:<16} : {} ({detail})",
        name,
        if ok { "OK" } else { "없음" }
    );
}

fn not_yet(cmd: &str, feature: &str) -> CmdResult {
    println!("`argos {cmd}`는 아직 구현되지 않았습니다 — 로드맵: {feature}");
    Ok(())
}
