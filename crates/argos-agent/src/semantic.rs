//! Explicit Linux configuration files: bounded observations, semantic diffs, no execution.
use argos_common::{config::SemanticConfig, Detection, FileEvent, Severity};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs::OpenOptions,
    io::{self, Read},
    path::{Component, Path},
};

#[derive(Clone, Copy)]
enum Kind {
    Ssh,
    Sudo,
    Cron,
    Systemd,
}

impl Kind {
    fn of(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?;
        if name == "authorized_keys" || name == "authorized_keys2" {
            return Some(Self::Ssh);
        }
        if name == "sudoers" || path.components().any(|p| p.as_os_str() == "sudoers.d") {
            return Some(Self::Sudo);
        }
        if name == "crontab"
            || path
                .components()
                .any(|p| matches!(p.as_os_str().to_str(), Some("cron.d" | "cron" | "crontabs")))
        {
            return Some(Self::Cron);
        }
        if matches!(
            path.extension().and_then(|v| v.to_str()),
            Some("service" | "timer" | "socket")
        ) || (name.ends_with(".conf")
            && path.components().any(|p| {
                p.as_os_str().to_str().is_some_and(|v| {
                    v.ends_with(".service.d") || v.ends_with(".timer.d") || v.ends_with(".socket.d")
                })
            }))
        {
            return Some(Self::Systemd);
        }
        None
    }
    fn label(self) -> &'static str {
        match self {
            Self::Ssh => "SSH 키/접속 제한",
            Self::Sudo => "관리자 권한 규칙",
            Self::Cron => "cron 자동 실행 등록",
            Self::Systemd => "systemd 서비스/자동 실행 설정",
        }
    }
    fn rule(self) -> &'static str {
        match self {
            Self::Ssh => "linux.authorized_keys",
            Self::Sudo => "linux.sudoers",
            Self::Cron => "linux.cron",
            Self::Systemd => "linux.systemd",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Snapshot {
    entries: BTreeSet<String>,
    permissions: Option<(u32, u32, u32)>,
}

pub struct SemanticMonitor {
    config: SemanticConfig,
    previous: HashMap<String, Option<Snapshot>>,
    unavailable: HashSet<String>,
}

impl SemanticMonitor {
    pub fn new(
        config: &SemanticConfig,
        watch_paths: &[std::path::PathBuf],
    ) -> Result<Self, String> {
        if config.files.len() > 1024
            || config.max_file_bytes == 0
            || config.max_file_bytes > 1024 * 1024
        {
            return Err("semantic: 최대 1024개 파일, 읽기 예산 1~1048576 바이트".into());
        }
        let mut previous = HashMap::new();
        let mut unavailable = HashSet::new();
        for path in &config.files {
            if !path.is_absolute()
                || path.components().any(|p| matches!(p, Component::ParentDir))
                || Kind::of(path).is_none()
            {
                return Err(format!(
                    "semantic: 지원하는 설정 파일의 .. 없는 절대 경로 필요: {}",
                    path.display()
                ));
            }
            if !watch_paths.iter().any(|root| path.starts_with(root)) {
                return Err(format!(
                    "semantic 파일은 watch_paths 안에 있어야 합니다: {}",
                    path.display()
                ));
            }
            let initial = snapshot(path, config.max_file_bytes);
            if let Err(error) = &initial {
                unavailable.insert(path.to_string_lossy().into_owned());
                tracing::warn!(path=%path.display(), %error, "설정 의미 기준 관측 실패 — 미수집");
            }
            previous.insert(path.to_string_lossy().into_owned(), initial.ok());
        }
        Ok(Self {
            config: config.clone(),
            previous,
            unavailable,
        })
    }

    pub fn unavailable_count(&self) -> usize {
        self.unavailable.len()
    }

    pub fn observe(&mut self, event: &FileEvent) -> Option<Detection> {
        let old = self.previous.get_mut(&event.path)?;
        let path = Path::new(&event.path);
        let kind = Kind::of(path)?;
        let (score, summary) = match snapshot(path, self.config.max_file_bytes) {
            Err(error) => {
                self.unavailable.insert(event.path.clone());
                (
                    0.0,
                    format!(
                        "{} 분석 불가: {error}; 이전 관측 유지, 보호 범위 누락",
                        kind.label()
                    ),
                )
            }
            Ok(current) => {
                self.unavailable.remove(&event.path);
                let previous = old.replace(current.clone());
                let Some(previous) = previous else {
                    return Some(Detection {
                        timestamp_ms: event.timestamp_ms,
                        rule: "health.semantic_baseline".into(),
                        score: 0.0,
                        severity: Severity::Low,
                        summary: format!(
                            "{} 최초 관측: 이전 내용 미수집, 정상 판정 아님",
                            kind.label()
                        ),
                        pid: event.pid,
                        paths: vec![event.path.clone()],
                    });
                };
                if current == previous {
                    return None;
                }
                let added = current.entries.difference(&previous.entries).count();
                let removed = previous.entries.difference(&current.entries).count();
                (70.0, format!("{} 변경: 추가 {added}, 제거 {removed}, 소유권/권한 변경 {}. 원문·명령·키 내용은 알림에서 제외",kind.label(),current.permissions!=previous.permissions))
            }
        };
        Some(Detection {
            timestamp_ms: event.timestamp_ms,
            rule: if score == 0.0 {
                "health.semantic_unavailable"
            } else {
                kind.rule()
            }
            .into(),
            score,
            severity: if score == 0.0 {
                Severity::Low
            } else {
                Severity::High
            },
            summary,
            pid: event.pid,
            paths: vec![event.path.clone()],
        })
    }
}

fn snapshot(path: &Path, limit: usize) -> io::Result<Snapshot> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(Snapshot {
                entries: BTreeSet::new(),
                permissions: None,
            })
        }
        Err(e) => return Err(e),
    };
    let before = file.metadata()?;
    if !before.is_file() || before.len() > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "일반 파일/읽기 예산 조건 불충족",
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() > limit
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "관측 도중 변경/읽기 예산 초과",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "UTF-8 설정 아님"))?;
    #[cfg(unix)]
    let permissions = {
        use std::os::unix::fs::MetadataExt;
        Some((after.uid(), after.gid(), after.mode() & 0o7777))
    };
    #[cfg(not(unix))]
    let permissions = None;
    Ok(Snapshot {
        entries: parse(
            Kind::of(path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "지원하지 않는 설정"))?,
            text,
        )?,
        permissions,
    })
}

// Preserve quoted content. Normalize only whitespace outside quotes; comments are removed only
// when they occupy the entire line (sudoers #include and numeric users remain meaningful).
fn normalize(line: &str) -> io::Result<String> {
    let mut result = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut space = false;
    for ch in line.chars() {
        if escaped {
            result.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            if space && !result.is_empty() {
                result.push(' ');
            }
            space = false;
            result.push(ch);
            escaped = true;
            continue;
        }
        if Some(ch) == quote {
            quote = None;
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
        }
        if ch.is_whitespace() && quote.is_none() {
            space = true;
        } else {
            if space && !result.is_empty() {
                result.push(' ');
            }
            space = false;
            result.push(ch);
        }
    }
    if quote.is_some() || escaped {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "닫히지 않은 인용/이스케이프",
        ));
    }
    Ok(result)
}

// Token boundaries honor quoted options. Stop before the free-form human comment.
fn ssh_record(line: &str) -> io::Result<String> {
    let mut quote = None;
    let mut escaped = false;
    let mut start = None;
    let mut key_seen = false;
    for (offset, ch) in line
        .char_indices()
        .chain(std::iter::once((line.len(), ' ')))
    {
        if start.is_none() {
            if ch.is_whitespace() {
                continue;
            }
            start = Some(offset);
        }
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if Some(ch) == quote {
            quote = None;
        } else if quote.is_none() && ch == '"' {
            quote = Some(ch);
        }
        if ch.is_whitespace() && quote.is_none() {
            let token = &line[start.take().unwrap()..offset];
            if key_seen {
                if !token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSH 키 인코딩 형식 오류",
                    ));
                }
                return normalize(&line[..offset]);
            }
            key_seen = token.starts_with("ssh-")
                || token.starts_with("ecdsa-sha2-")
                || token.starts_with("sk-ssh-")
                || token.starts_with("sk-ecdsa-");
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "SSH 키 형식 미지원/불완전",
    ))
}

fn parse(kind: Kind, text: &str) -> io::Result<BTreeSet<String>> {
    let mut entries = BTreeSet::new();
    let mut section = String::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let raw = raw.trim();
        let sudo_directive = matches!(kind, Kind::Sudo)
            && (raw.starts_with("#include")
                || raw.as_bytes().get(1).is_some_and(u8::is_ascii_digit));
        if raw.is_empty()
            || (raw.starts_with('#') && !sudo_directive)
            || (matches!(kind, Kind::Systemd) && raw.starts_with(';'))
        {
            continue;
        }
        pending.push_str(raw);
        if matches!(kind, Kind::Sudo | Kind::Systemd) && pending.ends_with('\\') {
            pending.pop();
            pending.push(' ');
            continue;
        }
        let line = if matches!(kind, Kind::Ssh) {
            ssh_record(&pending)?
        } else {
            normalize(&pending)?
        };
        pending.clear();
        let normalized = match kind {
            Kind::Ssh => format!("{}:{line}", entries.len()),
            Kind::Systemd => {
                if line.starts_with('[') && line.ends_with(']') {
                    section = line;
                    continue;
                }
                let (key, value) = line.split_once('=').ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "systemd 대입 구문 아님")
                })?;
                if section.is_empty() || key.trim().is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "systemd 섹션/키 없음",
                    ));
                }
                // Keep order through ordinal for repeat/reset directives such as ExecStart=.
                format!(
                    "{}:{section}:{}={}",
                    entries.len(),
                    key.trim(),
                    value.trim()
                )
            }
            _ => format!("{}:{line}", entries.len()),
        };
        entries.insert(normalized);
        if entries.len() > 10000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "설정 항목 상한 초과",
            ));
        }
    }
    if !pending.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "미완성 연속 행"));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_unavailable_stays_visible_until_successful_observation() {
        let dir = std::env::temp_dir().join(format!(
            "argos-semantic-{}-{}",
            std::process::id(),
            argos_common::now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("authorized_keys");
        std::fs::write(&path, "x".repeat(128)).unwrap();
        let mut monitor = SemanticMonitor::new(
            &SemanticConfig {
                files: vec![path.clone()],
                max_file_bytes: 64,
            },
            std::slice::from_ref(&dir),
        )
        .unwrap();
        assert_eq!(monitor.unavailable_count(), 1);
        std::fs::write(&path, "ssh-ed25519 AAAA comment").unwrap();
        let event = FileEvent {
            timestamp_ms: 1,
            pid: 0,
            path: path.to_string_lossy().into_owned(),
            action: argos_common::FileAction::Modify,
            size: None,
            entropy: None,
            process: None,
            content: None,
        };
        assert_eq!(
            monitor.observe(&event).unwrap().rule,
            "health.semantic_baseline"
        );
        assert_eq!(monitor.unavailable_count(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn comments_and_spacing_but_not_privilege_changes_are_ignored() {
        assert_eq!(
            parse(Kind::Sudo, "# note\nalice ALL=(root) /bin/ls\n").unwrap(),
            parse(Kind::Sudo, "alice   ALL=(root)   /bin/ls\n").unwrap()
        );
        assert_ne!(
            parse(Kind::Sudo, "alice ALL=(root) /bin/ls").unwrap(),
            parse(Kind::Sudo, "alice ALL=(ALL) NOPASSWD: ALL").unwrap()
        );
        assert!(parse(Kind::Sudo, "#include /etc/sudoers.d").unwrap().len() == 1);
    }
    #[test]
    fn keys_ignore_comment_and_detect_key_or_options_changes() {
        let key = parse(Kind::Ssh, "ssh-ed25519 AAAA user@host").unwrap();
        assert_eq!(
            key,
            parse(Kind::Ssh, "ssh-ed25519 AAAA other-comment").unwrap()
        );
        assert_ne!(
            key,
            parse(Kind::Ssh, "restrict ssh-ed25519 AAAA user").unwrap()
        );
        assert_ne!(key, parse(Kind::Ssh, "ssh-ed25519 BBBB user").unwrap());
    }
    #[test]
    fn quoted_ssh_options_and_directive_order_are_preserved() {
        let a = r#"command="echo ssh-fake AAAA" ssh-ed25519 REAL human's comment"#;
        let b = r#"command="echo ssh-fake AAAA" ssh-ed25519 OTHER other comment"#;
        assert_ne!(parse(Kind::Ssh, a).unwrap(), parse(Kind::Ssh, b).unwrap());
        assert_eq!(
            parse(
                Kind::Ssh,
                "ssh-ed25519 AAAA comment\\\nssh-ed25519 BBBB added"
            )
            .unwrap()
            .len(),
            2
        );
        assert_ne!(
            parse(Kind::Cron, "X=1\n* * * * * job\nX=2").unwrap(),
            parse(Kind::Cron, "X=2\n* * * * * job\nX=1").unwrap()
        );
        assert_ne!(
            parse(Kind::Sudo, "a ALL=ALL\na ALL=!/bin/x").unwrap(),
            parse(Kind::Sudo, "a ALL=!/bin/x\na ALL=ALL").unwrap()
        );
    }
    #[test]
    fn cron_and_systemd_capture_persistence_and_reject_bad_parse() {
        assert_ne!(
            parse(Kind::Cron, "@reboot /bin/true").unwrap(),
            parse(Kind::Cron, "@reboot /bin/other").unwrap()
        );
        assert_eq!(
            parse(Kind::Systemd, "[Service]\nUser = root\n").unwrap(),
            parse(Kind::Systemd, "#note\n[Service]\nUser=root\n").unwrap()
        );
        assert!(parse(Kind::Systemd, "ExecStart=/bin/true").is_err());
        assert!(parse(Kind::Ssh, "broken").is_err());
    }
}
