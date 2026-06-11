//! 네트워크 격리 (요건서 9장): iptables 기반 outbound 차단.
//!
//! ARGOS_ISOLATE 체인을 만들어 OUTPUT에 삽입한다:
//! - loopback, 기존 연결(ESTABLISHED — 관리 SSH 세션 유지), 허용 호스트만 통과
//! - 나머지 outbound 전부 DROP
//! `release`로 체인을 제거해 격리를 해제한다 (요건서 9장 대응 롤백).

use crate::ResponseError;

/// 격리 적용에 필요한 iptables 명령 목록. (인자 목록, 실패 허용 여부).
/// 실패 허용: 체인이 이미 존재하는 경우 등 멱등성을 위한 것.
pub fn isolation_commands(allow_hosts: &[String]) -> Vec<(Vec<String>, bool)> {
    let mut cmds: Vec<(Vec<String>, bool)> = Vec::new();
    let s = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();

    // 체인 생성(이미 있으면 실패해도 무방) 후 초기화.
    cmds.push((s(&["-N", "ARGOS_ISOLATE"]), true));
    cmds.push((s(&["-F", "ARGOS_ISOLATE"]), false));
    // loopback 허용.
    cmds.push((s(&["-A", "ARGOS_ISOLATE", "-o", "lo", "-j", "ACCEPT"]), false));
    // 기존 연결 유지 (관리 세션 끊김 방지).
    cmds.push((
        s(&[
            "-A", "ARGOS_ISOLATE", "-m", "conntrack", "--ctstate",
            "ESTABLISHED,RELATED", "-j", "ACCEPT",
        ]),
        false,
    ));
    // 허용 호스트 (중앙 서버 등).
    for host in allow_hosts {
        cmds.push((
            s(&["-A", "ARGOS_ISOLATE", "-d", host, "-j", "ACCEPT"]),
            false,
        ));
    }
    // 나머지 outbound 차단.
    cmds.push((s(&["-A", "ARGOS_ISOLATE", "-j", "DROP"]), false));
    // OUTPUT 최상단에 삽입 (중복 삽입 방지를 위해 먼저 제거 시도).
    cmds.push((s(&["-D", "OUTPUT", "-j", "ARGOS_ISOLATE"]), true));
    cmds.push((s(&["-I", "OUTPUT", "1", "-j", "ARGOS_ISOLATE"]), false));
    cmds
}

/// 격리 해제 명령 목록.
pub fn release_commands() -> Vec<(Vec<String>, bool)> {
    let s = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    vec![
        (s(&["-D", "OUTPUT", "-j", "ARGOS_ISOLATE"]), true),
        (s(&["-F", "ARGOS_ISOLATE"]), true),
        (s(&["-X", "ARGOS_ISOLATE"]), true),
    ]
}

/// 서버를 네트워크에서 격리한다 (Linux, root 필요).
pub fn isolate_host(allow_hosts: &[String]) -> Result<(), ResponseError> {
    run_iptables(isolation_commands(allow_hosts))
}

/// 격리를 해제한다.
pub fn release_isolation() -> Result<(), ResponseError> {
    run_iptables(release_commands())
}

#[cfg(target_os = "linux")]
fn run_iptables(commands: Vec<(Vec<String>, bool)>) -> Result<(), ResponseError> {
    for (args, allow_fail) in commands {
        let output = std::process::Command::new("iptables")
            .args(&args)
            .output()
            .map_err(|e| ResponseError::Signal { pid: 0, source: e })?;
        if !output.status.success() && !allow_fail {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            tracing::error!(args = ?args, stderr = %stderr, "iptables 명령 실패");
            return Err(ResponseError::Signal {
                pid: 0,
                source: std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("iptables {} 실패: {stderr}", args.join(" ")),
                ),
            });
        }
        tracing::info!(args = ?args, "iptables 적용");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_iptables(_commands: Vec<(Vec<String>, bool)>) -> Result<(), ResponseError> {
    Err(ResponseError::Unsupported("네트워크 격리는 Linux에서만 지원됩니다"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation_allows_hosts_and_drops_rest() {
        let cmds = isolation_commands(&["10.0.0.5".to_string(), "central.example.com".to_string()]);
        let flat: Vec<String> = cmds.iter().map(|(a, _)| a.join(" ")).collect();
        assert!(flat.iter().any(|c| c.contains("-d 10.0.0.5 -j ACCEPT")));
        assert!(flat.iter().any(|c| c.contains("-d central.example.com -j ACCEPT")));
        // DROP은 허용 규칙들 뒤, OUTPUT 삽입 전이어야 한다.
        let drop_idx = flat.iter().position(|c| c.ends_with("-j DROP")).unwrap();
        let accept_idx = flat.iter().position(|c| c.contains("10.0.0.5")).unwrap();
        let insert_idx = flat.iter().position(|c| c.starts_with("-I OUTPUT")).unwrap();
        assert!(accept_idx < drop_idx && drop_idx < insert_idx);
    }

    #[test]
    fn release_removes_chain() {
        let cmds = release_commands();
        let flat: Vec<String> = cmds.iter().map(|(a, _)| a.join(" ")).collect();
        assert_eq!(flat, vec!["-D OUTPUT -j ARGOS_ISOLATE", "-F ARGOS_ISOLATE", "-X ARGOS_ISOLATE"]);
        // 해제 명령은 전부 실패 허용 (이미 해제된 상태에서도 멱등).
        assert!(cmds.iter().all(|(_, allow_fail)| *allow_fail));
    }
}
