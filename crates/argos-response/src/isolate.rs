//! IPv4·IPv6의 INPUT/OUTPUT/FORWARD를 함께 제한하는 네트워크 격리.
//! 관리 연결은 방향·IP/CIDR·TCP 포트로 명시한다. 기존 연결도 예외가 아니다.
//! 각 주소 계열은 restore 트랜잭션으로 적용하고 적용 결과를 다시 확인한다.

use std::net::IpAddr;

const CHAINS: [(&str, &str); 3] = [
    ("INPUT", "ARGOS_INPUT"),
    ("OUTPUT", "ARGOS_OUTPUT"),
    ("FORWARD", "ARGOS_FORWARD"),
];
const LEGACY_CHAIN: &str = "ARGOS_ISOLATE";

#[derive(Debug, thiserror::Error)]
pub enum IsolationError {
    #[error("격리 허용 규칙 오류: {0}")]
    InvalidRule(String),
    #[error("방화벽 명령 실패 ({program}): {detail}")]
    Command { program: String, detail: String },
    #[error("네트워크 격리 작업 실패: {0}")]
    Incomplete(String),
    #[error("네트워크 격리는 Linux에서만 지원됩니다")]
    Unsupported,
}

/// 셸을 통하지 않고 실행할 명령. input은 restore의 표준 입력이다.
#[derive(Debug, Clone)]
pub struct FirewallCommand {
    pub program: &'static str,
    pub args: Vec<String>,
    pub input: String,
}

#[derive(Debug)]
struct ManagementRule {
    inbound: bool,
    network: String,
    port: u16,
    ipv6: bool,
}

fn parse_rule(text: &str) -> Result<ManagementRule, IsolationError> {
    let invalid = || {
        IsolationError::InvalidRule(format!("{text:?}: in:192.0.2.20:22 또는 out:[2001:db8::10]:443 형식의 명시적 IP/CIDR·포트가 필요합니다"))
    };
    let (direction, endpoint) = text.split_once(':').ok_or_else(invalid)?;
    let inbound = match direction {
        "in" => true,
        "out" => false,
        _ => return Err(invalid()),
    };
    let (network, port) = if let Some(rest) = endpoint.strip_prefix('[') {
        rest.split_once("]:").ok_or_else(invalid)?
    } else {
        let (network, port) = endpoint.rsplit_once(':').ok_or_else(invalid)?;
        if network.contains(':') {
            return Err(invalid());
        }
        (network, port)
    };
    let port = port.parse::<u16>().map_err(|_| invalid())?;
    if port == 0 {
        return Err(invalid());
    }
    let (ip_text, prefix) = network
        .split_once('/')
        .map_or((network, None), |(ip, p)| (ip, Some(p)));
    let ip = ip_text.parse::<IpAddr>().map_err(|_| invalid())?;
    let network = match prefix {
        Some(prefix) => {
            let prefix = prefix.parse::<u8>().map_err(|_| invalid())?;
            if prefix == 0 || prefix > if ip.is_ipv4() { 32 } else { 128 } {
                return Err(invalid());
            }
            format!("{ip}/{prefix}")
        }
        None => ip.to_string(),
    };
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(invalid());
    }
    Ok(ManagementRule {
        inbound,
        network,
        port,
        ipv6: ip.is_ipv6(),
    })
}

fn restore_command(ipv6: bool, input: String) -> FirewallCommand {
    FirewallCommand {
        program: if ipv6 {
            "ip6tables-restore"
        } else {
            "iptables-restore"
        },
        args: vec!["--noflush".into(), "--wait".into(), "5".into()],
        input,
    }
}

/// 호스트 상태를 읽거나 변경하지 않는 신규 격리 계획 (CLI --dry-run).
/// 실제 적용은 기존 Argos 점프를 제거하는 계획을 현재 상태에서 다시 만든다.
pub fn isolation_commands(allow: &[String]) -> Result<Vec<FirewallCommand>, IsolationError> {
    let rules = allow
        .iter()
        .map(|r| parse_rule(r))
        .collect::<Result<Vec<_>, _>>()?;
    Ok([false, true]
        .into_iter()
        .map(|ipv6| restore_command(ipv6, isolation_script(&rules, ipv6, "")))
        .collect())
}

/// 표준 설치 상태의 해제 계획. 실제 해제는 현재 존재하는 규칙만 제거한다.
pub fn release_commands() -> Vec<FirewallCommand> {
    let mut installed = String::new();
    for (base, chain) in CHAINS {
        installed.push_str(&format!(":{chain} - [0:0]\n-A {base} -j {chain}\n"));
    }
    [false, true]
        .into_iter()
        .map(|ipv6| restore_command(ipv6, release_script(&installed)))
        .collect()
}

fn own_chain(name: &str) -> bool {
    CHAINS.iter().any(|(_, chain)| *chain == name) || name == LEGACY_CHAIN
}

fn existing_chains(snapshot: &str) -> Vec<&str> {
    snapshot
        .lines()
        .filter_map(|line| {
            let name = line.strip_prefix(':')?.split_whitespace().next()?;
            own_chain(name).then_some(name)
        })
        .collect()
}

fn remove_jumps(snapshot: &str, script: &mut String) {
    for line in snapshot.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() >= 4
            && tokens[0] == "-A"
            && !own_chain(tokens[1])
            && tokens
                .windows(2)
                .any(|p| (p[0] == "-j" || p[0] == "-g") && own_chain(p[1]))
        {
            script.push_str(&line.replacen("-A", "-D", 1));
            script.push('\n');
        }
    }
}

fn isolation_script(rules: &[ManagementRule], ipv6: bool, snapshot: &str) -> String {
    let mut script = String::from("*filter\n");
    // --noflush에서 선언한 사용자 체인만 교체한다. 기존 전체 방화벽은 유지한다.
    for (_, chain) in CHAINS {
        script.push_str(&format!(":{chain} - [0:0]\n"));
    }
    remove_jumps(snapshot, &mut script);
    if existing_chains(snapshot).contains(&LEGACY_CHAIN) {
        script.push_str(&format!("-F {LEGACY_CHAIN}\n-X {LEGACY_CHAIN}\n"));
    }
    script.push_str("-A ARGOS_INPUT -i lo -j ACCEPT\n-A ARGOS_OUTPUT -o lo -j ACCEPT\n");
    if ipv6 {
        // IPv6 관리 연결 유지에 필요한 링크 내 이웃 탐색만 허용한다.
        for chain in ["ARGOS_INPUT", "ARGOS_OUTPUT"] {
            for kind in [135, 136] {
                script.push_str(&format!(
                    "-A {chain} -p ipv6-icmp --icmpv6-type {kind} -m hl --hl-eq 255 -j ACCEPT\n"
                ));
            }
        }
        script.push_str("-A ARGOS_INPUT -s fe80::/10 -p ipv6-icmp --icmpv6-type 134 -m hl --hl-eq 255 -j ACCEPT\n");
        script.push_str("-A ARGOS_OUTPUT -d ff02::2 -p ipv6-icmp --icmpv6-type 133 -m hl --hl-eq 255 -j ACCEPT\n");
    }
    for rule in rules.iter().filter(|r| r.ipv6 == ipv6) {
        let (original, original_peer, reply, reply_peer) = if rule.inbound {
            ("ARGOS_INPUT", "-s", "ARGOS_OUTPUT", "-d")
        } else {
            ("ARGOS_OUTPUT", "-d", "ARGOS_INPUT", "-s")
        };
        script.push_str(&format!("-A {original} {original_peer} {} -p tcp --dport {} -m conntrack --ctstate NEW,ESTABLISHED --ctdir ORIGINAL -j ACCEPT\n", rule.network, rule.port));
        script.push_str(&format!("-A {reply} {reply_peer} {} -p tcp --sport {} -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT\n", rule.network, rule.port));
    }
    for (base, chain) in CHAINS {
        script.push_str(&format!("-A {chain} -j DROP\n-I {base} 1 -j {chain}\n"));
    }
    script.push_str("COMMIT\n");
    script
}

fn release_script(snapshot: &str) -> String {
    let mut script = String::from("*filter\n");
    remove_jumps(snapshot, &mut script);
    // 모든 체인을 먼저 비워 상호 참조도 제거한다.
    for chain in existing_chains(snapshot) {
        script.push_str(&format!("-F {chain}\n"));
    }
    for chain in existing_chains(snapshot) {
        script.push_str(&format!("-X {chain}\n"));
    }
    script.push_str("COMMIT\n");
    script
}

trait FirewallRunner {
    fn run(&mut self, command: &FirewallCommand) -> Result<String, IsolationError>;
}

fn read_command(ipv6: bool) -> FirewallCommand {
    FirewallCommand {
        program: if ipv6 {
            "ip6tables-save"
        } else {
            "iptables-save"
        },
        args: vec!["-t".into(), "filter".into()],
        input: String::new(),
    }
}

fn verify(snapshot: &str, script: &str, release: bool) -> Result<(), IsolationError> {
    if release {
        if !existing_chains(snapshot).is_empty() {
            return Err(IsolationError::Incomplete(
                "해제 후에도 Argos 체인이 남았습니다".into(),
            ));
        }
        return Ok(());
    }
    for (base, chain) in CHAINS {
        let base_prefix = format!("-A {base} ");
        let first = snapshot.lines().find(|line| line.starts_with(&base_prefix));
        if first != Some(format!("-A {base} -j {chain}").as_str()) {
            return Err(IsolationError::Incomplete(format!(
                "{base} 최상단의 {chain} 연결을 확인하지 못했습니다"
            )));
        }
        let prefix = format!("-A {chain} ");
        // save는 주소/모듈을 정규화한다. 사전 구문 검사 후 연결·규칙 수·DROP을 검증한다.
        let actual: Vec<_> = snapshot
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .collect();
        let expected_count = script
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .count();
        if actual.len() != expected_count
            || actual.last() != Some(&format!("-A {chain} -j DROP").as_str())
        {
            return Err(IsolationError::Incomplete(format!(
                "{chain}의 규칙 수 또는 최종 DROP 검증 실패"
            )));
        }
    }
    Ok(())
}

fn execute(
    runner: &mut impl FirewallRunner,
    allow: &[String],
    release: bool,
) -> Result<(), IsolationError> {
    let rules = allow
        .iter()
        .map(|r| parse_rule(r))
        .collect::<Result<Vec<_>, _>>()?;
    // 두 주소 계열을 모두 읽고 사전 검사한 뒤에만 변경을 시작한다.
    let mut plans = Vec::new();
    for ipv6 in [false, true] {
        let snapshot = runner.run(&read_command(ipv6))?;
        let script = if release {
            release_script(&snapshot)
        } else {
            isolation_script(&rules, ipv6, &snapshot)
        };
        plans.push(restore_command(ipv6, script));
    }
    for plan in &plans {
        let mut check = plan.clone();
        check.args.push("--test".into());
        runner.run(&check)?;
    }
    for (index, plan) in plans.iter().enumerate() {
        runner.run(plan).map_err(|e| IsolationError::Incomplete(format!("{} 적용 실패; {index}개 주소 계열은 이미 적용되었을 수 있습니다. 부분 상태를 확인하세요: {e}", plan.program)))?;
    }
    for (index, ipv6) in [false, true].into_iter().enumerate() {
        let snapshot = runner.run(&read_command(ipv6)).map_err(|e| {
            IsolationError::Incomplete(format!(
                "규칙 적용 후 상태 조회 실패; 적용된 규칙을 확인하세요: {e}"
            ))
        })?;
        verify(&snapshot, &plans[index].input, release)?;
        if !release {
            // -C는 저장 출력의 정규화와 무관하게 IP·포트·방향·상태 조건을 검증한다.
            for rule in plans[index]
                .input
                .lines()
                .filter(|line| line.starts_with("-A "))
            {
                let mut args: Vec<String> = rule.split_whitespace().map(str::to_string).collect();
                args[0] = "-C".into();
                args.extend(["--wait".into(), "5".into()]);
                let check = FirewallCommand {
                    program: if ipv6 { "ip6tables" } else { "iptables" },
                    args,
                    input: String::new(),
                };
                runner.run(&check).map_err(|e| {
                    IsolationError::Incomplete(format!("적용 후 개별 격리 규칙 검증 실패: {e}"))
                })?;
            }
        }
    }
    Ok(())
}

/// 명시된 TCP 관리 연결만 허용한다. 호스트를 통과하는 전달 트래픽은 모두 차단한다.
pub fn isolate_host(allow: &[String]) -> Result<(), IsolationError> {
    execute(&mut SystemRunner, allow, false)
}

/// 현재 존재하는 Argos 규칙만 제거한다. 해제 검증 실패를 성공으로 숨기지 않는다.
pub fn release_isolation() -> Result<(), IsolationError> {
    execute(&mut SystemRunner, &[], true)
}

struct SystemRunner;

#[cfg(target_os = "linux")]
impl FirewallRunner for SystemRunner {
    fn run(&mut self, command: &FirewallCommand) -> Result<String, IsolationError> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let error = |detail: String| IsolationError::Command {
            program: command.program.into(),
            detail,
        };
        let mut child = Command::new(command.program)
            .args(&command.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| error(e.to_string()))?;
        let written = child
            .stdin
            .take()
            .unwrap()
            .write_all(command.input.as_bytes());
        // stdin 실패여도 자식을 회수한다.
        let output = child.wait_with_output().map_err(|e| error(e.to_string()))?;
        if !output.status.success() {
            return Err(error(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        written.map_err(|e| error(e.to_string()))?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

#[cfg(not(target_os = "linux"))]
impl FirewallRunner for SystemRunner {
    fn run(&mut self, _command: &FirewallCommand) -> Result<String, IsolationError> {
        Err(IsolationError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_families_cover_all_packet_paths_and_only_explicit_management_sessions() {
        let commands = isolation_commands(&[
            "in:192.0.2.20/32:22".into(),
            "out:10.0.0.5:443".into(),
            "out:[2001:db8::10]:443".into(),
        ])
        .unwrap();
        assert_eq!(commands.len(), 2);
        for command in &commands {
            assert!(command.args.contains(&"--noflush".into()));
            for (base, chain) in CHAINS {
                assert!(command.input.contains(&format!("-I {base} 1 -j {chain}")));
                assert!(command.input.contains(&format!("-A {chain} -j DROP")));
            }
            assert!(!command.input.contains("ESTABLISHED,RELATED"));
            for rule in command
                .input
                .lines()
                .filter(|line| line.contains("--ctstate"))
            {
                assert!(rule.contains(" -s ") || rule.contains(" -d "));
                assert!(rule.contains("--sport") || rule.contains("--dport"));
                assert!(rule.contains("--ctdir"));
            }
            assert!(!command
                .input
                .lines()
                .any(|line| line.starts_with("-A ARGOS_FORWARD") && line.contains("ACCEPT")));
        }
        assert!(commands[0]
            .input
            .contains("-A ARGOS_INPUT -s 192.0.2.20/32 -p tcp --dport 22"));
        assert!(commands[0]
            .input
            .contains("-A ARGOS_OUTPUT -d 10.0.0.5 -p tcp --dport 443"));
        assert!(!commands[0].input.contains("2001:db8"));
        assert!(commands[1]
            .input
            .contains("-d 2001:db8::10 -p tcp --dport 443"));
    }

    #[test]
    fn rejects_ambiguous_or_overbroad_management_exceptions() {
        for rule in [
            "10.0.0.5",
            "out:central.example.com:443",
            "in:0.0.0.0/0:22",
            "out:[::/0]:443",
            "in:10.0.0.0/33:22",
            "out:[2001:db8::/129]:443",
            "out:10.0.0.5:0",
            "out:10.0.0.5:65536",
            "out:2001:db8::10:443",
            "in:10.0.0.5:22\nCOMMIT",
        ] {
            assert!(
                isolation_commands(&[rule.into()]).is_err(),
                "규칙 거부 필요: {rule}"
            );
        }
    }

    #[test]
    fn reapplication_and_release_remove_existing_and_legacy_jumps() {
        let snapshot = "*filter\n:ARGOS_INPUT - [0:0]\n:ARGOS_ISOLATE - [0:0]\n-A INPUT -j ARGOS_INPUT\n-A INPUT -j ARGOS_INPUT\n-A OUTPUT -j ARGOS_ISOLATE\nCOMMIT\n";
        let script = isolation_script(&[], false, snapshot);
        assert_eq!(script.matches("-D INPUT -j ARGOS_INPUT").count(), 2);
        assert!(script.contains("-F ARGOS_ISOLATE\n-X ARGOS_ISOLATE"));
        assert!(!script.contains("-F INPUT"));
        let released = release_script(snapshot);
        assert!(released.contains("-D OUTPUT -j ARGOS_ISOLATE"));
        assert!(released.contains("-X ARGOS_INPUT"));
        assert_eq!(release_script("*filter\nCOMMIT\n"), "*filter\nCOMMIT\n");
    }

    #[derive(Default)]
    struct FakeRunner {
        calls: Vec<FirewallCommand>,
        states: [String; 2],
        fail_test: bool,
        fail_ipv6_apply: bool,
        corrupt_readback: bool,
        fail_rule_check: bool,
    }

    impl FirewallRunner for FakeRunner {
        fn run(&mut self, command: &FirewallCommand) -> Result<String, IsolationError> {
            self.calls.push(command.clone());
            let family = usize::from(command.program.starts_with("ip6"));
            let test = command.args.contains(&"--test".into());
            if (test && self.fail_test)
                || (!test && command.program == "ip6tables-restore" && self.fail_ipv6_apply)
                || (self.fail_rule_check && command.args.first().map(String::as_str) == Some("-C"))
            {
                return Err(IsolationError::Command {
                    program: command.program.into(),
                    detail: "주입한 실패".into(),
                });
            }
            if command.program.ends_with("-save") {
                return Ok(if self.corrupt_readback {
                    String::new()
                } else {
                    self.states[family].clone()
                });
            }
            if !test && command.program.ends_with("-restore") {
                self.states[family] = command
                    .input
                    .lines()
                    .filter(|line| {
                        line.starts_with(':') || line.starts_with("-A") || line.starts_with("-I")
                    })
                    .map(|line| line.replacen("-I", "-A", 1).replace(" 1 -j", " -j"))
                    .collect::<Vec<_>>()
                    .join("\n");
            }
            Ok(String::new())
        }
    }

    #[test]
    fn preflight_failure_never_mutates_firewall() {
        let mut runner = FakeRunner {
            fail_test: true,
            ..FakeRunner::default()
        };
        assert!(execute(&mut runner, &[], false).is_err());
        assert!(runner
            .calls
            .iter()
            .all(|c| c.program.ends_with("-save") || c.args.contains(&"--test".into())));
    }

    #[test]
    fn partial_family_failure_is_reported() {
        let mut runner = FakeRunner {
            fail_ipv6_apply: true,
            ..FakeRunner::default()
        };
        let error = execute(&mut runner, &[], false).unwrap_err().to_string();
        assert!(error.contains("1개 주소 계열"));
        assert!(!runner.states[0].is_empty());
    }

    #[test]
    fn apply_then_verify_both_families_and_idempotent_release() {
        let mut runner = FakeRunner::default();
        execute(&mut runner, &["in:192.0.2.20:22".into()], false).unwrap();
        execute(&mut runner, &[], true).unwrap();
        execute(&mut runner, &[], true).unwrap();
        assert!(runner.states.iter().all(String::is_empty));
    }

    #[test]
    fn missing_enforcement_on_readback_is_not_success() {
        let mut runner = FakeRunner {
            corrupt_readback: true,
            ..FakeRunner::default()
        };
        assert!(execute(&mut runner, &[], false).is_err());
    }

    #[test]
    fn correct_counts_do_not_hide_wrong_rule_conditions() {
        let mut runner = FakeRunner {
            fail_rule_check: true,
            ..FakeRunner::default()
        };
        let error = execute(&mut runner, &["in:192.0.2.20:22".into()], false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("개별 격리 규칙 검증 실패"));
    }
}
