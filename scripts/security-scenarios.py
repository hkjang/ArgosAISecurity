#!/usr/bin/env python3
"""Verify security scenarios with built Argos binaries and isolated temporary files.

Usage: python3 scripts/security-scenarios.py --bin-dir /tmp/argos-target/debug
No root, network service, system configuration edit, or automatic response required.
The JSON report records expected and observed outcomes. Use --keep to retain logs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def wait_until(predicate, message, timeout=12):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except (OSError, sqlite3.Error, json.JSONDecodeError) as error:
            last_error = error
        time.sleep(0.05)
    raise AssertionError(f"{message}; last error: {last_error}")


def rows(database, sql, parameters=()):
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        return connection.execute(sql, parameters).fetchall()


class Scenarios:
    def __init__(self, binaries, work):
        self.binaries, self.work = binaries, work
        self.processes, self.results = [], []
        self.env = os.environ.copy()
        self.env["RUST_LOG"] = "info"
        for name in ("ARGOS_CENTRAL_TOKEN", "ANTHROPIC_API_KEY"):
            self.env.pop(name, None)

    def cli(self, config, *arguments, success=True):
        result = subprocess.run(
            [str(self.binaries / "argos"), "--config", str(config), *map(str, arguments)],
            capture_output=True, text=True, timeout=15, cwd=self.work, env=self.env,
        )
        require((result.returncode == 0) == success,
                f"argos {arguments}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
        return result

    def agent(self, config, name, success=True):
        logfile = self.work / f"{name}.log"
        log = logfile.open("w")
        process = subprocess.Popen(
            [str(self.binaries / "argos-agent"), "--config", str(config)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            cwd=self.work, env=self.env,
        )
        self.processes.append((process, log))
        if not success:
            require(process.wait(timeout=12) != 0, f"{name}: rejected policy started an agent")
            require("이벤트 파이프라인 가동" not in logfile.read_text(), f"{name}: fallback agent started")
        else:
            def ready():
                require(process.poll() is None, f"{name} exited early:\n{logfile.read_text()}")
                return "이벤트 파이프라인 가동" in logfile.read_text()
            wait_until(ready, f"{name}: agent did not start")
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)

    def close(self):
        for process, log in reversed(self.processes):
            self.stop(process)
            if log:
                log.close()

    def record(self, name, expected, observed):
        self.results.append(dict(scenario=name, expected=expected, observed=observed, passed=True))
        print(f"PASS {name}", flush=True)

    def replace(self, path, text):
        replacement = self.work / "replacement.txt"
        replacement.write_text(text)
        replacement.replace(path)

    def semantic_and_retention(self):
        watched = self.work / "watched"
        watched.mkdir()
        fixtures = {
            "authorized_keys": ("ssh-ed25519 AAAA fixture\n", "linux.authorized_keys"),
            "sudoers": ("alice ALL=(root) /bin/ls\n", "linux.sudoers"),
            "crontab": ("0 1 * * * /bin/true\n", "linux.cron"),
            "fixture.service": ("[Service]\nUser=nobody\nExecStart=/bin/true\n", "linux.systemd"),
        }
        paths = [watched / name for name in fixtures]
        for path in paths:
            path.write_text(fixtures[path.name][0])
        database, backup, config = self.work / "events.db", self.work / "backup", self.work / "argos.toml"
        config.write_text(f'''watch_paths = [{json.dumps(str(watched))}]
db_path = {json.dumps(str(database))}
sensor = "notify"
[response]
auto_block = false
[process_monitor]
enabled = true
interval_ms = 100
[semantic]
files = {json.dumps([str(path) for path in paths])}
[backup]
enabled = true
dir = {json.dumps(str(backup))}
max_file_bytes = 1048576
keep_versions = 0
baseline_on_start = true
''')
        agent = self.agent(config, "semantic-agent")
        index = backup / "index.db"
        baseline = {}
        for path in paths:
            version = wait_until(lambda: rows(index, "SELECT id FROM versions WHERE path=? ORDER BY id", (str(path),)), f"no baseline for {path}")[0][0]
            baseline[path.name] = version
            self.cli(config, "restore", path, "--mark-good", version, "--note", "scenario fixture reviewed")

        # Use atomic replacement to avoid asserting on a transient truncated file.
        for path in paths:
            before = rows(database, "SELECT COUNT(*) FROM file_events WHERE path=?", (str(path),))[0][0]
            neutral = "# harmless operator comment\n" + fixtures[path.name][0]
            if path.name == "authorized_keys":
                neutral = "ssh-ed25519 AAAA changed human's comment\n"
            self.replace(path, neutral)
            wait_until(lambda: rows(database, "SELECT COUNT(*) FROM file_events WHERE path=?", (str(path),))[0][0] > before, "neutral edit was not observed")
        time.sleep(0.25)
        count = rows(database, "SELECT COUNT(*) FROM detections WHERE rule LIKE 'linux.%'")[0][0]
        require(count == 0, f"neutral comments created {count} semantic alarms")
        self.record("semantic neutral comments", "0 semantic alarms after four observed edits", count)

        changes = {
            "authorized_keys": "ssh-ed25519 AAAA fixture\nssh-ed25519 BBBB added-key\n",
            "sudoers": "alice ALL=(ALL) NOPASSWD: ALL\n",
            "crontab": "@reboot /bin/true\n",
            "fixture.service": "[Service]\nUser=root\nExecStart=/bin/true\n",
        }
        detected = []
        for name, content in changes.items():
            self.replace(watched / name, content)
            rule = fixtures[name][1]
            wait_until(lambda: rows(database, "SELECT id FROM detections WHERE rule=?", (rule,)), f"missing {rule} detection")
            detected.append(rule)
        self.record("semantic configuration changes", "SSH key / sudo rule / cron job / service changes detected", detected)
        key_path = watched / "authorized_keys"
        auto_pins = wait_until(lambda: [pin for pin in json.loads(self.cli(config, "retention", "list").stdout)
                                       if pin["version_id"] == baseline["authorized_keys"] and pin["actor"] == "argos-agent"], "detection did not pin preceding known-good version")
        self.record("automatic incident retention", "known-good key-file baseline pinned by agent", [pin["incident_id"] for pin in auto_pins])
        self.process_exec(config, database)
        self.stop(agent)
        require(agent.returncode == 0, "semantic agent did not stop cleanly")

        version = baseline["authorized_keys"]
        for incident in ("scenario-a", "scenario-b"):
            self.cli(config, "retention", "pin", key_path, "--version", version, "--incident", incident,
                     "--actor", "fixture-operator", "--reason", "independent investigation")
        self.cli(config, "restore", key_path, "--revoke-good", version, "--note", "later review revoked trust")
        unchanged = key_path.read_bytes()
        self.cli(config, "restore", key_path, success=False)
        require(key_path.read_bytes() == unchanged, "a pinned untrusted version was restored")
        self.cli(config, "retention", "release", "--incident", "scenario-a", "--approval", "approval-a",
                 "--approver", "fixture-operator", "--reason", "self-approval must fail", success=False)
        self.cli(config, "retention", "release", "--incident", "scenario-a", "--approval", "approval-a",
                 "--approver", "fixture-reviewer", "--reason", "independent case closure")
        remaining = json.loads(self.cli(config, "retention", "list", "--incident", "scenario-b").stdout)
        require(len(remaining) == 1 and remaining[0]["version_id"] == version, "release removed another incident's pin")
        audit = json.loads(self.cli(config, "retention", "audit", "--incident", "scenario-a").stdout)
        require([entry["action"] for entry in audit] == ["pinned", "released"], "retention audit is incomplete")
        self.cli(config, "retention", "release", "--incident", "scenario-b", "--approval", "approval-a",
                 "--approver", "fixture-reviewer", "--reason", "reused approval must fail", success=False)
        self.record("incident retention and separate approval", "independent refs; untrusted restore / self-approval / approval reuse rejected",
                    dict(remaining_incident=remaining[0]["incident_id"], audit_actions=[entry["action"] for entry in audit]))
        self.evidence_package(config, database)
        self.distributed_replay(database)
        return config

    def process_exec(self, config, database):
        gate = self.work / "exec-gate"
        sleeper = shutil.which("sleep")
        require(sleeper is not None, "sleep executable is required")
        code = "import os,sys,time; from pathlib import Path\nwhile not Path(sys.argv[1]).exists(): time.sleep(.05)\nos.execv(sys.argv[2], [sys.argv[2], '30'])\n"
        child = subprocess.Popen([sys.executable, "-c", code, str(gate), sleeper], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append((child, None))
        before = wait_until(lambda: rows(database, "SELECT exe,start_time_ticks,boot_id FROM process_events WHERE pid=? ORDER BY id", (child.pid,)), "child initial image not observed")[0]
        gate.touch()
        def changed():
            return [row for row in rows(database, "SELECT exe,start_time_ticks,boot_id FROM process_events WHERE pid=? ORDER BY id", (child.pid,)) if row[0] == str(Path(sleeper).resolve())]
        after = wait_until(changed, "same-PID exec image change not observed")[0]
        require(before[0] != after[0] and before[1:] == after[1:], "exec changed process identity instead of only its image")
        evidence = json.loads(self.cli(config, "evidence", "--from-ms", 0, "--to-ms", int(time.time() * 1000) + 1000,
                                       "--pid", child.pid, "--limit", 20).stdout)
        events = [row["event"] for row in evidence["processes"]["rows"]]
        require(len(events) >= 2 and all(event["credentials"] for event in events), "credential snapshots missing")
        require(all(len(event["credentials"]["uids"]) == 4 and len(event["credentials"]["gids"]) == 4
                    and "cap_effective" in event["credentials"] for event in events), "UID/GID/capability evidence incomplete")
        self.stop(child)
        self.record("same-PID exec and credential evidence", "image changes; PID/start/boot identity stable; four UID/GID values and capabilities collected",
                    dict(before_image=before[0], after_image=after[0], records=len(events)))

    def distributed_replay(self, database):
        # Historical synthetic rows, not a live privileged sensor or real attack.
        first_ms = 1_000_000
        with sqlite3.connect(database) as connection:
            for index in range(5):
                event = dict(timestamp_ms=first_ms + index * 110_000, pid=100_000 + index,
                             path=f"/fixture/replay/document-{index}", action="Modify", size=4096,
                             entropy=7.9, content=None,
                             process=dict(uid=1000, exe="/fixture/task", start_time_ticks=100 + index,
                                          boot_id="scenario-boot", ancestors=[dict(pid=99_999, start_time_ticks=50, boot_id="scenario-boot")]))
                connection.execute("INSERT INTO file_events(timestamp_ms,pid,path,action,size,entropy,event_json) VALUES(?,?,?,?,?,?,?)",
                                   (event["timestamp_ms"], event["pid"], event["path"], event["action"], event["size"], event["entropy"], json.dumps(event)))
        config = self.work / "replay.toml"
        config.write_text(f'db_path = {json.dumps(str(database))}\nsensor = "fanotify"\n')
        candidate = self.work / "candidate.toml"
        candidate.write_text("""version = 1
[detection.multi_window]
enabled = true
protected_paths = ["/fixture/replay"]
[[detection.multi_window.windows]]
window_secs = 10
min_changed_files = 5
mass_change_threshold = 5
detect_score = 80.0
[[detection.multi_window.windows]]
window_secs = 60
min_changed_files = 5
mass_change_threshold = 5
detect_score = 80.0
[[detection.multi_window.windows]]
window_secs = 600
min_changed_files = 5
mass_change_threshold = 5
detect_score = 80.0
[detection.content_sampling]
enabled = true
[response]
auto_block = true
block_score = 80.0
""")
        def dump():
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
                return "\n".join(connection.iterdump())
        original = dump()
        report = json.loads(self.cli(config, "policy", "simulate", "--candidate", candidate,
                                     "--from-ms", first_ms, "--to-ms", first_ms + 440_000).stdout)
        require(report["coverage"]["evaluated_events"] == 5 and report["coverage"]["truncated"] is False,
                "distributed replay did not cover the five historical events")
        require(report["baseline"]["alerts"] == 0, "baseline short window unexpectedly detected the distributed fixture")
        result = report["candidate"]
        require(result["aggregate_alerts"] >= 3 and result["alerts"] > 0, "long-window path/user/ancestry aggregation missed distributed fixture")
        require(result["would_block_pids"] == [] and result["threshold_targets"] == [],
                "aggregate-only evidence proposed killing an individual PID")
        require(any("표본" in warning for warning in report["warnings"]), "missing historic content sample coverage was not reported")
        require(dump() == original, "policy simulation mutated the evidence database")
        self.record("distributed historical policy replay", "5 PID instances over 440 seconds: aggregate alerts; no single-PID block; absent content samples disclosed; DB unchanged",
                    dict(aggregate_alerts=result["aggregate_alerts"], would_block_pids=result["would_block_pids"], evaluated_events=5))

    def evidence_package(self, config, database):
        incident = rows(database, "SELECT id FROM detections WHERE rule='linux.authorized_keys' ORDER BY id LIMIT 1")[0][0]
        destination = self.work / "evidence-package"
        self.cli(config, "evidence-export", incident, "--out", destination)
        self.cli(config, "evidence-verify", destination)
        manifest = json.loads((destination / "manifest.json").read_text())
        require(manifest["include_sensitive"] is False and manifest["collected_at_ms"] > 0,
                "package does not declare redaction/collection time")
        for name, details in manifest["files"].items():
            content = (destination / name).read_bytes()
            require(hashlib.sha256(content).hexdigest() == details["sha256"] and len(content) == details["size_bytes"],
                    f"independent package checksum failed: {name}")
            require(str(self.work) not in content.decode(), f"private fixture path leaked into {name}")
        exported = json.loads((destination / "evidence.json").read_text())
        require(exported["incident"]["id"] == incident, "redaction removed incident evidence ID")
        require(exported["incident"]["paths"] == "[REDACTED]", "incident paths were not masked")
        original = (destination / "evidence.json").read_bytes()
        self.cli(config, "evidence-export", incident, "--out", destination, success=False)
        require((destination / "evidence.json").read_bytes() == original, "existing package overwritten")
        (destination / "evidence.json").write_bytes(b"{}")
        self.cli(config, "evidence-verify", destination, success=False)
        (destination / "evidence.json").write_bytes(original)
        extra = destination / "unexpected.txt"
        extra.write_text("unlisted")
        self.cli(config, "evidence-verify", destination, success=False)
        extra.unlink()
        self.cli(config, "evidence-verify", destination)
        self.record("incident evidence package", "redacted paths; evidence IDs retained; independent hashes match; overwrite/tamper/unlisted files rejected",
                    dict(incident_id=incident, files=sorted(manifest["files"]), redacted=True))

    def policy(self, base_config):
        key_output = self.cli(base_config, "policy", "gen-key").stdout
        keys = re.findall(r"(?m)^[0-9a-fA-F]{64}$", key_output)
        require(len(keys) == 2, "key generation did not return secret/public keys")
        secret, public = keys
        key_file = self.work / "policy.key"
        key_file.write_text(secret)
        key_file.chmod(0o600)
        policy = self.work / "policy.toml"
        config = self.work / "policy-agent.toml"
        database = self.work / "policy-events.db"
        config.write_text(f'''watch_paths = [{json.dumps(str(self.work / "policy-watch"))}]
db_path = {json.dumps(str(database))}
sensor = "notify"
[backup]
enabled = false
[process_monitor]
enabled = false
[policy]
path = {json.dumps(str(policy))}
policy_id = "scenario"
host_id = "host-1"
groups = ["web"]
[policy.trusted_keys]
signer-1 = "{public}"
''')
        now = int(time.time() * 1000)
        def document(version, host="host-1", expiry=None, score=45.0):
            return f'''version = {version}
policy_id = "scenario"
key_id = "signer-1"
issued_at_ms = {now - 10000}
not_before_ms = {now - 10000}
expires_at_ms = {now + 3600000 if expiry is None else expiry}
target_hosts = [{json.dumps(host)}]
target_groups = ["web"]
[detection]
detect_score = {score}
[response]
auto_block = false
'''
        def sign(text):
            policy.write_text(text)
            self.cli(base_config, "policy", "sign", policy, "--key-file", key_file)
        def status():
            return json.loads(self.cli(config, "policy", "status", "--limit", 30).stdout)
        original = document(2)
        sign(original)
        first = self.agent(config, "policy-first")
        self.stop(first)
        accepted = status()
        require(accepted["active"]["version"] == 2, "policy high-watermark not recorded")
        restarted = self.agent(config, "policy-restart")
        self.stop(restarted)
        require(any(entry["outcome"] == "restarted" for entry in status()["audit"]), "identical restart was not audited")
        rejections = []
        for name, text, reason in [
            ("downgrade", document(1), "version_downgrade"),
            ("reuse", document(2, score=50.0), "version_reuse"),
            ("expired", document(3, expiry=now - 1000), "expired"),
            ("wrong-host", document(3, host="different-host"), "host_target_mismatch"),
        ]:
            sign(text)
            self.agent(config, f"policy-{name}", success=False)
            snapshot = status()
            require(snapshot["active"]["version"] == 2 and snapshot["active"]["sha256"] == accepted["active"]["sha256"], f"{name} changed active policy")
            require(snapshot["audit"][0]["reason"] == reason, f"{name}: wrong rejection audit {snapshot['audit'][0]}")
            rejections.append(reason)
        sign(original)
        resumed = self.agent(config, "policy-restored-original")
        self.stop(resumed)
        self.record("persistent policy trust", "same-version identical restart allowed; downgrade/reuse/expiry/host mismatch refused with unchanged active policy", rejections)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=Path(os.environ.get("ARGOS_BIN_DIR", "target/debug")))
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--report", type=Path, help="write a JSON report to a new file")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("these scenarios require Linux /proc and notify")
    binaries = args.bin_dir.resolve()
    for binary in ("argos", "argos-agent"):
        require((binaries / binary).is_file(), f"missing binary: {binaries / binary}")
    work = Path(tempfile.mkdtemp(prefix="argos-security-scenarios-"))
    runner = Scenarios(binaries, work)
    passed = False
    try:
        config = runner.semantic_and_retention()
        runner.policy(config)
        report = dict(passed=True, scenarios=runner.results,
                      limitations=["Polling does not capture every short-lived exec or credential change.",
                                   "No privileged UID transitions, host system configuration, network isolation, or real ransomware executed.",
                                   "Prune concurrency and multi-window/partial-encryption fixture coverage are exercised by Rust tests."])
        (work / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        if args.report:
            with args.report.open("x") as output:
                json.dump(report, output, ensure_ascii=False, indent=2)
                output.write("\n")
        passed = True
        print(f"ALL {len(runner.results)} SECURITY SCENARIOS PASSED")
    except Exception as error:
        failure = dict(passed=False, scenarios=runner.results, error=str(error))
        (work / "report.json").write_text(json.dumps(failure, ensure_ascii=False, indent=2) + "\n")
        raise
    finally:
        runner.close()
        if args.keep or not passed:
            print(f"Scenario artifacts: {work}", flush=True)
        else:
            shutil.rmtree(work)


if __name__ == "__main__":
    main()
