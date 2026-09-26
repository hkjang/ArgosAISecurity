#!/usr/bin/env python3
"""빌드된 바이너리의 인증·근거 조회·복구 통합 검증. root/외부 서비스 불필요.

사용: ARGOS_BIN_DIR=/tmp/argos-target/debug python3 scripts/platform-smoke.py
실패 시 로그 경로를 출력하며 --keep으로 임시 결과를 보존할 수 있다.
"""

import argparse
import html.parser
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def wait_until(predicate, message, timeout=10):
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
    raise AssertionError(f"{message}; 마지막 오류: {last_error}")


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def http(base, path, token=None, data=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base + path,
        data=None if data is None else json.dumps(data).encode(),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def sql_rows(database, query, values=()):
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        return connection.execute(query, values).fetchall()


class Smoke:
    def __init__(self, binaries, work):
        self.binaries = binaries
        self.work = work
        self.processes = []
        self.env = os.environ.copy()
        self.env.pop("ARGOS_CENTRAL_TOKEN", None)
        self.env["RUST_LOG"] = "info"

    def command(self, name, *arguments, expected=0, input_text=None):
        result = subprocess.run(
            [str(self.binaries / name), *map(str, arguments)],
            input=input_text, text=True, capture_output=True, timeout=15,
            cwd=self.work, env=self.env,
        )
        require(
            result.returncode == expected if expected is not None else result.returncode != 0,
            f"{name} {arguments}: 종료 {result.returncode}\n{result.stdout}\n{result.stderr}",
        )
        return result

    def start(self, name, label, *arguments):
        log = (self.work / f"{label}.log").open("w+")
        process = subprocess.Popen(
            [str(self.binaries / name), *map(str, arguments)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            cwd=self.work, env=self.env,
        )
        self.processes.append((process, log))
        return process

    @staticmethod
    def stop(process):
        if process.poll() is not None:
            return
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
            log.close()

    def central_checks(self):
        # 운영 모드 인증 필수, 개발 모드는 명시적 loopback 바인딩만 허용.
        self.command("argos-central", "--listen", "127.0.0.1:0", "--db", self.work / "missing-auth.db", expected=None)
        self.command("argos-central", "--development", "--listen", "0.0.0.0:0", "--db", self.work / "public-dev.db", expected=None)
        dev_port = available_port()
        dev_base = f"http://127.0.0.1:{dev_port}"
        dev = self.start("argos-central", "development", "--development", "--listen", f"127.0.0.1:{dev_port}", "--db", self.work / "dev.db")
        wait_until(lambda: http(dev_base, "/healthz")[0] == 200, "개발 서버 시작 실패")
        require(http(dev_base, "/api/v1/agents")[0] == 200, "개발 loopback 조회 실패")
        self.stop(dev)

        tokens = {"host-a": "fixture-a-token", "host-b": "fixture-b-token"}
        token_file = self.work / "agent-tokens.json"
        token_file.write_text(json.dumps(tokens))
        port = available_port()
        base = f"http://127.0.0.1:{port}"
        admin = "fixture-admin-token"
        self.start("argos-central", "production", "--listen", f"127.0.0.1:{port}", "--db", self.work / "central.db", "--token", admin, "--agent-tokens", token_file)
        wait_until(lambda: http(base, "/healthz")[0] == 200, "운영 서버 시작 실패")
        require(http(base, "/api/v1/agents")[0] == 401, "무인증 관리자 조회 허용")
        require(http(base, "/api/v1/agents", tokens["host-a"])[0] == 401, "에이전트 토큰에 관리자 권한 부여")
        register = {"agent_id": "host-a", "hostname": "fixture-a", "tags": []}
        require(http(base, "/api/v1/agents/register", admin, register)[0] == 401, "관리자 토큰으로 에이전트 가장 허용")
        require(http(base, "/api/v1/agents/register", tokens["host-b"], register)[0] == 401, "다른 에이전트 토큰으로 등록 허용")
        require(http(base, "/api/v1/agents/register", tokens["host-a"], register)[0] == 200, "정상 에이전트 등록 실패")
        report = dict(agent_id="host-a", delivery_id="fixture-delivery-1", timestamp_ms=1000,
                      rule="fixture.test", score=90, severity="critical", summary="local fixture",
                      pid=4242, paths=["/fixture/document"])
        require(http(base, "/api/v1/detections", tokens["host-b"], report)[0] == 401, "다른 에이전트 탐지 가장 허용")
        for _ in range(2):
            require(http(base, "/api/v1/detections", tokens["host-a"], report)[0] == 200, "탐지 전달 실패")
        require(len(json.loads(http(base, "/api/v1/detections", admin)[1])) == 1, "같은 전달 ID가 중복 저장됨")
        heartbeat = dict(agent_id="host-a", sensor_healthy=False, outbox_pending=2, failed_attempts=3)
        require(http(base, "/api/v1/agents/heartbeat", tokens["host-b"], heartbeat)[0] == 401, "다른 에이전트 생존 신호 가장 허용")
        require(http(base, "/api/v1/agents/heartbeat", tokens["host-a"], heartbeat)[0] == 200, "생존 신호 저장 실패")
        status = json.loads(http(base, "/api/v1/agents", admin)[1])[0]
        require(status["sensor_healthy"] is False and status["outbox_pending"] == 2 and status["failed_attempts"] == 3, "보호 중단 상태가 조회에 반영되지 않음")
        print("PASS 중앙 인증·에이전트 신원·재전송 중복 제거·생존 신호")

    def agent_and_recovery_checks(self):
        watched = self.work / "watched"
        watched.mkdir()
        target = watched / "business.txt"
        original = b"verified business fixture\n"
        target.write_bytes(original)
        database = self.work / "events.db"
        backup = self.work / "backup"
        config = self.work / "argos.toml"
        config.write_text(f'''watch_paths = [{json.dumps(str(watched))}]
db_path = {json.dumps(str(database))}
sensor = "notify"
[response]
auto_block = false
[process_monitor]
enabled = false
[backup]
enabled = true
dir = {json.dumps(str(backup))}
max_file_bytes = 1048576
keep_versions = 5
baseline_on_start = true
''')
        agent = self.start("argos-agent", "agent", "--config", config)
        index = backup / "index.db"
        baseline = wait_until(lambda: sql_rows(index, "SELECT id, known_good FROM versions WHERE path=? ORDER BY id", (str(target),)), "기준 백업 생성 실패")[0]
        require(baseline[1] == 0, "기준 백업이 자동으로 정상 판정됨")
        target.write_bytes(b"unreviewed changed fixture\n")
        wait_until(lambda: len(sql_rows(index, "SELECT id FROM versions WHERE path=?", (str(target),))) >= 2, "변경 백업 수집 실패")
        health_path = database.with_suffix(".health.json")
        health = wait_until(lambda: json.loads(health_path.read_text()), "에이전트 상태 파일 없음")
        require(health["sensor"]["alive"] is True, "기동 센서 상태가 비활성으로 기록됨")
        self.stop(agent)
        require(agent.returncode == 0, "에이전트 정상 종료 실패")
        cli = lambda *args, **kwargs: self.command("argos", "--config", config, *args, **kwargs)
        damaged = target.read_bytes()
        cli("restore", target, expected=None)
        require(target.read_bytes() == damaged, "정상본 없는 복구가 원본을 변경")
        preview = self.work / "preview.txt"
        cli("restore", target, "--version", baseline[0], "--preview", preview)
        require(preview.read_bytes() == original and target.read_bytes() == damaged, "미리보기의 원본 보존 실패")
        cli("restore", target, "--version", baseline[0], "--preview", preview, expected=None)
        cli("restore", target, "--mark-good", baseline[0], "--note", "독립 스모크 정상 내용 대조")
        cli("recovery-status", "--test", target)
        require(target.read_bytes() == damaged, "복구 시험이 원본을 변경")
        owner_before = target.stat()
        if os.name == "posix":
            target.chmod(0o6755)
        cli("restore", target)
        require(target.read_bytes() == original, "최신 변경본 대신 지정 정상본 복구 실패")
        owner_after = target.stat()
        if os.name == "posix":
            require(stat.S_IMODE(owner_after.st_mode) == 0o755, "복구 과정에서 setuid/setgid가 보존됨")
            require((owner_after.st_uid, owner_after.st_gid) == (owner_before.st_uid, owner_before.st_gid), "복구 과정에서 소유권이 변경됨")
        readiness = json.loads(cli("recovery-status").stdout)
        row = next(row for row in readiness["paths"] if row["path"] == str(target))
        require(row["known_good_versions"] == 1 and row["last_restore_test_ok"] is True, "복구 준비도 정상본/시험 정보 누락")
        recovery_html = self.work / "recovery.html"
        cli("recovery-status", "--html", recovery_html)
        require(report_payload(recovery_html)["kind"] == "recovery", "복구 보고서 종류 오류")
        cli("recovery-status", "--html", recovery_html, expected=None)
        print("PASS 실제 에이전트 수집·상태·미리보기·정상본 복구·복구 시험")
        return config, database

    def evidence_checks(self, config, database):
        malicious = '</script><script id="injected">window.ARGOS_SMOKE=1</script>'
        context = dict(uid=1000, exe="/usr/bin/fixture", start_time_ticks=321, boot_id="fixture-boot", ancestors=[dict(pid=10, start_time_ticks=123, boot_id="fixture-boot")])
        with sqlite3.connect(database) as connection:
            for index, pid in enumerate([4242, 4242, 9090]):
                event = dict(timestamp_ms=1000 + index, pid=pid, path=f"/fixture/{index}", action="Modify", size=64, entropy=7.9, process=context)
                connection.execute("INSERT INTO file_events(timestamp_ms,pid,path,action,size,entropy,event_json) VALUES(?,?,?,?,?,?,?)", (event["timestamp_ms"], pid, event["path"], "Modify", 64, 7.9, json.dumps(event)))
            detection_id = connection.execute("INSERT INTO detections(timestamp_ms,rule,score,severity,summary,pid,paths_json) VALUES(1100,'fixture.test',90,'critical',?,4242,'[]')", (malicious,)).lastrowid
            for start in (321, 322):
                connection.execute("INSERT INTO process_events(timestamp_ms,pid,ppid,uid,comm,cmdline,start_time_ticks,boot_id,exe) VALUES(1000,4242,1,1000,'fixture','fixture --local',?,'fixture-boot','/usr/bin/fixture')", (start,))
        cli = lambda *args, **kwargs: self.command("argos", "--config", config, *args, **kwargs)
        evidence = json.loads(cli("evidence", "--from-ms", 900, "--to-ms", 1200, "--limit", 1, "--pid", 4242).stdout)
        require(evidence["files"]["total_rows"] == 2 and evidence["files"]["truncated"] is True, "기간/PID/누락 집계 오류")
        require(evidence["files"]["rows"][0]["event"]["process"] == context, "파일 이벤트 프로세스 신원 손실")
        require(evidence["processes"]["total_rows"] == 2, "PID 재사용 근거 손실")
        before = logical_dump(database)
        requests = [
            {"jsonrpc": "2.0", "id": 0, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "platform-smoke", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "query_evidence", "arguments": {"from_ms": 900, "to_ms": 1200, "pid": 4242, "limit": 1}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "restore", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 5, "method": "kill_process", "params": {"pid": 4242}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "query_evidence", "arguments": {"from_ms": 900, "to_ms": 1200, "server": "other-host"}}},
        ]
        result = cli("mcp", input_text="".join(json.dumps(request) + "\n" for request in requests))
        responses = {message["id"]: message for message in map(json.loads, result.stdout.splitlines())}
        require(set(responses) == set(range(7)), "MCP 응답 또는 알림 처리 오류")
        require(responses[0]["error"]["code"] == -32002, "MCP 초기화 전 도구 조회 허용")
        require(responses[1]["result"]["protocolVersion"] == "2025-06-18", "MCP 초기화 응답 오류")
        tools = responses[2]["result"]["tools"]
        require(len(tools) == 1 and tools[0]["annotations"]["readOnlyHint"] is True, "MCP 조회 전용 선언 오류")
        require(responses[3]["result"]["structuredContent"] == evidence, "MCP/CLI 근거 결과 불일치")
        require(all("error" in responses[index] for index in (4, 5, 6)), "MCP 변경 명령 또는 지원하지 않는 범위 허용")
        require(logical_dump(database) == before, "MCP 조회가 DB 내용을 변경")
        incident = self.work / "incident.html"
        cli("incident", detection_id, "--window-secs", 1, "--html", incident)
        payload = report_payload(incident)
        require(payload["kind"] == "incident" and payload["data"]["detection"]["summary"] == malicious, "보고서의 원문 근거 손실")
        identities = {row["event"]["start_time_ticks"] for row in payload["data"]["evidence"]["processes"]["rows"]}
        require(identities == {321, 322}, "사건 보고서에서 PID 재사용 신원 손실")
        cli("incident", detection_id, "--html", incident, expected=None)
        print("PASS 기간별 근거·PID 신원·MCP 초기화/조회 전용·HTML 안전성")


def logical_dump(database):
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        return "\n".join(connection.iterdump())


class ReportParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.payload_parts = []
        self.in_payload = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "script":
            self.scripts.append(attributes)
            self.in_payload = attributes.get("id") == "evidence"

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_payload = False

    def handle_data(self, data):
        if self.in_payload:
            self.payload_parts.append(data)


def report_payload(path):
    parser = ReportParser()
    document = path.read_text()
    parser.feed(document)
    require(len(parser.scripts) == 2, "보고서 데이터가 추가 script 태그를 생성")
    require(not any("src" in attributes for attributes in parser.scripts), "독립 보고서에 외부 스크립트 포함")
    require(not any(attributes.get("id") == "injected" for attributes in parser.scripts), "보고서 스크립트 삽입 허용")
    return json.loads("".join(parser.payload_parts))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default_bin = os.environ.get("ARGOS_BIN_DIR", str(Path(os.environ.get("CARGO_TARGET_DIR", "target")) / "debug"))
    parser.add_argument("--bin-dir", type=Path, default=Path(default_bin))
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    for name in ("argos", "argos-agent", "argos-central"):
        require((binaries / name).is_file(), f"바이너리 없음: {binaries / name}; 먼저 cargo build --workspace 실행")
    work = Path(tempfile.mkdtemp(prefix="argos-platform-smoke-"))
    smoke = Smoke(binaries, work)
    failed = False
    try:
        smoke.central_checks()
        config, database = smoke.agent_and_recovery_checks()
        smoke.evidence_checks(config, database)
        print("PLATFORM SMOKE PASS (인증·실제 수집·안전 복구·조회/MCP·보고서)")
    except Exception:
        failed = True
        print(f"검증 실패 자료: {work}")
        for path in work.glob("*.log"):
            print(f"--- {path.name} ---\n{path.read_text()[-4000:]}")
        raise
    finally:
        smoke.close()
        if args.keep or failed:
            print(f"검증 자료 보존: {work}")
        else:
            shutil.rmtree(work)


if __name__ == "__main__":
    main()
