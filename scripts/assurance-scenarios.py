#!/usr/bin/env python3
"""빌드된 CLI/에이전트의 보호 공백·예외 감사·AI 근거 검사를 통합 시험한다.

Linux, Python 표준 라이브러리와 빌드된 argos/argos-agent만 필요하다.
실제 notify는 임시 경로에서만 실행하며 자동 대응·백업은 끈다.
예외 감사의 프로세스 근거는 합성 SQLite 행이고 실제 프로세스를 차단하지 않는다.
AI는 loopback Ollama 모의 HTTP 서버만 사용한다. --report는 새 파일만 허용한다.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# 도우미를 가져올 때 저장소에 Python 캐시를 남기지 않는다.
sys.dont_write_bytecode = True

# 기존 바이너리 실행·종료/SQLite 읽기·대기 함수를 공유한다.
_spec = importlib.util.spec_from_file_location("argos_platform_smoke", Path(__file__).with_name("platform-smoke.py"))
_smoke = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_smoke)
require, wait_until, rows = _smoke.require, _smoke.wait_until, _smoke.sql_rows


class Assurance(_smoke.Smoke):
    def __init__(self, binaries, work):
        super().__init__(binaries, work)
        self.results = []
        self.current = None
        self.env.pop("ANTHROPIC_API_KEY", None)
        self.env.pop("ARGOS_AI_MODEL", None)

    def record(self, name, expected, observed):
        self.results.append(dict(scenario=name, expected=expected, observed=observed, passed=True))
        print(f"PASS {name}", flush=True)

    def cli(self, config, *arguments, success=True):
        return self.command("argos", "--config", config, *arguments, expected=0 if success else None)

    def start_agent(self, config, label):
        process = self.start("argos-agent", label, "--config", config)
        def ready():
            log = (self.work / f"{label}.log").read_text()
            require(process.poll() is None, f"{label} 조기 종료: {log}")
            return "이벤트 파이프라인 가동" in log
        wait_until(ready, f"{label} 시작 실패")
        return process

    def coverage(self):
        self.current = "notify delivery and root replacement"
        watched = self.work / "watched"
        watched.mkdir(mode=0o700)
        config, database = self.work / "coverage.toml", self.work / "events.db"
        config.write_text(f'''watch_paths = [{json.dumps(str(watched))}]
db_path = {json.dumps(str(database))}
sensor = "notify"
[response]
auto_block = false
[backup]
enabled = false
[process_monitor]
enabled = false
[coverage]
enabled = true
interval_secs = 1
max_entries = 100
''')
        agent = self.start_agent(config, "coverage-agent")
        active_report = self.work / "probe-active.json"
        result = json.loads(self.cli(config, "coverage", "probe", "--directory", watched,
                                     "--timeout-secs", 5, "--out", active_report).stdout)
        require(result["success"] and result["event_id"] > 0 and result["cleaned_up"], "실행 센서의 전달/정리 실패")
        require(result == json.loads(active_report.read_text()), "probe 표준 출력/저장 결과 불일치")
        stored = rows(database, "SELECT path,timestamp_ms FROM file_events WHERE id=?", (result["event_id"],))
        require(stored and stored[0][0] == result["probe_path"], "probe 이벤트가 실제 DB 행과 다름")
        require(not Path(result["probe_path"]).exists(), "시험 파일이 정리되지 않음")
        self.record("actual notify probe", "새 파일의 실제 notify→agent→DB 전달과 정리", result)

        health_path = database.with_suffix(".health.json")
        def healthy():
            health = json.loads(health_path.read_text())
            coverage = health.get("coverage", {})
            return health if coverage.get("report", {}).get("assessment") == "no_observed_gap" and not coverage.get("stale", True) else None
        before = wait_until(healthy, "초기 정상 coverage 상태 없음 (30초 health tick 포함)", timeout=40)
        status = json.loads(self.cli(config, "coverage", "status").stdout)
        require(not status["health_stale"], "실행 에이전트의 상태 파일이 오래됨")
        old_root = self.work / "watched-registered-inode"
        watched.rename(old_root)
        watched.mkdir(mode=0o700)
        replacement_at = int(time.time() * 1000)
        def replacement_gap():
            health = json.loads(health_path.read_text())
            coverage = health.get("coverage", {})
            report = coverage.get("report", {})
            codes = [issue["code"] for root in report.get("roots", []) for issue in root["issues"]]
            if report.get("checked_at_ms", 0) >= replacement_at and "registered_root_replaced_or_missing" in codes:
                return health
            return None
        after = wait_until(replacement_gap, "루트 inode 교체가 health에 반영되지 않음", timeout=40)
        require(after["sensor_healthy"] is False and after["coverage"]["report"]["assessment"] == "gap_or_incomplete", "루트 교체 후 정상으로 표시됨")
        self.record("registered root replacement", "새 inode를 보호 상태 정상으로 수용하지 않음", dict(
            before=before["coverage"], after=after["coverage"], sensor_healthy=after["sensor_healthy"]))
        self.stop(agent)
        require(agent.returncode == 0, "첫 에이전트 정상 종료 실패")

        # 새 루트의 센서 등록 성공을 먼저 보인 후 같은 경로에서 중단만 바꿔 비교한다.
        agent = self.start_agent(config, "coverage-restarted-agent")
        restarted = json.loads(self.cli(config, "coverage", "probe", "--directory", watched, "--timeout-secs", 5).stdout)
        require(restarted["success"], "새 루트 재시작 후 probe 실패")
        self.stop(agent)
        require(agent.returncode == 0, "두 번째 에이전트 정상 종료 실패")
        failed = self.cli(config, "coverage", "probe", "--directory", watched, "--timeout-secs", 1, success=False)
        stopped = json.loads(failed.stdout)
        require(stopped["success"] is False and stopped["event_id"] is None, "중단된 센서가 전달 성공으로 표시됨")
        require(stopped["writer_succeeded"] and stopped["cleaned_up"], "중단 시험의 파일 작성/정리 실패")
        self.record("stopped sensor probe", "같은 새 루트에서 실행 중 성공, 센서 중단 후 새 DB 이벤트 없음", dict(
            before_stop_event_id=restarted["event_id"], stopped=stopped, exit_code=failed.returncode))
        return database

    def exception_audit(self, database):
        self.current = "approved exception counterfactual"
        context = dict(uid=1000, exe="/usr/bin/assurance-fixture-deploy", start_time_ticks=123,
                       boot_id="assurance-synthetic-boot", ancestors=[])
        ids = []
        # 명시적인 합성 과거 근거. 이 PID의 실제 프로세스를 생성하거나 신호를 보내지 않는다.
        with sqlite3.connect(database) as connection:
            for index, timestamp in enumerate((1100, 1200)):
                event = dict(timestamp_ms=timestamp, pid=424242, path=f"/fixture/approved/document-{index}",
                             action="Modify", size=128, entropy=8.0, process=context, content=None)
                row = connection.execute(
                    "INSERT INTO file_events(timestamp_ms,pid,path,action,size,entropy,event_json) VALUES(?,?,?,?,?,?,?)",
                    (timestamp, event["pid"], event["path"], "Modify", 128, 8.0, json.dumps(event)))
                ids.append(row.lastrowid)
        config = self.work / "audit.toml"
        config.write_text(f'''db_path = {json.dumps(str(database))}
sensor = "fanotify"
[detection]
min_changed_files = 1
mass_change_threshold = 1
[[detection.approved_changes]]
id = "assurance-approved-deployment"
valid_from_ms = 1000
valid_until_ms = 2000
paths = ["/fixture/approved"]
exe = "/usr/bin/assurance-fixture-deploy"
uid = 1000
adjusted_rules = ["behavior.ransomware_pattern"]
[response]
auto_block = true
block_score = 80.0
''')
        before = rows(database, "SELECT (SELECT COUNT(*) FROM file_events),(SELECT COUNT(*) FROM detections),(SELECT COUNT(*) FROM response_actions)")
        audit = json.loads(self.cli(config, "policy", "audit-exceptions", "--from-ms", 1000,
                                    "--to-ms", 2000, "--max-events", 100).stdout)
        usage, comparison = audit["exceptions"][0], audit["comparison"]
        require(audit["basis"] == "stored_event_replay_with_supplied_policy", "예외 감사 근거 종류 오류")
        require(usage["replay_matched_events"] == 2 and usage["evidence_event_ids"] == ids, "승인 예외 사용 근거가 합성 2행과 불일치")
        require(comparison["baseline"]["alerts"] == 0 and comparison["candidate"]["alerts"] > 0, "예외 제거 반사실 알림 증가가 없음")
        targets = comparison["delta"]["new_block_targets"]
        require(len(targets) == 1 and targets[0]["pid"] == 424242 and targets[0]["start_time_ticks"] == 123, "예외 제거 시 예상 차단 신원 오류")
        require(before == rows(database, "SELECT (SELECT COUNT(*) FROM file_events),(SELECT COUNT(*) FROM detections),(SELECT COUNT(*) FROM response_actions)"), "읽기 전용 감사가 이벤트·탐지·대응 DB를 변경함")
        self.record("approved exception counterfactual", "합성 근거 2건 승인 매칭; 예외 제거 시 알림/예상 차단 증가; 실제 대응 없음", dict(
            evidence_event_ids=ids, replay_matched_events=usage["replay_matched_events"],
            time_status=usage["time_status"], baseline_alerts=comparison["baseline"]["alerts"],
            without_exceptions_alerts=comparison["candidate"]["alerts"], new_block_targets=targets,
            stored_counts_unchanged=True, synthetic=True))
        return ids[0]

    def ai_cli(self, database, evidence_id):
        self.current = "CLI AI evidence validation"
        state = dict(mode="valid", requests=[], errors=[])
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                try:
                    require(self.path == "/api/chat", "잘못된 AI endpoint")
                    length = int(self.headers["Content-Length"])
                    require(0 < length <= 4 * 1024 * 1024, "AI 요청 크기 상한 오류")
                    request = json.loads(self.rfile.read(length))
                    require(request["stream"] is False and request["model"] == "assurance-local-mock", "Ollama 요청 계약 오류")
                    require("Authorization" not in self.headers, "모의 AI에 자격 증명 전달")
                    prompt = request["messages"][1]["content"]
                    require('"from_ms":1000' in prompt and '"to_ms":2000' in prompt, "기간 조회가 AI 프롬프트에서 누락됨")
                    require("allowed_citations" in prompt, "검증할 인용 목록 누락")
                    state["requests"].append(dict(mode=state["mode"], model=request["model"], bytes=length))
                    cited = evidence_id if state["mode"] == "valid" else evidence_id + 1_000_000_000
                    answer = dict(facts=[dict(text="시험 근거에서 파일 변경이 관측되었습니다.", evidence=[dict(
                        kind="files", id=cited, host="local", timestamp_ms=1100)], absence_claim=False)],
                        inferences=[], unknowns=[])
                    body = json.dumps(dict(message=dict(role="assistant", content=json.dumps(answer, ensure_ascii=False)), done=True), ensure_ascii=False).encode()
                    self.send_response(200)
                except Exception as error:
                    state["errors"].append(str(error))
                    body = b'{"error":"fixture assertion failed"}'
                    self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = self.work / "ai.toml"
            config.write_text(f'''db_path = {json.dumps(str(database))}
[ai]
provider = "ollama"
endpoint = "http://127.0.0.1:{server.server_port}/api/chat"
model = "assurance-local-mock"
timeout_secs = 5
evidence_limit = 100
''')
            arguments = ("ask", "--from-ms", 1000, "--to-ms", 2000, "--pid", 424242, "저장된 시험 근거를 설명해 주세요")
            valid = self.cli(config, *arguments)
            require(f"files.id:{evidence_id}@local" in valid.stdout and "확인된 사실 (AI 분류)" in valid.stdout, "검증된 구조화 CLI 답변 누락")
            require("의미적 정확성은 자동 검증하지 못" in valid.stdout, "AI 검증 한계 표시 누락")
            state["mode"] = "invalid-id"
            invalid = self.cli(config, *arguments, success=False)
            require("AI 근거 검증 실패" in invalid.stderr and not invalid.stdout.strip(), "없는 ID를 인용한 답변이 표시됨")
            require(not state["errors"] and len(state["requests"]) == 2, f"AI mock 요청 실패: {state['errors']}")
            self.record("CLI AI evidence validation", "실제 ask CLI의 올바른 인용 수락과 없는 ID 거부; 외부 AI 호출 없음", dict(
                accepted_evidence_id=evidence_id, accepted_output=valid.stdout.strip(),
                rejected_exit_code=invalid.returncode, rejected_error=invalid.stderr.strip(),
                requests=state["requests"], external_model_called=False))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=Path(os.environ.get("ARGOS_BIN_DIR", "target/debug")))
    parser.add_argument("--report", type=Path, help="결과를 쓸 새 JSON 파일 (기존 파일 덮어쓰기 금지)")
    parser.add_argument("--keep", action="store_true", help="성공 시에도 임시 fixture와 로그 보존")
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    for name in ("argos", "argos-agent"):
        if not (binaries / name).is_file() or not os.access(binaries / name, os.X_OK):
            parser.error(f"실행 파일 없음: {binaries / name}")
    report_file = None
    if args.report:
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            report_file = os.fdopen(os.open(args.report, flags, 0o600), "w")
        except OSError as error:
            parser.error(f"새 결과 파일을 만들 수 없음: {error}")
    work = Path(tempfile.mkdtemp(prefix="argos-assurance-"))
    suite = Assurance(binaries, work)
    report = dict(format="argos-assurance-scenarios-v1", started_at_ms=int(time.time() * 1000),
                  binaries=str(binaries), fixture=str(work), passed=False, scenarios=suite.results,
                  limitations=["Linux notify 임시 경로 시험이며 fanotify·컨테이너 전체 감시를 증명하지 않습니다.",
                               "정책 감사는 합성 과거 행 재생이며 실제 차단을 실행하지 않습니다.",
                               "AI는 loopback 모의 HTTP로 응답 검증을 확인하며 실제 모델의 분석 품질을 측정하지 않습니다."])
    try:
        database = suite.coverage()
        evidence_id = suite.exception_audit(database)
        suite.ai_cli(database, evidence_id)
        report["passed"] = True
    except Exception as error:
        report["failure"] = dict(scenario=suite.current, error=str(error))
        print(f"FAIL {suite.current}: {error}", file=sys.stderr, flush=True)
    finally:
        suite.close()
        report["finished_at_ms"] = int(time.time() * 1000)
        if report_file:
            json.dump(report, report_file, ensure_ascii=False, indent=2)
            report_file.write("\n")
            report_file.flush()
            os.fsync(report_file.fileno())
            report_file.close()
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if report["passed"] and not args.keep:
            shutil.rmtree(work)
        else:
            print(f"fixture/logs: {work}", file=sys.stderr)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
