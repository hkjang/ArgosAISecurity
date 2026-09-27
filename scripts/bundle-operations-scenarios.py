#!/usr/bin/env python3
"""임시 TLS 경계에서 번들 자동 재개·승인 전 격리 시험을 검증한다.

서로 다른 물리 호스트 시험을 대신하지 않는다. openssl과 Linux bubblewrap이
필요하며 임시 loopback 서버·합성 SQLite·전용 0700 경로만 사용한다.
--pg-root는 합성 PostgreSQL 18 native backup의 승인 전 격리 시험을 추가한다.
"""
import argparse
import fcntl
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "bundle_recovery_helpers", Path(__file__).with_name("bundle-recovery-scenarios.py"))
HELPERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPERS)
require, wait_until = HELPERS.require, HELPERS.wait_until


def issue_certificates(root):
    ca, key, cert = root / "ca.pem", root / "tls.key", root / "tls.pem"
    commands = [
        ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-keyout", root / "ca.key", "-out", ca, "-days", "2",
         "-subj", "/CN=Argos isolated test CA", "-addext", "basicConstraints=critical,CA:TRUE"],
        ["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-keyout", key, "-out", root / "tls.csr", "-subj", "/CN=127.0.0.1"],
        ["x509", "-req", "-in", root / "tls.csr", "-CA", ca, "-CAkey", root / "ca.key",
         "-CAcreateserial", "-out", cert, "-days", "2", "-extfile", root / "extensions"],
    ]
    (root / "extensions").write_text(
        "subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
    for command in commands:
        subprocess.run(["openssl", *map(str, command)], capture_output=True,
                       text=True, check=True, timeout=15)
    return ca, cert, key


def process_descendants(pid):
    found, pending = [], [pid]
    while pending:
        parent = pending.pop()
        try:
            children = (Path("/proc") / str(parent) / "task" / str(parent) / "children").read_text().split()
        except (FileNotFoundError, PermissionError):
            continue
        for value in children:
            child = int(value)
            if child not in found:
                found.append(child)
                pending.append(child)
    return found


class Gateway:
    """HTTPS 종료 후 임시 loopback 저장 서버로만 전달. 운영 프록시가 아니다."""
    def __init__(self, port, cert, key):
        self.port = port
        self.hold_publish = False
        self.drop_ack = False
        self.entered, self.release = threading.Event(), threading.Event()
        self.completed_before_drop = False
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                upstream = None
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 <= length <= 64 * 1024 * 1024:
                        self.send_error(413)
                        return
                    data = self.rfile.read(length)
                    if self.path.endswith("/complete") and parent.hold_publish:
                        parent.hold_publish = False
                        parent.entered.set()
                        parent.release.wait(30)
                        self.close_connection = True
                        return
                    upstream = http.client.HTTPConnection("127.0.0.1", parent.port, timeout=30)
                    headers = {k: v for k, v in self.headers.items()
                               if k.lower() not in ("host", "connection")}
                    upstream.request(self.command, self.path, body=data, headers=headers)
                    response = upstream.getresponse()
                    body = response.read(64 * 1024 * 1024 + 1)
                    if self.path.endswith("/complete") and parent.drop_ack and response.status == 200:
                        parent.drop_ack = False
                        parent.completed_before_drop = True
                        self.close_connection = True
                        return
                    self.send_response(response.status)
                    self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (OSError, ValueError, http.client.HTTPException):
                    self.close_connection = True
                finally:
                    if upstream:
                        upstream.close()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"https://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)


class Scenarios(HELPERS.Scenarios):
    def __init__(self, binaries, work):
        super().__init__(binaries, work)
        self.gateway = None
        for key in list(self.env):
            if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
                self.env.pop(key)

    def setup(self):
        super().setup()
        tls = self.work / "tls"
        tls.mkdir(mode=0o700)
        ca, cert, key = issue_certificates(tls)
        self.gateway = Gateway(self.port, cert, key)
        self.pem = ca.read_text()
        for path in (self.upload_config, self.admin_config):
            lines = [line for line in path.read_text().splitlines()
                     if not line.startswith(("endpoint =", "allow_http_loopback =", "timeout_secs ="))]
            lines += [f"endpoint = {json.dumps(self.gateway.endpoint)}", "timeout_secs = 5",
                      "allow_http_loopback = false", f"tls_ca_pem = {json.dumps(self.pem)}"]
            path.write_text("\n".join(lines) + "\n")

    def close(self):
        if self.gateway:
            self.gateway.close()
        super().close()

    def transport(self):
        result = json.loads(self.vault("usage", admin=True).stdout)
        require(bool(result), "신뢰한 TLS 서버 응답 없음")
        for name, text in [
            ("untrusted", "\n".join(line for line in self.admin_config.read_text().splitlines()
                                     if not line.startswith("tls_ca_pem ="))),
            ("hostname", self.admin_config.read_text().replace(self.gateway.endpoint,
                         self.gateway.endpoint.replace("127.0.0.1", "localhost"))),
        ]:
            config = self.work / f"{name}.toml"
            HELPERS.VAULT.private_text(config, text)
            self.cli("vault", "--vault-config", config, "usage", success=False)
        self.record("TLS 신뢰 목록·서버 이름 검증", "명시한 CA만 수락하고 신뢰 누락·서버 이름 불일치를 거부",
                    {"tls_verified": True, "untrusted_rejected": True, "hostname_rejected": True})

    def resume(self):
        source, backup = self.host / "orders.sqlite3", self.host / "backup.sqlite3"
        HELPERS.native_backup(source, backup)
        expected = HELPERS.digest_file(backup)
        plan = self.host / "plan.toml"
        plan.write_text(HELPERS.plan_text(backup))
        stage, queue = self.host / "stage", self.work / "queue"
        prepared = self.parsed("prepare", "--file", backup, "--out", stage,
                               "--original-path", source, "--plan", plan)
        self.bundle_id = prepared["bundle_id"]
        self.parsed("enqueue", "--stage", stage, "--directory", queue)
        # 등록된 TLS 신뢰 목록의 변경은 전송 전에 거부한다(공개 PEM의 같은 인증서/다른 원문).
        changed = self.work / "changed-trust.toml"
        text = self.upload_config.read_text().replace(json.dumps(self.pem), json.dumps(self.pem + "\n"))
        HELPERS.VAULT.private_text(changed, text)
        self.cli("vault", "--vault-config", changed, "queue", "drain", "--directory", queue, success=False)
        shutil.rmtree(self.host)
        require(not stage.exists() and not source.exists(), "원본 자료가 제거되지 않음")
        self.gateway.hold_publish = True
        command = [str(self.binaries / "argos"), "vault", "--vault-config", str(self.upload_config),
                   "queue", "drain", "--directory", str(queue), "--max-items", "16"]
        log = (self.work / "killed-publisher.log").open("w")
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                   stderr=subprocess.STDOUT, cwd=self.work, env=self.env)
        try:
            require(self.gateway.entered.wait(20), "청크 전송 후 자동 완료 단계에 도달하지 못함")
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            log.close()
            self.gateway.release.set()
        jobs = json.loads(self.cli("vault", "queue", "jobs", "--directory", queue).stdout)
        require(jobs["pending"] == 1 and jobs["leased"] == 1, "중단된 게시 임대가 영속되지 않음")
        self.record("stage 삭제·게시 직전 프로세스 종료", "고정 구성 목록과 청크가 큐에 남고 중단 임대가 보존됨",
                    {"source_removed": True, "leased_job": True, "trust_change_rejected": True})
        self.gateway.drop_ack = True
        deadline = time.monotonic() + 95
        restarted = False
        while time.monotonic() < deadline:
            result = subprocess.run(command, capture_output=True, text=True, env=self.env,
                                    cwd=self.work, timeout=35)
            require(result.returncode in (0, 1), "재시도 프로세스 비정상 종료")
            if self.gateway.completed_before_drop and not restarted:
                self.restart()
                restarted = True
            jobs = json.loads(self.cli("vault", "queue", "jobs", "--directory", queue).stdout)
            if jobs["complete"] == 1:
                break
            time.sleep(.4)
        require(jobs["complete"] == 1 and jobs["pending"] == 0, "임대 만료·ACK 유실 후 자동 완료 실패")
        require(restarted, "원격 완료 ACK 유실 및 서버 재시작 경로 미실행")
        record = self.parsed("show", "--agent-id", HELPERS.AGENT, "--id", self.bundle_id, admin=True)
        require(record["manifest"]["sha256"] == expected and record["completion"] is not None,
                "원본 없는 최종 완료 증명 불일치")
        require(record["current_review"] == "unknown" and not record["recommended"], "자동 게시가 승인으로 승격됨")
        self.record("임대 만료·ACK 유실·서버 재시작 후 자동 게시", "수동 publish나 원본 stage 없이 서명 완료 증명을 재확인",
                    {"complete": True, "current_review": "unknown", "sha256": expected})

    def preapproval(self):
        self.parsed("test", "--agent-id", HELPERS.AGENT, "--id", self.bundle_id,
                    "--out", self.work / "normal-before", admin=True, success=False)
        result = self.parsed("test", "--agent-id", HELPERS.AGENT, "--id", self.bundle_id,
                             "--preapproval", "--out", self.work / "preapproval", admin=True)
        require(result["trial_passed"] is True and result["recommended"] is False
                and result["operational_restore_authorized"] is False,
                "승인 전 시험이 운영 복구 승인으로 표시됨")
        current = self.parsed("show", "--agent-id", HELPERS.AGENT, "--id", self.bundle_id, admin=True)
        require(current["current_review"] == "unknown" and not current["recommended"], "시험이 원격 판정을 변경함")
        self.bundle("fetch", "--agent-id", HELPERS.AGENT, "--id", self.bundle_id,
                    "--out", self.work / "before-approval.sqlite3", admin=True, success=False)
        self.review(self.bundle_id, "good", "post-trial-approval")
        self.trial(self.bundle_id, self.work / "approved-trial", True)
        self.review(self.bundle_id, "revoked", "post-trial-revocation")
        revoked = self.parsed("test", "--agent-id", HELPERS.AGENT, "--id", self.bundle_id,
                              "--preapproval", "--out", self.work / "revoked-trial", admin=True, success=False)
        require(not revoked["trial_passed"] and not revoked["recommended"], "취소본의 승인 전 시험 허용")
        self.record("승인 전 격리 시험과 운영 승인 분리", "unknown 시험 성공 후에도 fetch 거부, 명시적 승인 뒤 정상 시험, 취소 뒤 거부",
                    {"preapproval_passed": True, "approval_unchanged_by_test": True,
                     "operational_restore_authorized_before_review": False, "revoked_rejected": True})

    def postgres_preapproval(self, pg_root):
        spec = importlib.util.spec_from_file_location(
            "service_recovery_fixture", Path(__file__).with_name("service-recovery-scenarios.py"))
        service = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(service)
        source = self.work / "postgresql-original"
        source.mkdir(mode=0o700)
        backup = service.postgres_fixture(source, pg_root)
        expected_hash = hashlib.sha256(backup.read_bytes()).hexdigest()
        plan, stage = source / "plan.toml", source / "stage"
        plan.write_text(service.plan_text(backup, "postgresql", pg_root, timeout=15))
        prepared = self.parsed("prepare", "--file", backup, "--out", stage,
                               "--original-path", "/var/lib/postgresql/orders.dump", "--plan", plan)
        bundle_id = prepared["bundle_id"]
        complete = self.parsed("upload", "--stage", stage)
        require(complete["completion"] is not None and complete["current_review"] == "unknown",
                "PostgreSQL 미승인 완료 fixture 오류")
        shutil.rmtree(source)
        marker = self.work / "postgresql-host-marker"
        marker.write_bytes(b"HOST-FILE-MUST-NOT-ENTER-POSTGRESQL")
        out, observed, postgres_observed = self.work / "postgresql-preapproval", set(), set()
        with marker.open("rb") as host_file, socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with socket.create_connection(listener.getsockname()) as connection:
                peer, _ = listener.accept()
                with peer:
                    descriptors = [fcntl.fcntl(fd, fcntl.F_DUPFD, 200)
                                   for fd in (host_file.fileno(), connection.fileno())]
                    try:
                        for fd in descriptors:
                            os.set_inheritable(fd, True)
                        forbidden = {os.readlink(f"/proc/self/fd/{fd}") for fd in descriptors}
                        stdout_path = self.work / "postgresql-preapproval.stdout.json"
                        stderr_path = self.work / "postgresql-preapproval.stderr.log"
                        command = [str(self.binaries / "argos"), "--config", str(self.agent_config),
                                   "vault", "--vault-config", str(self.admin_config), "bundle", "test",
                                   "--agent-id", HELPERS.AGENT, "--id", bundle_id,
                                   "--preapproval", "--out", str(out)]
                        with stdout_path.open("x") as stdout_log, stderr_path.open("x") as stderr_log:
                            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout_log,
                                                     stderr=stderr_log, env=self.env, cwd=self.work,
                                                     pass_fds=descriptors)
                            try:
                                deadline = time.monotonic() + 40
                                while child.poll() is None:
                                    require(time.monotonic() < deadline, "PostgreSQL 승인 전 시험 제한 시간 초과")
                                    for pid in process_descendants(child.pid):
                                        try:
                                            command_line = (Path("/proc") / str(pid) / "cmdline").read_bytes()
                                            arguments = command_line.split(b"\0")
                                            executable = Path(os.fsdecode(arguments[0])).name
                                            is_postgres = executable.startswith("postgres")
                                            if b"service-recovery-worker" not in arguments and not is_postgres:
                                                continue
                                            for fd in (Path("/proc") / str(pid) / "fd").iterdir():
                                                try:
                                                    require(os.readlink(fd) not in forbidden,
                                                            "PostgreSQL 작업자에 호스트 파일·소켓 FD 상속")
                                                except FileNotFoundError:
                                                    pass
                                            observed.add(pid)
                                            if is_postgres:
                                                postgres_observed.add(pid)
                                        except (FileNotFoundError, PermissionError):
                                            pass
                                    time.sleep(.02)
                            finally:
                                self.stop(child)
                        stdout, stderr = stdout_path.read_text(), stderr_path.read_text()
                        require(child.returncode == 0, f"PostgreSQL 승인 전 시험 실패: {stdout} {stderr}")
                        result = json.loads(stdout)
                    finally:
                        for fd in descriptors:
                            os.close(fd)
        require(bool(observed) and bool(postgres_observed), "PostgreSQL 실제 worker FD 관찰 누락")
        require(result["trial_passed"] is True and result["recommended"] is False
                and result["operational_restore_authorized"] is False
                and result["report_authenticated"] is False, "PostgreSQL 시험과 승인 상태 혼동")
        require(result["drill_report"]["engine"] == "postgresql"
                and result["drill_report"]["status"] == "passed"
                and result["verification"]["backup_sha256"] == expected_hash,
                "PostgreSQL 원격 백업·검사 보고서 결합 오류")
        require(json.loads((out / "bundle-test.json").read_text()) == result,
                "PostgreSQL stdout/영속 요약 불일치")
        require("PRIVATE-FIXTURE-DATA" not in stdout + stderr, "PostgreSQL 행 내용 출력 노출")
        current = self.parsed("show", "--agent-id", HELPERS.AGENT, "--id", bundle_id, admin=True)
        require(current["current_review"] == "unknown" and not current["recommended"],
                "PostgreSQL 승인 전 시험이 원격 정상 판정을 변경함")
        self.bundle("fetch", "--agent-id", HELPERS.AGENT, "--id", bundle_id,
                    "--out", self.work / "postgresql-unapproved-fetch.dump", admin=True, success=False)
        with socket.socket(socket.AF_UNIX) as connection:
            try:
                connection.connect(str(out / "drill/postgresql/socket/.s.PGSQL.5432"))
            except (FileNotFoundError, ConnectionRefusedError):
                pass
            else:
                raise AssertionError("시험 후 PostgreSQL 서버가 남았습니다")
        self.record("PostgreSQL 원본 없는 승인 전 시험·상속 FD 차단",
                    "합성 native dump와 원본 계획 삭제 후 unknown 시험 성공, 정상본 미승격, 기본 fetch 거부",
                    {"trial_passed": True, "operational_restore_authorized": False,
                     "recommended": False, "report_authenticated": False, "current_review": "unknown",
                     "native_backup_sha256": expected_hash, "native_backup_bytes": complete["manifest"]["size_bytes"],
                     "original_host_deleted": True, "normal_fetch_refused": True,
                     "postgres_server_cleaned": True, "inherited_file_socket_fds_blocked": True,
                     "observed_worker_processes": len(observed),
                     "observed_postgres_processes": len(postgres_observed), "postgres_major": 18})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--pg-root", type=Path, help="신뢰된 PostgreSQL 18 설치 경로: 선택적 승인 전 시험 추가")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if not shutil.which("openssl") or not Path("/usr/bin/bwrap").is_file():
        parser.error("openssl과 /usr/bin/bwrap이 필요합니다. 무격리 시험으로 대체하지 않습니다.")
    with args.report.open("x") as output:
        os.chmod(args.report, 0o600)
        previous = os.umask(0o077)
        work = Path(tempfile.mkdtemp(prefix="argos-bundle-operations-"))
        suite = Scenarios(args.bin_dir.resolve(), work)
        report = {"suite": "bundle-operations-tls", "passed": False, "scenarios": suite.results,
                  "work_dir": str(work), "physical_hosts": 1, "tls_terminated_at_test_gateway": True}
        try:
            report["version"] = suite.cli("--version").stdout.strip()
            suite.setup()
            suite.transport()
            suite.resume()
            suite.preapproval()
            if args.pg_root:
                suite.postgres_preapproval(args.pg_root.resolve())
            report["postgresql_tested"] = args.pg_root is not None
            report["passed"] = True
        except (AssertionError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            report["error"] = str(error)
            print(f"FAIL: {error}", file=sys.stderr, flush=True)
        finally:
            suite.close()
            report["passed_scenarios"] = len(suite.results)
            report["temporary_files_retained"] = bool(args.keep or not report["passed"])
            output.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
            if report["temporary_files_retained"]:
                print(f"임시 결과 보존: {work}", flush=True)
            else:
                shutil.rmtree(work)
            os.umask(previous)
        return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
