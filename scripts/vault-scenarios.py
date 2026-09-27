#!/usr/bin/env python3
"""실제 Argos CLI와 임시 원격 보관 서버의 어댑터 통합 시험.

python3 scripts/vault-scenarios.py --bin-dir /tmp/argos-recovery-target/debug \
    --report /tmp/argos-vault-scenarios.json

외부 서비스·root·운영 방화벽 변경 없이 loopback과 전용 임시 파일만 사용한다.
--keep은 성공 시에도 임시 로그/자료를 남긴다. 실패 시 자료를 보존한다.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_text(path, text):
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        output.write(text)


def rows(database, sql, parameters=()):
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        return connection.execute(sql, parameters).fetchall()


def wait_until(predicate, message, timeout=15):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (OSError, sqlite3.Error, json.JSONDecodeError) as error:
            last_error = error
        time.sleep(0.05)
    raise AssertionError(f"{message}; 마지막 오류: {last_error}")


class Scenarios:
    def __init__(self, binaries, work):
        self.binaries, self.work = binaries, work
        self.results, self.processes = [], []
        self.env = os.environ.copy()
        for key in ("ARGOS_CENTRAL_TOKEN", "ANTHROPIC_API_KEY", "ARGOS_AI_MODEL"):
            self.env.pop(key, None)
        self.env["RUST_LOG"] = "info"
        self.upload_config = work / "vault-upload.toml"
        self.admin_config = work / "vault-admin.toml"
        self.receipts = work / "receipts"
        self.receipts.mkdir(mode=0o700)

    def command(self, binary, *arguments, success=True):
        result = subprocess.run(
            [str(self.binaries / binary), *map(str, arguments)],
            stdin=subprocess.DEVNULL, text=True, capture_output=True,
            cwd=self.work, env=self.env, timeout=35,
        )
        require((result.returncode == 0) == success,
                f"{binary} {arguments}: 종료={result.returncode}\n{result.stdout}\n{result.stderr}")
        return result

    def cli(self, *arguments, success=True):
        return self.command("argos", *arguments, success=success)

    def vault(self, *arguments, admin=False, success=True):
        config = self.admin_config if admin else self.upload_config
        return self.cli("vault", "--vault-config", config, *arguments, success=success)

    def start(self, binary, label, *arguments):
        logfile = self.work / f"{label}.log"
        log = logfile.open("w", encoding="utf-8")
        process = subprocess.Popen(
            [str(self.binaries / binary), *map(str, arguments)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            cwd=self.work, env=self.env,
        )
        self.processes.append((process, log))
        return process, logfile

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

    def record(self, name, expected, observed):
        self.results.append(dict(scenario=name, expected=expected, observed=observed, passed=True))
        print(f"PASS {name}", flush=True)

    def setup(self):
        key_dir, self.storage = self.work / "keys", self.work / "remote-storage"
        key_dir.mkdir(mode=0o700)
        self.storage.mkdir(mode=0o700)
        key = key_dir / "signing.key"
        generated = json.loads(self.cli("vault", "keygen", "--out", key).stdout)
        self.public_key = generated["public_key"]
        require(len(self.public_key) == 64, "키 생성 CLI의 공개키 형식 오류")
        require(stat.S_IMODE(key.stat().st_mode) == 0o600, "서명키 권한 오류")
        upload_token, admin_token = secrets.token_hex(24), secrets.token_hex(24)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        server_config = self.work / "vault-server.toml"
        private_text(server_config, f'''bind = "127.0.0.1:{port}"
dir = {json.dumps(str(self.storage))}
signing_key_file = {json.dumps(str(key))}
key_id = "scenario-key"
retention_secs = 3600
max_object_bytes = 1048576
admin_token = "{admin_token}"
[agent_tokens]
scenario-agent = "{upload_token}"
''')
        common = f'''endpoint = "http://127.0.0.1:{port}"
agent_id = "scenario-agent"
pinned_pubkey = "{self.public_key}"
key_id = "scenario-key"
allow_http_loopback = true
max_object_bytes = 1048576
timeout_secs = 5
'''
        private_text(self.upload_config, common + f'upload_token = "{upload_token}"\n')
        private_text(self.admin_config, common + f'admin_token = "{admin_token}"\n')
        process, logfile = self.start("argos-vault", "vault-server", "--config", server_config)

        def ready():
            require(process.poll() is None, f"보관 서버 조기 종료: {logfile.read_text()}")
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        wait_until(ready, "보관 서버 시작 실패")

    def verify(self, path, receipt):
        result = json.loads(self.cli("vault", "verify", "--file", path,
                                     "--receipt", receipt, "--pubkey", self.public_key).stdout)
        require(result["verified"] is True, "CLI 수신증명 검증 성공 표시 없음")
        return result["receipt"]

    def fetch(self, sha256, output, receipt):
        self.vault("fetch", "--agent-id", "scenario-agent", "--sha256", sha256,
                   "--out", output, "--receipt", receipt, admin=True)
        return self.verify(output, receipt)

    def raw_audit(self):
        source = self.work / "audit.json"
        data = (json.dumps({"action": "approved_review", "event_id": 42,
                            "note": "CLI 원격 보존 검증"}, ensure_ascii=False) + "\n").encode()
        source.write_bytes(data)
        receipt = self.receipts / "audit.json"
        self.vault("upload", "--file", source, "--kind", "audit", "--receipt", receipt)
        proof = self.verify(source, receipt)
        require(proof["receipt"]["kind"] == "audit", "raw audit 종류가 서명에 반영되지 않음")
        require(proof["receipt"]["agent_id"] == "scenario-agent", "수집 에이전트 ID 불일치")
        require(proof["receipt"]["sha256"] == digest(data), "업로드 해시 불일치")
        source.unlink()
        output = self.work / "audit-restored.json"
        fetched = self.fetch(digest(data), output, self.receipts / "audit-fetched.json")
        require(output.read_bytes() == data, "원본 삭제 후 정확한 바이트 복원 실패")
        require(fetched == proof, "fetch가 원래 서명 수신증명을 반환하지 않음")
        require(stat.S_IMODE(output.stat().st_mode) == 0o600, "복원 출력 권한 오류")
        self.record("raw audit CLI upload/delete-local/fetch/verify",
                    "원본 삭제 후 관리자 역할로 동일 바이트 및 같은 서명 증명 복원",
                    {"sha256": digest(data), "bytes": len(data), "source_deleted": not source.exists(),
                     "same_receipt": True, "restored_mode": "0600"})

    def known_good_backup(self):
        watched = self.work / "watched"
        watched.mkdir(mode=0o700)
        source, canary = watched / "report.txt", watched / "canary.txt"
        data = b"reviewed application data before attack\n"
        source.write_bytes(data)
        canary.write_text("unchanged decoy\n")
        database, backup = self.work / "events.db", self.work / "backup"
        self.agent_config = self.work / "argos.toml"
        private_text(self.agent_config, f'''watch_paths = [{json.dumps(str(watched))}]
db_path = {json.dumps(str(database))}
sensor = "notify"
[detection]
canary_paths = [{json.dumps(str(canary))}]
[response]
auto_block = false
[process_monitor]
enabled = false
[backup]
enabled = true
dir = {json.dumps(str(backup))}
max_file_bytes = 1048576
baseline_on_start = true
''')
        agent, logfile = self.start("argos-agent", "baseline-agent", "--config", self.agent_config)

        def ready():
            require(agent.poll() is None, f"시험 에이전트 조기 종료: {logfile.read_text()}")
            return "이벤트 파이프라인 가동" in logfile.read_text()
        wait_until(ready, "베이스라인 에이전트 시작 실패")
        version = wait_until(lambda: rows(backup / "index.db",
                                         "SELECT id,hash,known_good FROM versions WHERE path=? ORDER BY id",
                                         (str(source),)), "실제 에이전트의 베이스라인 백업 없음")[0]
        require(version[1] == digest(data) and version[2] == 0, "베이스라인의 바이트/미검토 상태 오류")
        rejected_receipt = self.receipts / "unreviewed.json"
        self.cli("--config", self.agent_config, "vault", "upload-backup", source,
                 "--version", version[0], "--vault-config", self.upload_config,
                 "--receipt", rejected_receipt, success=False)
        require(not rejected_receipt.exists(), "미검토 백업 거부 시 수신증명 생성")
        require(not (self.storage / "scenario-agent" / f"{digest(data)}.blob").exists(),
                "미검토 백업이 원격으로 업로드됨")
        self.cli("--config", self.agent_config, "restore", source,
                 "--mark-good", version[0], "--note", "scenario original bytes reviewed")
        # 증거 패키지는 직접 DB에 탐지를 삽입하지 않고 실제 notify 미끼 탐지를 사용한다.
        canary.write_text("scenario decoy modification\n")
        self.detection_id = wait_until(
            lambda: rows(database, "SELECT id FROM detections WHERE rule='behavior.canary_tamper' ORDER BY id"),
            "미끼 파일 변경 탐지 없음")[0][0]
        self.stop(agent)
        source.write_bytes(b"damaged current version must not be selected\n")
        receipt = self.receipts / "backup.json"
        self.cli("--config", self.agent_config, "vault", "upload-backup", source,
                 "--version", version[0], "--vault-config", self.upload_config, "--receipt", receipt)
        proof = json.loads(receipt.read_text())
        require(proof["receipt"]["sha256"] == digest(data), "선택 정상본 대신 현재 손상 파일을 업로드함")
        require(proof["receipt"]["kind"] == "backup", "백업 어댑터의 종류 오류")
        output = self.work / "backup-restored.txt"
        self.fetch(digest(data), output, self.receipts / "backup-fetched.json")
        require(output.read_bytes() == data, "원격 정상본 바이트 불일치")
        require(source.read_bytes() != data, "보관/조회가 원본을 자동 복구함")
        self.record("known-good backup CLI adapter",
                    "실제 베이스라인 미검토 업로드 거부; 지정 정상본을 현재 손상 내용과 구별하여 보관",
                    {"version": version[0], "sha256": digest(data), "unreviewed_rejected": True,
                     "current_file_unchanged": True, "real_detection_id": self.detection_id})

    def evidence_package(self):
        package = self.work / "evidence-package"
        self.cli("--config", self.agent_config, "evidence-export", self.detection_id,
                 "--out", package, "--window-secs", 300, "--limit", 100)
        self.cli("--config", self.agent_config, "evidence-verify", package)
        names = ("evidence.json", "policy.json", "manifest.json")
        originals = {name: (package / name).read_bytes() for name in names}
        receipts = self.receipts / "package"
        upload = self.vault("upload-evidence", "--package", package, "--receipts", receipts)
        emitted = [json.loads(line) for line in upload.stdout.splitlines() if line.strip()]
        require([proof["receipt"]["sha256"] for proof in emitted]
                == [digest(originals[name]) for name in names],
                "CLI 증명 출력의 evidence/policy/manifest 전송 완료 순서 불일치")
        require(sorted(path.name for path in receipts.iterdir()) == sorted(f"{name}.receipt.json" for name in names),
                "패키지 3개 파일의 수신증명 목록 불일치")
        for name in names:
            proof = self.verify(package / name, receipts / f"{name}.receipt.json")
            require(proof["receipt"]["kind"] == "evidence", "증거 어댑터의 종류 오류")
            require(proof["receipt"]["sha256"] == digest(originals[name]), "패키지 스냅샷 해시 오류")

        # 업로드 사전 검증 실패는 새 수신증명이나 원격 객체를 만들면 안 된다.
        rejected = self.receipts / "tampered-package"
        before_objects = len(list(self.storage.rglob("*.blob")))
        (package / "evidence.json").write_bytes(originals["evidence.json"] + b"\nTAMPERED")
        self.vault("upload-evidence", "--package", package, "--receipts", rejected, success=False)
        require(not rejected.exists(), "변조 패키지 거부 전에 수신증명 디렉터리 생성")
        require(len(list(self.storage.rglob("*.blob"))) == before_objects, "변조 패키지가 원격 상태를 변경함")
        self.record("evidence adapter rejects tampered package before upload",
                    "manifest 해시 불일치가 원격 게시와 로컬 수신증명 생성 전에 거부됨",
                    {"rejected": True, "remote_object_count_unchanged": True, "receipt_directory_absent": True})

        shutil.rmtree(package)
        recovered = self.work / "evidence-recovered"
        recovered.mkdir(mode=0o700)
        for name in names:
            proof = self.fetch(digest(originals[name]), recovered / name,
                               self.receipts / f"recovered-{name}.receipt.json")
            require((recovered / name).read_bytes() == originals[name], "패키지 파일 복원 바이트 불일치")
            require(proof == json.loads((receipts / f"{name}.receipt.json").read_text()), "패키지 증명 변경")
        self.cli("--config", self.agent_config, "evidence-verify", recovered)
        self.record("evidence package CLI export/upload/restore",
                    "실제 탐지 패키지 3개를 서명 검증하고 원본 디렉터리 삭제 후 정확히 복원·manifest 재검증",
                    {"files": list(names), "sha256": {name: digest(data) for name, data in originals.items()},
                     "original_package_deleted": not package.exists(), "restored_package_verified": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=Path(os.environ.get("ARGOS_BIN_DIR", "target/debug")))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    for name in ("argos", "argos-agent", "argos-vault"):
        if not (binaries / name).is_file():
            parser.error(f"빌드된 바이너리가 없습니다: {binaries / name}")
    work = Path(tempfile.mkdtemp(prefix="argos-vault-scenarios-"))
    os.chmod(work, 0o700)
    scenarios = Scenarios(binaries, work)
    report = {"suite": "vault-cli-adapters", "bin_dir": str(binaries), "work_dir": str(work),
              "scope": "temporary loopback server, notify baseline, CLI adapters; no external TLS/WORM deployment",
              "passed": False, "scenarios": scenarios.results}
    exit_code = 1
    try:
        report["version"] = scenarios.cli("--version").stdout.strip()
        scenarios.setup()
        scenarios.raw_audit()
        scenarios.known_good_backup()
        scenarios.evidence_package()
        report["passed"] = True
        exit_code = 0
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        print(f"FAIL: {error}", file=sys.stderr)
    finally:
        scenarios.close()
        report["passed_scenarios"] = len(scenarios.results)
        report["temporary_files_retained"] = bool(args.keep or exit_code)
        if args.report:
            with args.report.open("x", encoding="utf-8") as output:
                os.chmod(args.report, 0o600)
                output.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        if args.keep or exit_code:
            print(f"임시 결과 보존: {work}", flush=True)
        else:
            shutil.rmtree(work)
    print(f"{len(scenarios.results)} CLI 보관 시나리오 {'통과' if exit_code == 0 else '완료 전 실패'}", flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
