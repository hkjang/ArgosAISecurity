#!/usr/bin/env python3
"""임시 loopback 서버와 실제 CLI로 영속 재전송·용량 제한·복구 보고서 재사용을 검증한다.

python3 scripts/durability-scenarios.py --bin-dir target/debug --report /tmp/argos-durability.json
모든 입력은 합성 데이터이며 운영 DB·외부 서비스·시스템 설정을 사용하지 않는다.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("argos_vault_scenarios", Path(__file__).with_name("vault-scenarios.py"))
VAULT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VAULT)
require, digest, wait_until = VAULT.require, VAULT.digest, VAULT.wait_until


class Scenarios(VAULT.Scenarios):
    def __init__(self, binaries, work, max_objects=1):
        super().__init__(binaries, work)
        self.max_objects, self.restart_number = max_objects, 0

    def setup(self):
        super().setup()
        self.server = self.processes[-1][0]
        self.server_config = self.work / "vault-server.toml"
        endpoint = re.search(r'^endpoint\s*=\s*"([^"]+)"', self.upload_config.read_text(), re.M).group(1)
        self.port = urlparse(endpoint).port
        self.stop(self.server)
        # 합성 시험의 객체 한도가 CI /tmp 여유 공간에 좌우되지 않게 한다.
        with self.server_config.open("a", encoding="utf-8") as config:
            config.write(f"\n[capacity]\nagent_max_objects = {self.max_objects}\nmin_free_bytes = 0\n")
        self.restart()

    def restart(self):
        self.stop(self.server)
        self.restart_number += 1
        self.server, logfile = self.start("argos-vault", f"vault-restart-{self.restart_number}", "--config", self.server_config)
        def ready():
            require(self.server.poll() is None, "임시 보관 서버가 재시작 중 종료되었습니다")
            with socket.create_connection(("127.0.0.1", self.port), timeout=.2):
                return True
        wait_until(ready, "임시 보관 서버 재시작 실패")

    def status(self, directory):
        return json.loads(self.cli("vault", "queue", "status", "--directory", directory).stdout)

    def queue(self, *args, success=True):
        return self.vault("queue", *args, success=success)

    def offline_queue_and_quota(self):
        self.stop(self.server)
        directory, source = self.work / "queue", self.work / "audit-original.json"
        original = b'{"event":17,"decision":"reviewed synthetic audit"}\n'
        source.write_bytes(original)
        item = json.loads(self.queue("enqueue", "--directory", directory, "--file", source, "--kind", "audit").stdout)
        require(item["sha256"] == digest(original) and item["size_bytes"] == len(original), "큐 등록 바이트 불일치")
        source.write_bytes(b"changed after enqueue; never upload these bytes")
        source.unlink()
        failed = json.loads(self.queue("drain", "--directory", directory, success=False).stdout)
        require((failed["attempted"], failed["failed"], failed["sent"], failed["remaining_pending"]) == (1, 1, 0, 1), "오프라인 drain 실패 상태 오류")
        persisted = self.status(directory)
        require(persisted["pending_items"] == 1 and persisted["failed_items"] == 1, "재시도 대기 상태 누락")
        stored = persisted["items"][0]
        require(stored["id"] == item["id"] and stored["attempts"] == 1 and stored["receipt"] is None, "새 CLI에서 상태 복원 실패")
        require(stored["next_retry_ms"] > int(time.time() * 1000), "재시도 대기 시각이 미래가 아님")
        deferred = json.loads(self.queue("drain", "--directory", directory).stdout)
        require(deferred["attempted"] == 0, "backoff 중 중복 전송을 시도함")
        self.record("오프라인 큐 등록·원본 삭제·재시도 상태 보존",
                    "원본 변경·삭제와 CLI 종료 후에도 고정 스냅샷 및 재시도 상태 보존",
                    {"id": item["id"], "sha256": item["sha256"], "attempts": stored["attempts"], "source_absent": True, "early_retry_attempted": 0})
        self.restart()
        wait_until(lambda: int(time.time() * 1000) >= stored["next_retry_ms"], "재시도 시각 도달 실패", timeout=12)
        sent = json.loads(self.queue("drain", "--directory", directory).stdout)
        require(sent["sent"] == 1 and sent["failed"] == 0 and sent["remaining_pending"] == 0, "재시작 후 drain 실패")
        completed = self.status(directory)
        require(completed["sent_items"] == 1 and completed["pending_bytes"] == 0, "완료 집계 오류")
        receipt = completed["items"][0]["receipt"]
        require(completed["items"][0]["attempts"] == 2 and receipt["receipt"]["sha256"] == digest(original), "큐 완료 증명/재시도 횟수 오류")
        require(not any((directory / "objects").iterdir()), "완료 영속화 후 큐 본문이 남음")
        output = self.work / "audit-fetched.json"
        fetched = self.fetch(digest(original), output, self.receipts / "audit-fetched.json")
        require(output.read_bytes() == original and fetched == receipt, "재시작 뒤 고정 원본 바이트·수신증명 불일치")
        self.record("재시작 재전송·서명 수신증명·원본 바이트",
                    "새 CLI가 동일 대상에 같은 바이트를 전송하고 서명 검증 후 완료",
                    {"sha256": digest(original), "attempts": 2, "same_receipt": True, "pending_bytes": 0})

        other = self.work / "other.json"
        other.write_bytes(b'{"different":true}\n')
        rejected_receipt = self.receipts / "quota-rejected.json"
        self.vault("upload", "--file", other, "--kind", "audit", "--receipt", rejected_receipt, success=False)
        require(not rejected_receipt.exists(), "용량 거부 후 수신증명 생성")
        usage = json.loads(self.vault("usage", admin=True).stdout)
        expected = {"logical_bytes": len(original), "objects": 1, "receipted_objects": 1}
        require(usage["total"] == expected, "거부 객체가 사용량에 반영됨")
        require(usage["agents"]["scenario-agent"]["usage"] == expected, "에이전트 사용량 불일치")
        require(usage["agents"]["scenario-agent"]["limits"]["max_objects"] == 1, "설정한 에이전트 한도 미적용")
        require(usage["admission_rejections"] >= 1, "용량 거부 집계 없음")
        retry = self.work / "same-original.json"
        retry.write_bytes(original)
        retry_receipt = self.receipts / "idempotent-retry.json"
        self.vault("upload", "--file", retry, "--kind", "audit", "--receipt", retry_receipt)
        require(json.loads(retry_receipt.read_text()) == receipt, "한도 도달 후 동일 객체 retry 실패")
        self.fetch(digest(original), self.work / "read-at-capacity.json", self.receipts / "read-at-capacity.json")
        self.restart()
        reconstructed = json.loads(self.vault("usage", admin=True).stdout)
        require(reconstructed["total"] == expected and reconstructed["agents"]["scenario-agent"]["usage"] == expected, "재시작 용량 재구성 실패")
        require(reconstructed["reconstruction_complete"] and reconstructed["storage_consistent"], "보관 정합성/재구성 실패")
        require(reconstructed["admission_rejections"] == 0, "프로세스별 거부 카운터 재시작 의미 변경")
        self.record("에이전트 객체 한도·기존 객체 조회와 재시도·용량 재구성",
                    "두 번째 신규 객체 거부, 기존 객체 조회·같은 전송 재시도 허용, 재시작 후 용량 복원",
                    {"usage": expected, "agent_max_objects": 1, "retry_same_receipt": True, "reconstructed": True, "process_rejection_counter_reset": True})

    def recovery_report_binding(self):
        original, backup = self.work / "orders-live.sqlite3", self.work / "orders-backup.sqlite3"
        with sqlite3.connect(original) as database:
            database.executescript("PRAGMA user_version=7;CREATE TABLE orders(id INTEGER PRIMARY KEY,secret TEXT);INSERT INTO orders VALUES(1,'PRIVATE-REPORT-FIXTURE'),(2,'second');")
            with sqlite3.connect(backup) as destination:
                database.backup(destination)
        content = backup.read_bytes()
        plan = self.work / "orders.toml"
        template = ('service_id="orders"\nengine="sqlite"\nbackup_path={backup}\ntimeout_secs=10\nexpected_user_version=7\n'
                    '[[tables]]\ncheck_id="orders-check"\ntable="orders"\nrequired_columns=["id","secret"]\nmin_rows={rows}\n')
        plan.write_text(template.format(backup=json.dumps(str(backup)), rows=2))
        out = self.work / "orders-drill"
        report = json.loads(self.cli("service-recovery", "test", "--plan", plan, "--out", out).stdout)
        require(report["format"] == "argos-service-recovery-v2" and report["plan_hash_version"] == 1, "v2 계획 결합 필드 누락")
        report_path = out / "service-recovery.json"
        report_original = report_path.read_bytes()
        def verify(expected=True, path=report_path):
            result = json.loads(self.cli("service-recovery", "verify", "--plan", plan, "--report", path, "--max-age-secs", 3600, success=expected).stdout)
            require(result["report_authenticated"] is False, "무서명 보고서 출처 검증으로 과장함")
            return result
        require(verify()["status"] == "consistent", "새 드릴 보고서 검증 실패")
        moved = self.work / "orders-relocated.sqlite3"
        moved.write_bytes(content)
        plan.write_text(template.format(backup=json.dumps(str(moved)), rows=2))
        require(verify()["status"] == "consistent", "동일 내용 백업 경로 이동 거부")
        plan.write_text(template.format(backup=json.dumps(str(moved)), rows=1))
        require(verify(False)["failure_code"] == "report_plan_mismatch", "기대값을 약화한 다른 계획 재사용 허용")
        plan.write_text(template.format(backup=json.dumps(str(moved)), rows=2))
        changed = bytearray(content); changed[-1] ^= 1
        moved.write_bytes(changed)
        require(verify(False)["failure_code"] == "report_backup_mismatch", "내용 변경 백업에 과거 보고서 재사용 허용")
        moved.write_bytes(content)
        legacy = dict(report)
        legacy["format"] = "argos-service-recovery-v1"
        for field in ("plan_hash_version", "plan_sha256", "expectations_sha256", "required_check_ids"):
            legacy.pop(field)
        legacy_path = self.work / "legacy-report.json"
        legacy_path.write_text(json.dumps(legacy))
        require(verify(False, legacy_path)["failure_code"] == "legacy_or_unbound_report", "구버전 무결합 보고서 재사용 허용")
        require(backup.read_bytes() == content and report_path.read_bytes() == report_original, "검증이 원본 백업/보고서를 수정함")
        self.record("SQLite v2 시험·현재 계획과 백업 결합",
                    "현재 계획·전체 백업 내용·검사 목록·최신성을 확인하고 변경/구버전 보고서 거부",
                    {"format": report["format"], "plan_sha256": report["plan_sha256"], "backup_relocation_allowed": True, "changed_plan_rejected": True, "changed_backup_rejected": True, "legacy_rejected": True, "report_authenticated": False})

    def queue_adapters(self):
        # 기존 실제 에이전트의 베이스라인·정상본·미끼 탐지 준비를 재사용한다.
        self.known_good_backup()
        source = self.work / "watched/report.txt"
        selected = VAULT.rows(self.work / "backup/index.db", "SELECT id,hash FROM versions WHERE path=? AND known_good=1 ORDER BY id", (str(source),))[0]
        expected_backup = b"reviewed application data before attack\n"
        package = self.work / "queued-evidence"
        self.cli("--config", self.agent_config, "evidence-export", self.detection_id, "--out", package, "--window-secs", 300, "--limit", 100)
        self.cli("--config", self.agent_config, "evidence-verify", package)
        names = ("evidence.json", "policy.json", "manifest.json")
        expected_package = {name: (package / name).read_bytes() for name in names}
        before_entries = sorted(path.name for path in package.iterdir())
        self.queue("enqueue-evidence", "--directory", package, "--package", package, success=False)
        require(sorted(path.name for path in package.iterdir()) == before_entries,
                "자기 자신을 큐 경로로 지정한 거부가 증거 파일 목록을 변경함")
        require(all((package / name).read_bytes() == content for name, content in expected_package.items()),
                "거부된 증거 큐 경로가 기존 패키지 내용을 변경함")
        self.record("증거 패키지를 큐 경로로 재사용 거부", "패키지와 같은 경로를 큐로 지정하면 파일 생성·내용 변경 전에 거부",
                    {"same_path_rejected": True, "file_list_and_contents_unchanged": True})
        self.stop(self.server)
        directory = self.work / "adapter-queue"
        queued = json.loads(self.cli("--config", self.agent_config, "vault", "--vault-config", self.upload_config,
                                    "queue", "enqueue-backup", "--directory", directory, source, "--version", selected[0]).stdout)
        require(queued["sha256"] == digest(expected_backup), "현재 손상 내용이 정상본 대신 큐에 등록됨")
        evidence = self.queue("enqueue-evidence", "--directory", directory, "--package", package)
        emitted = [json.loads(line) for line in evidence.stdout.splitlines() if line.strip()]
        require({row["package_file"]: row["item"]["sha256"] for row in emitted} == {name: digest(data) for name, data in expected_package.items()}, "증거 패키지 큐 스냅샷 불일치")
        source.unlink(); shutil.rmtree(package)
        self.restart()
        sent = json.loads(self.queue("drain", "--directory", directory, "--max-items", 16).stdout)
        require(sent["sent"] == 4 and sent["failed"] == 0 and sent["remaining_pending"] == 0, "어댑터 큐 재전송 실패")
        restored = self.work / "queue-backup-restored.txt"
        self.fetch(digest(expected_backup), restored, self.receipts / "queue-backup-receipt.json")
        require(restored.read_bytes() == expected_backup, "큐 백업 원격 복원 바이트 불일치")
        recovered = self.work / "queue-evidence-recovered"
        recovered.mkdir(mode=0o700)
        for name, content in expected_package.items():
            self.fetch(digest(content), recovered / name, self.receipts / f"queue-{name}.receipt.json")
            require((recovered / name).read_bytes() == content, "큐 증거 원격 복원 바이트 불일치")
        self.cli("--config", self.agent_config, "evidence-verify", recovered)
        self.record("정상 백업·사고 증거 큐 어댑터",
                    "실제 에이전트 정상본/증거 패키지의 고정 바이트를 오프라인 등록 후 원본 삭제·재시작·전송·복원",
                    {"queued_backup_version": selected[0], "sent_objects": 4, "source_and_package_deleted": True, "restored_evidence_verified": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=Path(os.environ.get("ARGOS_BIN_DIR", "target/debug")))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--skip-adapters", action="store_true", help="argos-agent 기반 백업·증거 큐 어댑터 시험 생략")
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    for name in ("argos", "argos-vault") + (() if args.skip_adapters else ("argos-agent",)):
        if not (binaries / name).is_file():
            parser.error(f"빌드된 바이너리가 없습니다: {binaries / name}")
    report_file = None
    if args.report:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        report_file = os.fdopen(os.open(args.report, flags, 0o600), "w", encoding="utf-8")
    root = Path(tempfile.mkdtemp(prefix="argos-durability-"))
    os.chmod(root, 0o700)
    main_work, adapter_work = root / "durability", root / "adapters"
    main_work.mkdir(mode=0o700)
    suites = [Scenarios(binaries, main_work)]
    results = suites[0].results
    report = {"suite": "durable-vault-and-recovery-reports", "bin_dir": str(binaries), "work_dir": str(root),
              "scope": "합성 SQLite와 임시 loopback 보관 서버·무서명 보고서 일관성; 외부 서비스·운영 DB 미사용",
              "passed": False, "scenarios": results, "adapters_tested": not args.skip_adapters}
    exit_code = 1
    try:
        report["version"] = suites[0].cli("--version").stdout.strip()
        suites[0].setup()
        suites[0].offline_queue_and_quota()
        suites[0].recovery_report_binding()
        if not args.skip_adapters:
            adapter_work.mkdir(mode=0o700)
            adapter = Scenarios(binaries, adapter_work, max_objects=1000)
            adapter.results = results
            suites.append(adapter)
            adapter.setup()
            adapter.queue_adapters()
        report["passed"] = True
        exit_code = 0
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        print(f"FAIL: {error}", file=sys.stderr)
    finally:
        for suite in reversed(suites):
            suite.close()
        report["passed_scenarios"] = len(results)
        report["temporary_files_retained"] = bool(args.keep or exit_code)
        if report_file:
            with report_file as output:
                output.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
                output.flush(); os.fsync(output.fileno())
            require(stat.S_IMODE(args.report.stat().st_mode) == 0o600, "시나리오 보고서 권한 오류")
        if args.keep or exit_code:
            print(f"임시 결과 보존: {root}", flush=True)
        else:
            shutil.rmtree(root)
    print(f"{len(results)} 영속성 시나리오 {'통과' if exit_code == 0 else '완료 전 실패'}", flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
