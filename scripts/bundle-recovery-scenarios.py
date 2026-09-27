#!/usr/bin/env python3
"""실제 CLI와 임시 loopback 서버로 원본 로컬 자료 없는 분할 DB 복구를 검증한다.

67MiB zeroblob을 가진 SQLite native backup을 16MiB 청크로 준비하고 큐로 보관한다.
동일 시험 호스트에서 원본 디렉터리를 삭제한 뒤 새 작업 경로에서 원격 조회·복구
시험을 수행한다. 실제 별도 서버 이전·운영 DB·외부 TLS 서비스 검증은 아니다.
"""
import argparse
import hashlib
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
from urllib.parse import urlparse

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "argos_vault_bundle_helpers", Path(__file__).with_name("vault-scenarios.py"))
VAULT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VAULT)
require, wait_until = VAULT.require, VAULT.wait_until

MIB = 1024 * 1024
AGENT = "scenario-agent"
SENSITIVE_ROW = "PRIVATE-BUNDLE-FIXTURE-ROW"


def digest_file(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def plan_text(backup, min_rows=2):
    return (f'service_id = "bundle-orders-fixture"\nengine = "sqlite"\n'
            f'backup_path = {json.dumps(str(backup))}\n'
            'timeout_secs = 60\nmax_backup_bytes = 134217728\n'
            'max_workspace_bytes = 536870912\nexpected_user_version = 7\n'
            '[[tables]]\ncheck_id = "orders-schema-rows"\ntable = "orders"\n'
            'required_columns = ["id", "secret"]\n' + f'min_rows = {min_rows}\n')


def native_backup(original, backup, large=False):
    with sqlite3.connect(original) as database:
        database.executescript("PRAGMA user_version=7; CREATE TABLE orders(id INTEGER PRIMARY KEY,secret TEXT);")
        database.executemany("INSERT INTO orders VALUES(?,?)", [(1, SENSITIVE_ROW), (2, "second")])
        if large:
            database.execute("CREATE TABLE padding(id INTEGER PRIMARY KEY,payload BLOB)")
            database.execute("INSERT INTO padding VALUES(1,zeroblob(?))", (67 * MIB,))
        database.commit()
        with sqlite3.connect(backup) as destination:
            database.backup(destination)
    for path in (original, backup):
        os.chmod(path, 0o600)


class Scenarios(VAULT.Scenarios):
    def __init__(self, binaries, work):
        super().__init__(binaries, work)
        self.host = work / "original-host"
        self.host.mkdir(mode=0o700)
        self.agent_config = self.host / "agent.toml"
        # 복구 번들 CLI가 관련 없는 로컬 에이전트 설정을 읽으면 즉시 실패해야 한다.
        self.agent_config.write_text("INVALID-UNRELATED-AGENT-CONFIG!", encoding="utf-8")
        self.restart_number = 0

    def command(self, binary, *arguments, success=True):
        result = subprocess.run(
            [str(self.binaries / binary), *map(str, arguments)],
            stdin=subprocess.DEVNULL, text=True, capture_output=True,
            cwd=self.work, env=self.env, timeout=120,
        )
        require((result.returncode == 0) == success,
                f"{binary} {arguments}: 종료={result.returncode}\n{result.stdout}\n{result.stderr}")
        require(SENSITIVE_ROW not in result.stdout + result.stderr, "민감한 합성 행 내용이 CLI 출력에 노출됨")
        return result

    def setup(self):
        super().setup()
        self.server = self.processes[-1][0]
        self.server_config = self.work / "vault-server.toml"
        self.stop(self.server)
        for path in (self.server_config, self.upload_config, self.admin_config):
            text = path.read_text(encoding="utf-8")
            require("max_object_bytes = 1048576" in text, "보관 시험 기본 객체 설정이 변경됨")
            text = text.replace("max_object_bytes = 1048576", "max_object_bytes = 67108864")
            if path != self.server_config:
                require("timeout_secs = 5" in text, "보관 시험 기본 요청 제한이 변경됨")
                text = text.replace("timeout_secs = 5", "timeout_secs = 30")
            else:
                # 시험 머신 /tmp의 잔여 공간 차이가 기능 시험을 가리지 않게 한다.
                text += "\n[capacity]\nmin_free_bytes = 0\n"
            path.write_text(text, encoding="utf-8")
            os.chmod(path, 0o600)
        endpoint = re.search(r'^endpoint\s*=\s*"([^"]+)"', self.upload_config.read_text(), re.M).group(1)
        self.port = urlparse(endpoint).port
        self.restart()

    def restart(self):
        self.stop(self.server)
        self.restart_number += 1
        self.server, _ = self.start("argos-vault", f"bundle-server-{self.restart_number}",
                                    "--config", self.server_config)

        def ready():
            require(self.server.poll() is None, "임시 번들 보관 서버가 조기 종료됨")
            with socket.create_connection(("127.0.0.1", self.port), timeout=.2):
                return True
        wait_until(ready, "번들 보관 서버 시작 실패")

    def bundle(self, *arguments, admin=False, success=True):
        config = self.admin_config if admin else self.upload_config
        return self.cli("--config", self.agent_config, "vault", "--vault-config", config,
                        "bundle", *arguments, success=success)

    def parsed(self, *arguments, admin=False, success=True):
        # json.loads는 복수 JSON 문서·추가 stdout을 거부한다.
        return json.loads(self.bundle(*arguments, admin=admin, success=success).stdout)

    def trial(self, bundle_id, out, success):
        result = self.parsed("test", "--agent-id", AGENT, "--id", bundle_id,
                             "--out", out, admin=True, success=success)
        require(result["format"] == "argos-bundle-recovery-test-v1", "번들 시험 보고서 형식 오류")
        require(result["status"] == ("passed" if success else "rejected"), "번들 시험 상태 오류")
        require(result["recommended"] is success, "시험 성공 여부와 복구 추천 불일치")
        require(result["report_authenticated"] is False
                and result["trial_executor_authenticated"] is False
                and result["original_agent_database_used"] is False,
                "무서명 보고서/실행자 인증/원본 DB 사용 여부 표시 오류")
        require(json.loads((out / "bundle-test.json").read_text()) == result, "stdout과 영속 보고서 불일치")
        require(stat.S_IMODE(out.stat().st_mode) == 0o700, "복구 시험 디렉터리 권한 오류")
        require(stat.S_IMODE((out / "bundle-test.json").stat().st_mode) == 0o600, "시험 보고서 권한 오류")
        return result

    def review(self, bundle_id, decision, request):
        return self.parsed("review", "--agent-id", AGENT, "--id", bundle_id,
                           "--request-id", request, "--decision", decision,
                           "--actor", "synthetic-operator", "--reason", "isolated fixture review",
                           admin=True)

    def large_bundle(self):
        original, backup = self.host / "orders.sqlite3", self.host / "orders.backup.sqlite3"
        native_backup(original, backup, large=True)
        self.expected_hash, self.backup_bytes = digest_file(backup), backup.stat().st_size
        require(self.backup_bytes > 64 * MIB, "시험 백업이 원격 단일 객체 64MiB 상한보다 작음")
        require(self.backup_bytes <= 128 * MIB, "시험 계획의 백업 한도 초과")
        plan = self.host / "recovery-plan.toml"
        plan.write_text(plan_text(backup), encoding="utf-8")
        history = self.host / "source-review.json"
        history.write_text(json.dumps({"decision": "good", "note": "unverified source-side claim"}), encoding="utf-8")
        with sqlite3.connect(self.host / "agent-events.sqlite3") as database:
            database.execute("CREATE TABLE evidence(id INTEGER PRIMARY KEY,note TEXT)")
            database.execute("INSERT INTO evidence VALUES(1,'synthetic local agent state')")
        stage, queue = self.host / "prepared", self.host / "upload-queue"
        prepared = self.parsed("prepare", "--file", backup, "--out", stage,
                               "--original-path", original, "--version", 7,
                               "--plan", plan, "--review-history", history)
        self.bundle_id = prepared["bundle_id"]
        require(prepared["sha256"] == self.expected_hash and prepared["size_bytes"] == self.backup_bytes,
                "준비된 번들과 원본 native backup의 해시/크기 불일치")
        require(prepared["source_metadata_claims_verified"] is False
                and prepared["remote_review"] == "unknown" and prepared["recommended"] is False,
                "원본 판정 주장을 원격 정상 판정으로 승격함")
        manifest = json.loads((stage / "manifest.json").read_text())
        require(len(manifest["chunks"]) >= 5, "64MiB 초과 백업을 16MiB 청크로 분할하지 않음")
        require(all(item["size_bytes"] == 16 * MIB for item in manifest["chunks"][:-1]), "중간 청크 크기 오류")
        require(sum(item["size_bytes"] for item in manifest["chunks"]) == self.backup_bytes, "청크 크기 합계 오류")
        queued = self.parsed("enqueue", "--stage", stage, "--directory", queue,
                             "--max-items", 1000, "--max-bytes", 256 * MIB)
        unique = {item["sha256"] for item in manifest["chunks"]}
        require(len(queued["chunk_items"]) == len(unique) >= 2, "청크 등록 중복 판정/개수 오류")
        require({item["sha256"] for item in queued["chunk_items"]} == unique, "큐와 구성 목록의 청크 해시 차이")
        require(queued["state"] == "pending" and not queued["recommended"], "등록만으로 완료/추천 표시됨")
        self.record("64MiB 초과 native backup 분할·큐 등록",
                    "67MiB zeroblob을 포함한 DB를 16MiB 청크로 분할하고 고유 청크만 영속 등록",
                    {"backup_bytes": self.backup_bytes, "sha256": self.expected_hash,
                     "chunk_count": len(manifest["chunks"]), "unique_chunks": len(unique),
                     "max_object_bytes": 64 * MIB, "queue_max_bytes": 256 * MIB})

        partial = json.loads(self.vault("queue", "drain", "--directory", queue, "--max-items", 1).stdout)
        require(partial["sent"] == 1 and partial["remaining_pending"] > 0, "부분 청크 전송 fixture 오류")
        self.bundle("publish", "--manifest", stage / "manifest.json", success=False)
        record = self.parsed("show", "--agent-id", AGENT, "--id", self.bundle_id, admin=True)
        page = self.parsed("list", "--agent-id", AGENT, admin=True)
        require(record["completion"] is None and not record["recommended"], "부분 전송을 완료/추천으로 표시함")
        require(any(item["bundle_id"] == self.bundle_id and item["complete"] is False for item in page["items"]),
                "원격 목록에 미완료 번들이 없음")
        self.record("부분 전송의 게시 보류·미완료 조회",
                    "일부 청크만 전송하면 완료 증명 발급을 거부하고 원격 목록에 미완료로 표시",
                    {"sent": partial["sent"], "remaining_pending": partial["remaining_pending"], "complete": False})

        drained = json.loads(self.vault("queue", "drain", "--directory", queue, "--max-items", 100).stdout)
        require(drained["failed"] == 0 and drained["remaining_pending"] == 0, "전체 청크 전송 실패")
        complete = self.parsed("publish", "--manifest", stage / "manifest.json")
        require(complete["completion"] is not None and complete["manifest"]["sha256"] == self.expected_hash,
                "전체 바이트에 결합한 완료 증명이 없음")
        require(complete["current_review"] == "unknown" and not complete["recommended"], "완료와 정상 판정을 혼동함")
        self.bundle("fetch", "--agent-id", AGENT, "--id", self.bundle_id,
                    "--out", self.work / "unknown-fetch.sqlite3", admin=True, success=False)
        require(not (self.work / "unknown-fetch.sqlite3").exists(), "미판정 기본 fetch가 파일을 게시함")
        rejected = self.trial(self.bundle_id, self.work / "unknown-trial", False)
        require(rejected["failure_code"] == "remote_review_not_good", "미판정 시험의 거부 근거 오류")
        require(not (self.work / "unknown-trial" / "backup.bin").exists(), "미판정 시험이 백업을 받음")
        self.record("완료 후 미판정 복구 보류",
                    "전체 해시 완료 증명만으로 fetch/DB 시험을 허용하지 않음",
                    {"completion_present": True, "current_review": "unknown", "failure_code": rejected["failure_code"]})

        approved = self.review(self.bundle_id, "good", "fixture-good-1")
        require(approved["recommended"] is True and len(approved["reviews"]) == 1, "관리자 정상 판정 적용 실패")
        shutil.rmtree(self.host)
        require(not self.host.exists() and not backup.exists() and not stage.exists() and not queue.exists(),
                "원본·계획·stage·큐·가상 에이전트 DB를 제거하지 못함")
        new_host = self.work / "new-recovery-workspace"
        new_host.mkdir(mode=0o700)
        page = self.parsed("list", "--agent-id", AGENT, admin=True)
        found = [item for item in page["items"] if item["original_path"] == str(original)]
        require(len(found) == 1 and found[0]["recommended"], "원본 자료 없이 원격 목록에서 복구 대상을 찾지 못함")
        remote_id = found[0]["bundle_id"]
        require(remote_id == self.bundle_id, "원격 검색 결과의 ID 불일치")
        shown = self.parsed("show", "--agent-id", AGENT, "--id", remote_id, admin=True)
        require(shown["manifest"]["metadata"]["recovery_plan"] is not None, "원격 구성 목록에 복구 계획이 없음")
        result = self.trial(remote_id, new_host / "trial", True)
        require(result["remote_review_authenticated"] is True and result["source_metadata_claims_verified"] is False,
                "원격 서명 판정과 원본 메타데이터 주장을 혼동함")
        require(result["backup_sha256"] == self.expected_hash and result["backup_bytes"] == self.backup_bytes,
                "원격 복구 시험의 백업 결합 오류")
        report = result["drill_report"]
        require(report["status"] == "passed" and report["backup_sha256"] == self.expected_hash, "SQLite 복구 시험 실패")
        checks = {check["check_id"]: check for check in report["checks"]}
        for name in ("argos-integrity", "argos-foreign-keys", "argos-user-version", "orders-schema-rows", "argos-write-read-rollback"):
            require(name in checks and checks[name]["passed"], f"필수 DB 검사 실패/누락: {name}")
        require(checks["orders-schema-rows"]["observed_rows"] == 2, "복구 행 수 오류")
        require(result["verification"]["status"] == "consistent"
                and result["verification"]["report_authenticated"] is False, "무서명 보고서 재검증 표시 오류")
        restored = new_host / "trial" / "drill" / "restored.sqlite3"
        with sqlite3.connect(f"file:{restored}?mode=ro", uri=True) as database:
            require(database.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 2, "새 작업 경로의 복구 행 수 오류")
            require(database.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='__argos_service_recovery_probe'").fetchone()[0] == 0,
                    "고정 쓰기 시험의 rollback이 반영되지 않음")
        require(digest_file(new_host / "trial" / "backup.bin") == self.expected_hash, "새 경로의 재조립 백업 해시 오류")
        self.record("원본 로컬 자료 삭제 후 원격 조회·SQLite 복구 시험",
                    "같은 loopback 호스트에서 원본 DB·stage·큐·에이전트 DB 없이 새 경로에 재조립하고 검사",
                    {"original_directory_absent": True, "recovered_from_remote_list": remote_id,
                     "backup_bytes": self.backup_bytes, "sha256": self.expected_hash,
                     "checked_ids": sorted(checks), "report_authenticated": False,
                     "original_agent_database_used": False, "same_test_host": True})

        self.restart()
        restarted = self.parsed("show", "--agent-id", AGENT, "--id", remote_id, admin=True)
        require(restarted["completion"] == approved["completion"] and restarted["reviews"] == approved["reviews"]
                and restarted["recommended"], "서버 재시작 후 완료/검토 이력 변경")
        self.record("서버 재시작 후 완료·정상 판정 유지",
                    "원격 저장소와 카탈로그에서 동일 완료 증명·검토 이력을 재구성",
                    {"bundle_id": remote_id, "same_completion": True, "same_reviews": True})

        revoked = self.review(remote_id, "revoked", "fixture-revoke-1")
        require(revoked["current_review"] == "revoked" and not revoked["recommended"], "취소 판정 미적용")
        self.bundle("fetch", "--agent-id", AGENT, "--id", remote_id, "--out", new_host / "revoked.sqlite3",
                    admin=True, success=False)
        require(not (new_host / "revoked.sqlite3").exists(), "취소된 기본 fetch가 파일을 게시함")
        rejected = self.trial(remote_id, new_host / "revoked-trial", False)
        require(rejected["failure_code"] == "remote_review_not_good", "취소 시험 거부 근거 오류")
        evidence = new_host / "revoked-evidence.sqlite3"
        fetched = self.parsed("fetch", "--agent-id", AGENT, "--id", remote_id,
                              "--out", evidence, "--evidence-only", admin=True)
        require(fetched["evidence_only"] is True and fetched["recommended"] is False, "조사용 취소본을 추천으로 표시함")
        require(digest_file(evidence) == self.expected_hash, "취소 이후 보존한 증거 바이트 불일치")
        self.record("취소 전파·기본 복구 거부·조사용 보존",
                    "취소 후 기본 fetch와 시험을 거부하고 evidence-only의 검증된 바이트 수집만 허용",
                    {"review_sequence": len(revoked["reviews"]), "failure_code": rejected["failure_code"],
                     "evidence_sha256": self.expected_hash, "recommended": False})

    def insufficient_rows(self):
        fixture = self.work / "insufficient-rows"
        fixture.mkdir(mode=0o700)
        original, backup = fixture / "source.sqlite3", fixture / "backup.sqlite3"
        native_backup(original, backup)
        plan = fixture / "plan.toml"
        plan.write_text(plan_text(backup, min_rows=3), encoding="utf-8")
        stage = fixture / "stage"
        prepared = self.parsed("prepare", "--file", backup, "--out", stage,
                               "--original-path", original, "--plan", plan)
        uploaded = self.parsed("upload", "--stage", stage)
        require(uploaded["completion"] is not None, "행 부족 fixture의 원격 게시 실패")
        bundle_id = prepared["bundle_id"]
        self.review(bundle_id, "good", "fixture-small-good")
        result = self.trial(bundle_id, fixture / "trial", False)
        require(result["failure_code"] == "service_recovery_failed", "행 부족을 DB 시험 실패로 분류하지 않음")
        require(result["drill_report"]["failure_code"] == "sqlite_row_expectation_failed", "행 부족의 구체 시험 근거 누락")
        require(result["recommended"] is False, "정상 판정만으로 실패한 DB 시험을 복구 추천함")
        self.record("정상 판정 이후에도 행 부족 시험은 추천 거부",
                    "원격 Good과 별개로 내장 계획의 최소 행 수 검사 실패 시 복구 추천을 보류",
                    {"failure_code": result["failure_code"], "drill_failure_code": result["drill_report"]["failure_code"],
                     "recommended": False})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=Path(os.environ.get("ARGOS_BIN_DIR", "target/debug")))
    parser.add_argument("--report", type=Path, help="새 0600 JSON 보고서 경로")
    parser.add_argument("--keep", action="store_true", help="성공 시에도 임시 자료 보존")
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    for name in ("argos", "argos-vault"):
        if not (binaries / name).is_file():
            parser.error(f"빌드된 바이너리가 없습니다: {binaries / name}")
    output = None
    if args.report:
        try:
            descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            output = os.fdopen(descriptor, "w", encoding="utf-8")
        except OSError as error:
            parser.error(f"새 보고서 파일을 만들 수 없습니다: {error}")
    previous_umask = os.umask(0o077)
    work = Path(tempfile.mkdtemp(prefix="argos-bundle-recovery-"))
    os.chmod(work, 0o700)
    suite = Scenarios(binaries, work)
    report = {"format": "argos-bundle-cli-scenarios-v1", "bin_dir": str(binaries),
              "work_dir": str(work), "passed": False, "scenarios": suite.results,
              "limits": {"object_bytes": 64 * MIB, "chunk_bytes": 16 * MIB,
                         "workspace_bytes": 512 * MIB, "drill_timeout_secs": 60,
                         "http_timeout_secs": 30, "subprocess_timeout_secs": 120},
              "limitations": ["같은 loopback 시험 호스트에서 원본 자료를 삭제하고 새 작업 경로를 사용함; 실제 별도 서버 이전 시험이 아님",
                              "합성 SQLite native backup만 사용; 실제 업무 DB·서비스 가용성·RPO/RTO를 증명하지 않음",
                              "시험 보고서는 무서명이며 실행자 신원을 인증하지 않음",
                              "디스크 여유 공간 설정은 합성 시험에서만 0으로 설정; 운영 기본 여유 한도 검증이 아님"]}
    exit_code = 1
    try:
        report["version"] = suite.cli("--version").stdout.strip()
        suite.setup()
        suite.large_bundle()
        suite.insufficient_rows()
        report["passed"] = True
        exit_code = 0
    except (AssertionError, OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
    finally:
        suite.close()
        report["passed_scenarios"] = len(suite.results)
        report["temporary_files_retained"] = bool(args.keep or exit_code)
        if output:
            output.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
            output.close()
        if args.keep or exit_code:
            print(f"임시 결과 보존: {work}", flush=True)
        else:
            shutil.rmtree(work)
        os.umask(previous_umask)
    print(f"{len(suite.results)} 번들 복구 시나리오 {'통과' if not exit_code else '완료 전 실패'}", flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
