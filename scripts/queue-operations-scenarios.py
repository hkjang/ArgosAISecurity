#!/usr/bin/env python3
"""실제 CLI로 큐 순환·느린 전송 중 등록·오류 분류·수신증명 이력 내보내기를 검증한다."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from urllib.parse import urlparse

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('vault_scenarios', Path(__file__).with_name('vault-scenarios.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require = base.require
SECRET = b'PRIVATE-REMOTE-ERROR-MUST-NOT-PERSIST'


class Gateway(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, upstream):
        super().__init__(('127.0.0.1', 0), Handler)
        self.upstream = upstream
        self.mode = 'forward'
        self.started = threading.Event()
        self.release = threading.Event()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        mode = self.server.mode
        if mode == 'hold':
            self.server.started.set()
            self.server.release.wait(10)
        if isinstance(mode, int):
            self.send_response(mode)
            self.send_header('Content-Length', str(len(SECRET)))
            self.end_headers()
            self.wfile.write(SECRET)
            return
        connection = http.client.HTTPConnection(self.server.upstream.hostname, self.server.upstream.port, timeout=10)
        try:
            connection.request('POST', self.path, body, {k: v for k, v in self.headers.items() if k.lower() != 'host'})
            response = connection.getresponse()
            data = response.read()
            self.send_response(response.status)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(data)
        finally:
            connection.close()


class Scenarios(base.Scenarios):
    def queue(self, *args, config=None, success=True):
        return self.cli('vault', '--vault-config', config or self.upload_config, 'queue', *args, success=success)

    def status(self, directory):
        return json.loads(self.cli('vault', 'queue', 'status', '--directory', directory).stdout)

    def archive_cycle(self):
        directory = self.work / 'archive-queue'
        source = self.work / 'source.bin'
        first = None
        for n in range(4):
            source.write_bytes(f'archive-{n}'.encode())
            item = json.loads(self.queue('enqueue', '--directory', directory, '--file', source, '--kind', 'audit', '--max-items', 1).stdout)
            if n == 0:
                first = item
            report = json.loads(self.queue('drain', '--directory', directory, '--max-items', 1).stdout)
            require(report['sent'] == 1 and report['remaining_pending'] == 0, '완료 후 활성 슬롯 미해제')
        source.write_bytes(b'archive-0')
        duplicate = json.loads(self.queue('enqueue', '--directory', directory, '--file', source, '--kind', 'audit', '--max-items', 1).stdout)
        require(duplicate['id'] == first['id'] and duplicate['state'] == 'sent', '완료 보관소 중복 판정 실패')
        show = json.loads(self.cli('vault', 'queue', 'show', '--directory', directory, '--id', first['id']).stdout)
        require(show['receipt']['receipt']['sha256'] == first['sha256'], '이전 수신증명 조회 실패')
        status = self.status(directory)
        require(status['sent_items'] == 4 and status['pending_items'] == 0, '활성/완료 집계 불일치')
        archive = self.work / 'receipts.jsonl'
        exported = json.loads(self.cli('vault', 'queue', 'export-archive', '--directory', directory, '--out', archive).stdout)
        require(exported['archived_items'] == 4 and exported['source_preserved'], '내보내기 수/보존 상태 오류')
        saved_queue = self.work / 'saved-queue'
        directory.rename(saved_queue)
        verified = json.loads(self.cli('vault', 'queue', 'verify-archive', '--file', archive, '--pubkey', self.public_key).stdout)
        require(verified['archived_items'] == 4 and not verified['archive_authenticated'], '독립 검증 의미 오류')
        truncated = self.work / 'truncated.jsonl'
        truncated.write_bytes(archive.read_bytes()[:-8])
        truncated.chmod(0o600)
        self.cli('vault', 'queue', 'verify-archive', '--file', truncated, '--pubkey', self.public_key, success=False)
        saved_queue.rename(directory)
        self.cli('vault', 'queue', 'export-archive', '--directory', directory, '--out', archive, success=False)
        self.record('완료 이력 분리·중복 방지·오프라인 내보내기 검증',
                    '활성 한도 1개로 4회 전달하고 원본 큐 없이 서명 검증, 잘린 파일·덮어쓰기 거부',
                    {'active_limit': 1, 'completed': 4, 'same_duplicate_id': True, 'archive_authenticated': False})

    def concurrent_registration(self, gateway, config):
        directory = self.work / 'concurrent-queue'
        source = self.work / 'slow.bin'
        source.write_bytes(b'slow-first')
        self.queue('enqueue', '--directory', directory, '--file', source, '--kind', 'audit', config=config)
        gateway.mode = 'hold'
        process, log = self.start('argos', 'slow-drain', 'vault', '--vault-config', config, 'queue', 'drain', '--directory', directory, '--max-items', 1)
        try:
            require(gateway.started.wait(5), '느린 서버 전송 시작 실패')
            source.write_bytes(b'enqueue-during-network-wait')
            started = time.monotonic()
            item = json.loads(self.queue('enqueue', '--directory', directory, '--file', source, '--kind', 'audit', config=config).stdout)
            elapsed = time.monotonic() - started
            require(elapsed < 2 and process.poll() is None, '네트워크 대기 중 등록이 막힘')
            # 같은 큐의 별도 worker도 임대한 첫 항목을 중복 전송하지 않는다.
            gateway.mode = 'forward'
            second = json.loads(self.queue('drain', '--directory', directory, '--max-items', 1, config=config).stdout)
            require(second['sent'] == 1, '다른 활성 항목의 동시 worker 처리 실패')
            gateway.release.set()
            require(process.wait(timeout=10) == 0, f'첫 worker 실패: {log.read_text()}')
            state = self.status(directory)
            require(state['pending_items'] == 0 and state['sent_items'] == 2, '동시 전달 완료 수 오류')
            self.record('느린 전송 중 신규 등록·별도 작업자 처리', '첫 요청을 대기시킨 상태에서 등록과 두 번째 항목 전송 성공',
                        {'enqueue_seconds': round(elapsed, 3), 'second_id': item['id'], 'completed': 2})
        finally:
            gateway.release.set()
            self.stop(process)
            gateway.mode = 'forward'

    def classified_failures(self, gateway, config):
        source = self.work / 'failure.bin'
        observed = {}
        for status, code in [(401, 'authentication'), (507, 'capacity'), (429, 'rate_limit'), (503, 'server_transient')]:
            directory = self.work / f'error-{status}'
            source.write_bytes(f'failure-{status}'.encode())
            self.queue('enqueue', '--directory', directory, '--file', source, '--kind', 'audit', config=config)
            gateway.mode = status
            result = self.queue('drain', '--directory', directory, config=config, success=False)
            report = json.loads(result.stdout)
            state = self.status(directory)
            require(report['failed'] == 1 and state['pending_items'] == 1, '실패 항목 유실')
            require(state['items'][0]['last_error'] == code, f'{status} 오류 유형 불일치: {state}')
            for path in directory.rglob('*'):
                if path.is_file():
                    require(SECRET not in path.read_bytes(), '원격 오류 본문이 큐에 저장됨')
            require(SECRET.decode() not in result.stdout + result.stderr, '원격 오류 본문 노출')
            observed[str(status)] = code
        gateway.mode = 'forward'
        self.record('오류 유형·재시도 보존·비밀값 비노출', '인증/용량/호출 제한/서버 오류를 구별하고 pending 유지', observed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, default=Path('target/debug'))
    parser.add_argument('--report', type=Path)
    parser.add_argument('--keep', action='store_true')
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix='argos-queue-operations-'))
    scenario = Scenarios(args.bin_dir.resolve(), work)
    report = {'suite': 'queue-operations', 'passed': False, 'scenarios': scenario.results}
    gateway = None
    code = 1
    output = None
    try:
        if args.report:
            output = os.fdopen(os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w')
        scenario.setup()
        scenario.archive_cycle()
        endpoint = urlparse(tomllib.loads(scenario.upload_config.read_text())['endpoint'])
        gateway = Gateway(endpoint)
        thread = threading.Thread(target=gateway.serve_forever, daemon=True)
        thread.start()
        config = work / 'gateway.toml'
        base.private_text(config, re.sub(r'^endpoint\s*=.*$', f'endpoint="http://127.0.0.1:{gateway.server_port}"', scenario.upload_config.read_text(), flags=re.M))
        scenario.concurrent_registration(gateway, config)
        scenario.classified_failures(gateway, config)
        report['passed'] = True
        code = 0
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        print(f'FAIL: {error}', file=sys.stderr)
    finally:
        if gateway:
            gateway.release.set()
            gateway.shutdown()
            gateway.server_close()
        scenario.close()
        if output:
            with output:
                json.dump(report, output, ensure_ascii=False, indent=2)
                output.write('\n')
                output.flush()
                os.fsync(output.fileno())
        if code or args.keep:
            print(f'결과 보존: {work}')
        else:
            shutil.rmtree(work)
    print(f'{len(scenario.results)} 큐 운영 시나리오 {"통과" if code == 0 else "실패"}')
    return code


if __name__ == '__main__':
    sys.exit(main())
