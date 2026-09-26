#!/usr/bin/env python3
"""호스트 방화벽에 접근하지 않는 IPv4/IPv6 격리 패킷 통합 시험.

필요: Linux의 비특권 user/net namespace, iproute2, iptables/ip6tables,
      cargo build -p argos-cli로 생성한 argos 바이너리.
사용: python3 scripts/test-isolation-netns.py --argos /absolute/path/to/argos
"""

import argparse
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading


def actor():
    """TCP 시험의 제어 경로는 네트워크 대신 부모와의 파이프를 사용한다."""
    sockets = {}
    listeners = []

    def echo(connection):
        try:
            while data := connection.recv(1024):
                connection.sendall(data)
        except OSError:
            pass
        finally:
            connection.close()

    def listen(server):
        while True:
            connection, _ = server.accept()
            threading.Thread(target=echo, args=(connection,), daemon=True).start()

    print(json.dumps({"ready": True}), flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        try:
            operation = request["operation"]
            if operation == "listen":
                family = socket.AF_INET6 if ":" in request["host"] else socket.AF_INET
                server = socket.socket(family)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                server.bind((request["host"], request["port"]))
                server.listen(16)
                listeners.append(server)
                threading.Thread(target=listen, args=(server,), daemon=True).start()
            elif operation == "connect":
                connection = socket.create_connection(
                    (request["host"], request["port"]), timeout=0.5
                )
                connection.settimeout(0.5)
                sockets[request["id"]] = connection
            elif operation == "exchange":
                connection = sockets[request["id"]]
                connection.sendall(b"argos-test\n")
                if connection.recv(1024) != b"argos-test\n":
                    raise OSError("에코 내용 불일치")
            else:
                raise ValueError("알 수 없는 제어 명령")
            response = {"ok": True}
        except (OSError, ValueError) as error:
            response = {"ok": False, "error": str(error)}
        print(json.dumps(response), flush=True)


def rpc(process, **request):
    process.stdin.write(json.dumps(request) + "\n")
    process.stdin.flush()
    if not select.select([process.stdout], [], [], 5)[0]:
        raise AssertionError("시험 프로세스 제어 응답 시간 초과")
    result = process.stdout.readline()
    if not result:
        raise AssertionError("시험 프로세스가 중단되었습니다")
    return json.loads(result)


def command(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise AssertionError(f"명령 실패: {args}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def isolated_test(binary, parent_namespace):
    # 실제 방화벽 명령보다 먼저 격리 확인. 호스트 namespace에서는 무조건 거부한다.
    if not parent_namespace or os.readlink("/proc/self/ns/net") == parent_namespace:
        raise AssertionError("독립 네트워크 namespace가 아니므로 시험을 거부합니다")
    mapping = Path("/proc/self/uid_map").read_text().split()
    if os.geteuid() != 0 or len(mapping) != 3 or mapping[0] != "0" or mapping[2] != "1":
        raise AssertionError("전용 단일 사용자 매핑이 아니므로 시험을 거부합니다")
    interfaces = command("ip", "-o", "link", "show").splitlines()
    if len(interfaces) != 1 or ": lo:" not in interfaces[0]:
        raise AssertionError("빈 시험 namespace가 필요합니다")
    actors = []

    def spawn(new_namespace):
        args = [sys.executable, str(Path(__file__).resolve()), "--actor"]
        if new_namespace:
            args = ["unshare", "--net", "--", *args]
        process = subprocess.Popen(args, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        actors.append(process)
        if not select.select([process.stdout], [], [], 5)[0]:
            raise AssertionError("시험 namespace 시작 실패")
        assert json.loads(process.stdout.readline())["ready"]
        return process

    def peer_command(peer, *args):
        return command("nsenter", "--target", str(peer.pid), "--net", "--", *args)

    try:
        left, right, host = spawn(True), spawn(True), spawn(False)
        command("ip", "link", "set", "lo", "up")
        for label, subnet, peer in [("left", 1, left), ("right", 2, right)]:
            interface, other = f"argos-{label}", f"peer-{label}"
            command("ip", "link", "add", interface, "type", "veth", "peer", "name", other)
            command("ip", "link", "set", other, "netns", str(peer.pid))
            command("ip", "addr", "add", f"10.20.{subnet}.1/24", "dev", interface)
            command("ip", "-6", "addr", "add", f"fd00:{subnet}::1/64", "dev", interface, "nodad")
            command("ip", "link", "set", interface, "up")
            peer_command(peer, "ip", "link", "set", "lo", "up")
            peer_command(peer, "ip", "addr", "add", f"10.20.{subnet}.2/24", "dev", other)
            peer_command(peer, "ip", "-6", "addr", "add", f"fd00:{subnet}::2/64", "dev", other, "nodad")
            peer_command(peer, "ip", "link", "set", other, "up")
            remote = 3 - subnet
            peer_command(peer, "ip", "route", "add", f"10.20.{remote}.0/24", "via", f"10.20.{subnet}.1")
            peer_command(peer, "ip", "-6", "route", "add", f"fd00:{remote}::/64", "via", f"fd00:{subnet}::1")
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
        Path("/proc/sys/net/ipv6/conf/all/forwarding").write_text("1")

        for firewall in ["iptables", "ip6tables"]:
            command(firewall, "-N", "ARGOS_TEST_UNRELATED")
            command(firewall, "-A", "ARGOS_TEST_UNRELATED", "-j", "RETURN")

        cases = []
        for family, host_address, remote_address in [
            ("IPv4", "10.20.1.1", "10.20.2.2"),
            ("IPv6", "fd00:1::1", "fd00:2::2"),
        ]:
            for port in [2222, 3333]:
                assert rpc(host, operation="listen", host=host_address, port=port)["ok"]
            for port in [4444, 5555]:
                assert rpc(right, operation="listen", host=remote_address, port=port)["ok"]
            for label, client, address, port, permitted in [
                ("INPUT management", left, host_address, 2222, True),
                ("INPUT established suspect", left, host_address, 3333, False),
                ("OUTPUT management", host, remote_address, 4444, True),
                ("OUTPUT established suspect", host, remote_address, 5555, False),
                ("FORWARD container path", left, remote_address, 4444, False),
            ]:
                case_id = f"{family} {label}"
                assert rpc(client, operation="connect", id=case_id, host=address, port=port)["ok"], case_id
                assert rpc(client, operation="exchange", id=case_id)["ok"], case_id
                cases.append((case_id, client, address, port, permitted))

        allow = [
            "--allow", "in:10.20.1.2:2222", "--allow", "in:[fd00:1::2]:2222",
            "--allow", "out:10.20.2.2:4444", "--allow", "out:[fd00:2::2]:4444",
        ]
        # 존재하지 않는 명시적 설정 경로: 작업 디렉터리의 실제 운영 설정을 읽지 않는다.
        with tempfile.TemporaryDirectory(prefix="argos-isolation-netns-") as directory:
            os.environ["XTABLES_LOCKFILE"] = str(Path(directory) / "xtables.lock")
            cli = [binary, "--config", str(Path(directory) / "absent.toml"), "isolate"]
            command(*cli, *allow)
            command(*cli, *allow)  # 재적용에서도 중복 점프나 오래된 예외가 없어야 한다.
            for case_id, client, address, port, permitted in cases:
                result = rpc(client, operation="exchange", id=case_id)
                assert result["ok"] == permitted, (case_id, result, permitted)
                print(f"PASS {case_id}: {'허용' if permitted else '차단'}", flush=True)
                fresh = rpc(client, operation="connect", id=case_id + " new", host=address, port=port)
                assert fresh["ok"] == permitted, (case_id, "새 연결", fresh)
            for firewall in ["iptables", "ip6tables"]:
                state = command(firewall, "-S")
                assert "-A ARGOS_TEST_UNRELATED -j RETURN" in state
                for base in ["INPUT", "OUTPUT", "FORWARD"]:
                    assert state.count(f"-A {base} -j ARGOS_{base}\n") == 1
            command(*cli, "--release")
            command(*cli, "--release")
            for case_id, client, address, port, _ in cases:
                reopened = case_id + " released"
                assert rpc(client, operation="connect", id=reopened, host=address, port=port)["ok"], case_id
                assert rpc(client, operation="exchange", id=reopened)["ok"], case_id
            for firewall in ["iptables", "ip6tables"]:
                state = command(firewall, "-S")
                assert "-A ARGOS_TEST_UNRELATED -j RETURN" in state
                assert all(f"ARGOS_{base}" not in state for base in ["INPUT", "OUTPUT", "FORWARD"])
        print("PASS 새 연결/기존 연결, 양방향 관리 연결, 전달 차단, 재적용, 해제, 무관 규칙 보존", flush=True)
    finally:
        for process in actors:
            process.terminate()
        for process in actors:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--argos")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--actor", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--parent-namespace", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.actor:
        actor()
        return
    if args.inside:
        isolated_test(args.argos, args.parent_namespace)
        return
    if not args.argos:
        parser.error("--argos에 빌드한 바이너리의 경로를 지정하세요")
    for required in ["unshare", "nsenter", "ip", "iptables", "ip6tables", "iptables-save", "ip6tables-save", "iptables-restore", "ip6tables-restore"]:
        if not shutil.which(required):
            parser.error(f"필요한 도구가 없습니다: {required}")
    parent = os.readlink("/proc/self/ns/net")
    result = subprocess.run([
        "unshare", "--user", "--map-root-user", "--net", "--", sys.executable,
        str(Path(__file__).resolve()), "--inside", "--parent-namespace", parent,
        "--argos", str(Path(args.argos).resolve()),
    ])
    if os.readlink("/proc/self/ns/net") != parent:
        raise AssertionError("부모 프로세스 namespace 변경 감지")
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
