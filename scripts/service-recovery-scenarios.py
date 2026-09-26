#!/usr/bin/env python3
"""Run real CLI restore drills using only temporary synthetic databases.

SQLite is always tested. --pg-root adds PostgreSQL custom archive scenarios;
that package tree and /usr/bin/bwrap must already be installed and trusted.
No production database, network connection, user SQL, or system config is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time


def invoke(binary, plan, out, expected, config=None):
    command = [str(binary)]
    if config is not None:
        command += ["--config", str(config)]
    command += ["service-recovery", "test", "--plan", str(plan), "--out", str(out)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    assert (result.returncode == 0) == expected, (result.returncode, result.stdout, result.stderr)
    if not result.stdout.strip():
        assert not expected
        return None
    report = json.loads(result.stdout)
    assert report["status"] == ("passed" if expected else "failed"), report
    assert report["rpo_ms"] is None and report["service_rto_ms"] is None, report
    assert "PRIVATE-FIXTURE-DATA" not in result.stdout + result.stderr
    if expected:
        persisted = json.loads((out / "service-recovery.json").read_text())
        assert persisted == report
    return report


def plan_text(backup, engine="sqlite", pg_root=None, min_rows=2, timeout=10):
    text = (f'service_id = "orders-fixture"\nengine = "{engine}"\n'
            f'backup_path = {json.dumps(str(backup))}\ntimeout_secs = {timeout}\n'
            'max_backup_bytes = 16777216\nmax_workspace_bytes = 536870912\n')
    if engine == "sqlite":
        text += 'expected_user_version = 7\n'
    else:
        text += f'[postgresql]\ninstallation_root = {json.dumps(str(pg_root))}\nmajor_version = 18\n'
    return text + ('[[tables]]\ncheck_id = "orders-schema-rows"\ntable = "orders"\n'
                   'required_columns = ["id", "secret"]\n' + f'min_rows = {min_rows}\n')


def sqlite_scenarios(binary, root, passed):
    original, backup = root / "original.sqlite3", root / "backup.sqlite3"
    with sqlite3.connect(original) as database:
        database.executescript("PRAGMA user_version=7; CREATE TABLE orders(id INTEGER PRIMARY KEY, secret TEXT);"
                               "INSERT INTO orders VALUES(1,'PRIVATE-FIXTURE-DATA'),(2,'second');")
        with sqlite3.connect(backup) as destination:
            database.backup(destination)
    before = hashlib.sha256(backup.read_bytes()).hexdigest()
    plan = root / "sqlite.toml"
    plan.write_text(plan_text(backup))
    unrelated_config = root / "invalid-argos.toml"
    unrelated_config.write_text("INVALID-UNRELATED-CONFIG-SECRET!")
    report = invoke(binary, plan, root / "sqlite-ok", True, unrelated_config)
    assert report["backup_sha256"] == before
    assert any(check["check_id"] == "argos-write-read-rollback" and check["passed"] for check in report["checks"])
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == before
    with sqlite3.connect(root / "sqlite-ok/restored.sqlite3") as restored:
        assert restored.execute("SELECT count(*) FROM orders").fetchone()[0] == 2
        assert restored.execute("SELECT count(*) FROM sqlite_master WHERE name='__argos_service_recovery_probe'").fetchone()[0] == 0
    passed += ["sqlite-native-backup-restore", "sqlite-write-rollback", "original-unchanged", "unknown-RPO-and-service-RTO", "unrelated-config-ignored", "sensitive-row-not-in-report"]
    invoke(binary, plan, root / "sqlite-ok", False)
    passed.append("existing-workspace-refused")
    plan.write_text(plan_text(backup, min_rows=3))
    assert invoke(binary, plan, root / "sqlite-short", False)["failure_code"] == "sqlite_row_expectation_failed"
    passed.append("insufficient-rows-fail")
    plan.write_text(plan_text(backup))
    Path(str(backup) + "-wal").write_bytes(b"simulated-live-sidecar")
    assert invoke(binary, plan, root / "sqlite-live", False)["failure_code"] == "offline_native_backup_required"
    Path(str(backup) + "-wal").unlink()
    passed.append("live-sqlite-sidecar-refused")
    plan.write_text(plan_text(backup).replace('table = "orders"', 'table = "orders; DROP TABLE orders"'))
    invoke(binary, plan, root / "sqlite-injection", False)
    passed.append("SQL-identifier-injection-refused")


def postgres_fixture(root, pg_root):
    assert os.geteuid() != 0, "PostgreSQL scenarios must run as a regular user"
    assert Path('/usr/bin/bwrap').is_file(), "bubblewrap is required; no host fallback"
    work = root / "pg-fixture"
    work.mkdir(mode=0o700)
    (work / "socket").mkdir(mode=0o700)
    (root / "fixture-passwd").write_text(f"argos:x:{os.getuid()}:{os.getgid()}:Argos:/work:/bin/false\n")
    (root / "fixture-group").write_text(f"argos:x:{os.getgid()}:\n")
    install = '/opt/pg/usr/lib/postgresql/18'
    common = ['/usr/bin/bwrap', '--unshare-all', '--unshare-user', '--unshare-net', '--unshare-pid', '--disable-userns',
              '--die-with-parent', '--new-session', '--clearenv', '--cap-drop', 'ALL', '--dir', '/usr',
              '--ro-bind', '/usr/bin', '/usr/bin', '--ro-bind', '/usr/lib', '/usr/lib', '--dir', '/usr/share']
    for directory in ['/bin', '/lib', '/lib64', '/usr/share/zoneinfo']:
        if Path(directory).exists():
            common += ['--ro-bind', directory, directory]
    common += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/etc',
               '--ro-bind', str(root / 'fixture-passwd'), '/etc/passwd', '--ro-bind', str(root / 'fixture-group'), '/etc/group',
               '--ro-bind', str(pg_root / 'usr/lib/postgresql/18'), install,
               '--ro-bind', str(pg_root / 'usr/share/postgresql/18'), '/opt/pg/usr/share/postgresql/18',
               '--ro-bind', str(pg_root / 'usr/lib/x86_64-linux-gnu'), '/opt/pglib',
               '--bind', str(work), '/work', '--chdir', '/work',
               '--setenv', 'PATH', f'{install}/bin:/usr/bin:/bin', '--setenv', 'LC_ALL', 'C',
               '--setenv', 'HOME', '/work', '--setenv', 'LD_LIBRARY_PATH', '/opt/pglib', '--']

    def command(name, *arguments):
        return common + [f'{install}/bin/{name}'] + list(arguments)

    def call(name, *arguments, sql=None):
        result = subprocess.run(command(name, *arguments), input=sql, text=True, capture_output=True, timeout=15)
        if result.returncode:
            raise AssertionError(f"synthetic PostgreSQL fixture command {name} failed; install compatible tools and enable bubblewrap")
        return result.stdout

    call('initdb', '-D', '/work/data', '-U', 'argosverify', '--auth-local=trust', '--auth-host=reject', '--no-locale', '--encoding=UTF8', '--no-instructions')
    server = subprocess.Popen(command('postgres', '-D', '/work/data', '-k', '/work/socket', '-c', 'listen_addresses=', '-c', 'shared_buffers=16MB', '-c', 'max_connections=5', '-c', 'log_min_messages=panic'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    client = ('-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-h', '/work/socket', '-U', 'argosverify', '-d', 'postgres', '--no-password')
    try:
        deadline = time.monotonic() + 8
        while True:
            try:
                assert call('psql', *client, sql='SELECT 1;').strip() == '1'
                break
            except AssertionError:
                assert server.poll() is None and time.monotonic() < deadline, 'fixture PostgreSQL did not become ready'
                time.sleep(.05)
        call('psql', *client, sql="CREATE TABLE public.orders(id bigint PRIMARY KEY,secret text NOT NULL); INSERT INTO public.orders VALUES(1,'PRIVATE-FIXTURE-DATA'),(2,'second');")
        call('psql', *client, sql="""CREATE FUNCTION public.argos_fixture_delay() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN
IF EXISTS(SELECT 1 FROM pg_event_trigger_ddl_commands() WHERE object_identity='public.__argos_service_recovery_probe') THEN PERFORM pg_sleep(2); END IF;
END $$; CREATE EVENT TRIGGER argos_fixture_delay ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.argos_fixture_delay();""")
        call('pg_dump', '--format=custom', '--file=/work/orders.dump', '--host=/work/socket', '--username=argosverify', '--dbname=postgres', '--no-password')
    finally:
        server.kill()
        server.communicate(timeout=5)  # wait until namespace descendants close their pipes
    return work / 'orders.dump'


def postgres_scenarios(binary, root, pg_root, passed):
    backup = postgres_fixture(root, pg_root)
    plan = root / 'postgresql.toml'
    plan.write_text(plan_text(backup, 'postgresql', pg_root))
    report = invoke(binary, plan, root / 'pg-ok', True)
    assert any(check['check_id'] == 'argos-constraints' and check['passed'] for check in report['checks'])
    passed += ['postgresql-custom-archive-restore', 'postgresql-constraints-and-write-rollback']
    sock = socket.socket(socket.AF_UNIX)
    try:
        try:
            sock.connect(str(root / 'pg-ok/postgresql/socket/.s.PGSQL.5432'))
        except (FileNotFoundError, ConnectionRefusedError):
            pass
        else:
            raise AssertionError('PostgreSQL server remains running after drill')
    finally:
        sock.close()
    passed.append('postgresql-server-cleanup')
    plan.write_text(plan_text(backup, 'postgresql', pg_root, min_rows=3))
    assert invoke(binary, plan, root / 'pg-short', False)['failure_code'] == 'postgresql_row_expectation_failed'
    passed.append('postgresql-row-expectation-fails')
    # A fixture-only DDL trigger delays the fixed write probe by 2 seconds, so
    # this 1-second whole-drill deadline is deterministic on fast machines too.
    plan.write_text(plan_text(backup, 'postgresql', pg_root, timeout=1))
    result = invoke(binary, plan, root / 'pg-timeout', False)
    assert result['failure_code'] == 'timeout', result
    passed.append('postgresql-whole-drill-timeout')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, default=Path('target/debug'))
    parser.add_argument('--pg-root', type=Path, help='trusted Debian-style PostgreSQL 18 package root; enables optional PostgreSQL scenarios')
    args = parser.parse_args()
    binary = (args.bin_dir / 'argos').resolve()
    assert binary.is_file(), binary
    passed = []
    with tempfile.TemporaryDirectory(prefix='argos-service-scenarios-') as temporary:
        root = Path(temporary)
        sqlite_scenarios(binary, root, passed)
        if args.pg_root is not None:
            postgres_scenarios(binary, root, args.pg_root.resolve(), passed)
    print(json.dumps({'passed': passed, 'count': len(passed), 'postgresql_tested': args.pg_root is not None}, indent=2))


if __name__ == '__main__':
    main()
