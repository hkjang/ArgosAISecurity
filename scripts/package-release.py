#!/usr/bin/env python3
"""Commit된 소스의 문서와 검증한 Linux 실행 파일을 이전 릴리즈 형식으로 포장한다."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True, help='존재하지 않는 새 출력 디렉터리')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    def run(*command):
        return subprocess.check_output(command, cwd=repo, text=True).strip()
    if run('git', 'status', '--porcelain'):
        raise SystemExit('패키징 전에 모든 릴리즈 소스를 커밋해야 합니다.')
    if args.out.exists():
        raise SystemExit('출력 디렉터리가 이미 존재합니다.')
    if run('uname', '-m') != 'x86_64' or run('uname', '-s') != 'Linux':
        raise SystemExit('이 패키징 도구는 Linux x86_64 산출물용입니다.')
    version = tomllib.loads((repo / 'Cargo.toml').read_text())['workspace']['package']['version']
    binaries_path = args.bin_dir.resolve()
    if run(str(binaries_path / 'argos'), '--version') != f'argos {version}':
        raise SystemExit('CLI 바이너리와 소스 버전이 다릅니다.')
    commit = run('git', 'rev-parse', 'HEAD')
    name = f'argos-v{version}-linux-x86_64-gnu'
    directory = args.out.resolve() / name
    directory.mkdir(parents=True)
    for relative in run('git', 'ls-tree', '-r', '--name-only', 'HEAD').splitlines():
        if relative in ('README.md', 'LICENSE') or relative.startswith(('docs/', 'config/', 'packaging/', 'scripts/')):
            target = directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(subprocess.check_output(['git', 'show', f'HEAD:{relative}'], cwd=repo))
            target.chmod(0o644)
    (directory / 'bin').mkdir()
    binaries = {}
    for name_in_bin in ('argos', 'argos-agent', 'argos-central', 'argos-vault'):
        target = directory / 'bin' / name_in_bin
        shutil.copy2(binaries_path / name_in_bin, target)
        target.chmod(0o755)
        versions = re.findall(r'GLIBC_([0-9.]+)', run('readelf', '--version-info', str(target)))
        minimum = max(set(versions), key=lambda value: tuple(map(int, value.split('.'))))
        binaries[name_in_bin] = {
            'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
            'size_bytes': target.stat().st_size,
            'minimum_glibc': minimum,
            'needed_libraries': re.findall(r'\(NEEDED\).*?\[(.*?)\]', run('readelf', '-d', str(target))),
        }
    info = {
        'version': version, 'tag': f'v{version}',
        'source_repository': 'https://github.com/hkjang/ArgosAISecurity', 'source_commit': commit,
        'target': 'x86_64-unknown-linux-gnu',
        'minimum_glibc': max((item['minimum_glibc'] for item in binaries.values()), key=lambda value: tuple(map(int, value.split('.')))),
        'rustc': run('rustc', '--version'), 'cargo': run('cargo', '--version'),
        'build_command': 'cargo build --release --workspace --offline --locked',
        'packaged_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'binaries': binaries,
        'optional_drill_dependencies': 'PostgreSQL native tools and Linux bubblewrap are installed separately; not bundled.',
    }
    (directory / 'BUILD_INFO.json').write_text(json.dumps(info, indent=2) + '\n')
    archive = directory.parent / (directory.name + '.tar.gz')
    with tarfile.open(archive, 'w:gz') as tar:
        tar.add(directory, arcname=directory.name)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (directory.parent / 'SHA256SUMS').write_text(f'{digest}  {archive.name}\n')
    print(json.dumps({'archive': str(archive), 'sha256': digest, 'build_info': info}, indent=2))


if __name__ == '__main__':
    main()
