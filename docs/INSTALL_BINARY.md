# Linux 바이너리 설치

v0.7.0 패키지는 x86_64 Linux와 **glibc 2.39 이상**을 요구한다. `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, `/lib64/ld-linux-x86-64.so.2`가 필요하다. 배포판의 glibc가 더 오래되었거나 아키텍처가 다르면 태그 소스에서 `cargo build --release --workspace --locked`로 빌드한다. Linux 소스 빌드 최소 Rust 버전은 1.86이고, 릴리즈 검증 버전은 1.93.1이다.

[v0.7.0 GitHub 릴리즈](https://github.com/hkjang/ArgosAISecurity/releases/tag/v0.7.0)에서 압축 파일과 `SHA256SUMS`를 같은 새 디렉터리에 내려받고 검증한다. [릴리즈 노트](releases/v0.7.0.md)에 기능 변경과 정책 설정 이전 절차가 있다.

```bash
mkdir argos-v0.7.0-download
cd argos-v0.7.0-download
curl -fLO https://github.com/hkjang/ArgosAISecurity/releases/download/v0.7.0/argos-v0.7.0-linux-x86_64-gnu.tar.gz
curl -fLO https://github.com/hkjang/ArgosAISecurity/releases/download/v0.7.0/SHA256SUMS
sha256sum -c SHA256SUMS
tar -xzf argos-v0.7.0-linux-x86_64-gnu.tar.gz
cd argos-v0.7.0-linux-x86_64-gnu
./bin/argos --version
./bin/argos --help
```

`BUILD_INFO.json`에는 소스 커밋, 빌드 도구, 실행 파일별 SHA-256과 동적 라이브러리 요구사항이 들어 있다. 압축 파일에는 `bin/`, `config/`, `packaging/`, `docs/`, `scripts/`, `README.md`, `LICENSE`가 포함된다. 기본 설정은 자동 차단을 비활성화한다.

## 직접 실행

```bash
cp config/argos.example.toml argos.toml
mkdir -p watched argos-data
./bin/argos-agent --config argos.toml
```

실행 전 `watch_paths`, `db_path`, `[backup].dir`을 환경에 맞게 수정한다. 백업 디렉터리는 감시 경로 밖에 둔다. `notify` 센서는 일반 사용자로 실행할 수 있으나 원인 PID를 제공하지 않는다. Linux `fanotify` 센서에는 필요한 커널 지원과 권한이 필요하다. 정상본 지정·미리보기 절차는 [복구 안내](FEATURE_RECOVERY.md)를 따른다.

위 예제 설정은 `./watched`와 `./argos-data`를 사용한다. 설정 파일이 없는 Linux 기본 실행은 `/home`과 `/var/lib/argos/argos.db`를 사용하므로, 의도한 파일을 `--config`로 명시한다. 다른 터미널에서도 같은 작업 디렉터리와 설정 파일을 사용한다.

```bash
./bin/argos --config argos.toml doctor
./bin/argos --config argos.toml status
./bin/argos --config argos.toml recovery-status
```

`doctor`는 설정·저장소 경로와 실행 플랫폼 등을 보여주는 기본 진단이며 커널 권한이나 전체 보호 동작을 인증하지 않는다. `status`에서 센서·프로세스 감시·백업·보존 대기열·정책 유효성 상태를 함께 확인한다. 다중 시간 구간·내용 표본은 기본 비활성이며, Linux 설정 의미 감시는 `[semantic].files`와 `watch_paths`에 실제 보호 경로를 지정해야 한다.

## systemd 서비스

기존 설치를 교체할 때는 먼저 서비스를 중지하고 설정, 이벤트 DB 및 백업 저장소를 보관한다. 서명 정책을 사용하면 정책 상태 디렉터리도 함께 보관하고 [정책 설정 이전](FEATURE_POLICY.md#이전-설정에서-이전하기)을 먼저 완료한다. v0.1.0의 `policy.pubkey`만 있는 정책은 v0.7.0 운영 활성화에서 거부된다. 설치 예시는 다음과 같다. 기존 `/etc/argos/argos.toml`은 덮어쓰지 않는다.

```bash
sudo install -m 0755 bin/argos bin/argos-agent bin/argos-central bin/argos-vault /usr/bin/
sudo install -d -m 0750 /etc/argos /var/lib/argos
sudo install -m 0640 config/argos.example.toml /etc/argos/argos.toml.example
sudo install -m 0644 packaging/argos-agent.service /etc/systemd/system/argos-agent.service
```

예제를 참고해 `/etc/argos/argos.toml`을 작성하고 권한을 `0640` 이하로 설정한다. 서비스 설정에는 절대 경로를 사용한다. 예를 들어 `db_path = "/var/lib/argos/argos.db"`, `[backup].dir = "/var/lib/argos/backup"`으로 지정하고 `watch_paths`에는 실제 보호 경로를 넣는다. 유닛의 `ProtectSystem=full` 및 `ReadWritePaths=/var/lib/argos`가 선택한 저장 경로의 쓰기를 허용하는지도 확인한다.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now argos-agent
sudo systemctl status argos-agent
sudo journalctl -u argos-agent -n 100 --no-pager
sudo argos --config /etc/argos/argos.toml status
```

중앙 서버는 운영용 관리자 토큰과 개별 에이전트 토큰을 별도로 설정한다. [중앙 서버 안내](SERVICE_CENTRAL.md)를 따른다. 네트워크 격리에는 iptables/ip6tables 도구와 권한이 필요하다. [대응 안내](FEATURE_RESPONSE.md)의 관리 연결 허용 규칙과 `--dry-run`을 확인한 뒤 사용한다.

## 검증

패키지의 `scripts/smoke-test.sh`와 `scripts/platform-smoke.py`, `scripts/security-scenarios.py`는 임시 경로에서 시험한다. Python 시험에는 Python 3이 필요하다.

```bash
ARGOS_BIN_DIR="$PWD/bin" sh scripts/smoke-test.sh
python3 scripts/platform-smoke.py --bin-dir "$PWD/bin"
python3 scripts/security-scenarios.py --bin-dir "$PWD/bin"
```

격리 시험은 사용자/네트워크 네임스페이스를 지원하는 환경에서만 실행한다. 재현 명령과 검증하지 않은 범위는 [검증 기록](PLATFORM_VALIDATION.md)을 확인한다.

## 운영 기능 안내

- 정책 설정과 서명·버전 관리: [정책 신뢰](FEATURE_POLICY.md)
- 정상본 확인·사건 보존·승인 해제: [복구](FEATURE_RECOVERY.md)
- SSH 키·sudoers·cron·systemd 변경 분석: [Linux 분석](FEATURE_LINUX_ANALYSIS.md)
- 사고 인계용 내보내기와 해시 검증: [증거 패키지](FEATURE_EVIDENCE_PACKAGE.md)
- 기간별 AI 근거 조회와 Ollama 설정: [AI 조사](FEATURE_AI.md)

## v0.7.0 검증 도구 준비

`argos-vault`는 별도 보관 호스트에 설치하고 [인증·TLS·키 설정](FEATURE_REMOTE_VAULT.md)을 적용한다. 에이전트 설치만으로 원격 보관이 활성화되지는 않는다. PostgreSQL 복구 시험에는 일반 사용자, 작동하는 `/usr/bin/bwrap`과 별도 PostgreSQL 도구가 필요하다. [복구 계획](FEATURE_SERVICE_RECOVERY.md)에 입력 형식과 검증 범위를 설명한다.

```bash
python3 scripts/assurance-scenarios.py --bin-dir "$PWD/bin"
python3 scripts/vault-scenarios.py --bin-dir "$PWD/bin"
python3 scripts/durability-scenarios.py --bin-dir "$PWD/bin"
python3 scripts/service-recovery-scenarios.py --bin-dir "$PWD/bin"
# PostgreSQL 18 도구를 설치한 호스트에서는 추가 실행:
python3 scripts/service-recovery-scenarios.py --bin-dir "$PWD/bin" --pg-root /
```

추가 시나리오는 Python 3.11 이상을 사용한다. 실제 자료 대신 임시 합성 데이터와 loopback 시험 서버를 사용하며 PostgreSQL 드릴은 root로 실행하지 않는다.

v0.3.0 보관 서버에서 이전할 때는 [용량 기본값·정합성 검사](FEATURE_VAULT_CAPACITY.md)를 먼저 확인한다. 기존 복구 v1 보고서는 새 `verify`의 성공 근거로 사용할 수 없으므로 현재 계획으로 시험을 다시 실행한다. 대기열은 선택 기능이며 [영속 전송 안내](FEATURE_VAULT_QUEUE.md)의 완료 이력 상한과 재시도 명령을 확인한다.

## v0.5.0에서 도입한 큐 운영 이전

v0.4.0의 전송 프로세스를 모두 종료하고 큐를 보관한 뒤 교체한다. 첫 변경 작업이 기존 서명 수신증명을 검증하고 큐 DB를 v2로 원자적으로 이전한다. 이전 뒤 v0.4.0 바이너리를 같은 큐에 사용하지 않는다. 완료 이력은 활성 항목 한도에서 제외되지만 총 예약 슬롯 100,000개 한도가 있다. [이력 내보내기](FEATURE_VAULT_QUEUE.md)와 [선택적 예약 전송](FEATURE_VAULT_SCHEDULER.md)을 따른다.

```bash
python3 scripts/queue-operations-scenarios.py --bin-dir "$PWD/bin"
```


## v0.6.0에서 도입한 복구 묶음

백업 한 파일과 메타데이터를 16MiB 청크·최대 1GiB로 보관하는 [복구 묶음](FEATURE_RECOVERY_BUNDLE.md)이 추가됐다. 서버와 클라이언트를 함께 업그레이드하고 작업자를 중지한 상태에서 보관 저장소·카탈로그·서명키·큐를 보존한다. 번들 카탈로그와 내부 제어 객체가 생긴 저장소는 v0.5 이하 서버에 그대로 연결하지 않는다. v0.6.0은 v0.5 큐 schema v2를 사용했다. 현재 v0.7.0의 schema v3 이전 절차는 아래를 따른다.

새 호스트 복구에는 원본 에이전트 DB 대신 관리자 보관 설정·고정 공개키와 DB 시험 도구가 필요하다. 준비 stage, 복구 부모와 출력은 전용 경로로 만든다. [prepare → 영속 등록·자동 게시 → 격리 시험 → 검토](FEATURE_RECOVERY_BUNDLE_CLI.md) 절차를 따른다. 운영 파일 덮어쓰기·서비스 자동 시작·로컬 정상본 취소 자동 전파는 포함하지 않는다. 최신 실행 결과와 재현 명령은 [검증 기록](PLATFORM_VALIDATION.md)을 확인한다.

BUILD_INFO.json의 기록과 해시는 패키지 확인 자료다. 모든 실행 파일의 소스 커밋 내장·독립 빌드 대조·서명 빌드 기록은 아직 후속이다.

```bash
python3 scripts/bundle-recovery-scenarios.py --bin-dir "$PWD/bin"
```

이 시험은 동일 loopback 호스트의 별도 새 경로에서 약 67MiB 합성 SQLite 백업을 복구한다. 실제 다른 호스트·원격 TLS 배포·운영 자료의 복구 성능을 검증하는 시험은 아니다.

## v0.7.0 이전

기존 예약 전송과 큐 작업자를 중지하고 큐 전체를 보존한다. 첫 변경 작업이 이전 큐를 schema v3로 이관하며 이후 같은 큐에 구버전 작업자를 연결하지 않는다. 번들 enqueue 출력은 고유 청크 배열 chunk_items와 작업의 state/phase로 변경된다. [자동 재개](FEATURE_BUNDLE_JOBS.md)를 따른다.

서버의 취소 예약 자원은 일반 업로드의 디스크 여유 요건에 추가 영향을 준다. [용량 기본값](FEATURE_VAULT_CAPACITY.md)을 확인하고 물리 여유를 확보한다. 승인 전 SQLite 시험은 Linux x86_64 GNU·비 root·신뢰한 bubblewrap과 런타임·Linux 5.11 이상 close_range 지원이 필요하며 무격리 대체 실행은 없다. 관리자 보관 설정의 사설 TLS CA는 [원격 보관](FEATURE_REMOTE_VAULT.md)을 따른다.

```bash
python3 scripts/bundle-operations-scenarios.py --bin-dir "$PWD/bin" --report /tmp/argos-bundle-operations-new.json
```

위 스크립트는 openssl·bubblewrap을 사용한 같은 호스트의 임시 TLS/격리 시험이다. 실제 서버 3대나 운영 인증서를 검증하지 않는다.
