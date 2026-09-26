# Linux 바이너리 설치

v0.2.0 패키지는 x86_64 Linux와 **glibc 2.39 이상**을 요구한다. `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, `/lib64/ld-linux-x86-64.so.2`가 필요하다. 배포판의 glibc가 더 오래되었거나 아키텍처가 다르면 태그 소스에서 `cargo build --release --workspace --locked`로 빌드한다. Linux 소스 빌드 최소 Rust 버전은 1.86이고, 릴리즈 검증 버전은 1.93.1이다.

[v0.2.0 GitHub 릴리즈](https://github.com/hkjang/ArgosAISecurity/releases/tag/v0.2.0)에서 압축 파일과 `SHA256SUMS`를 같은 새 디렉터리에 내려받고 검증한다. [릴리즈 노트](releases/v0.2.0.md)에 기능 변경과 정책 설정 이전 절차가 있다.

```bash
mkdir argos-v0.2.0-download
cd argos-v0.2.0-download
curl -fLO https://github.com/hkjang/ArgosAISecurity/releases/download/v0.2.0/argos-v0.2.0-linux-x86_64-gnu.tar.gz
curl -fLO https://github.com/hkjang/ArgosAISecurity/releases/download/v0.2.0/SHA256SUMS
sha256sum -c SHA256SUMS
tar -xzf argos-v0.2.0-linux-x86_64-gnu.tar.gz
cd argos-v0.2.0-linux-x86_64-gnu
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

기존 설치를 교체할 때는 먼저 서비스를 중지하고 설정, 이벤트 DB 및 백업 저장소를 보관한다. 서명 정책을 사용하면 정책 상태 디렉터리도 함께 보관하고 [정책 설정 이전](FEATURE_POLICY.md#이전-설정에서-이전하기)을 먼저 완료한다. v0.1.0의 `policy.pubkey`만 있는 정책은 v0.2.0 운영 활성화에서 거부된다. 설치 예시는 다음과 같다. 기존 `/etc/argos/argos.toml`은 덮어쓰지 않는다.

```bash
sudo install -m 0755 bin/argos bin/argos-agent bin/argos-central /usr/bin/
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
