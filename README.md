<p align="center">
  <img src="docs/images/logo.svg" alt="Argos AI Security Logo" width="160" height="160" />
</p>

<h1 align="center">Argos AI Security</h1>

<p align="center">
  <strong>차단과 복구를 검증할 수 있는 Linux 보안 플랫폼</strong><br />
  행위 탐지 · 정상 복구 지점 · 정책 신뢰 · 근거 기반 AI 조사
</p>

<p align="center">
  전체 제품 요건은 <a href="docs/REQUIREMENTS.md">docs/REQUIREMENTS.md</a>, 구조 설명은 <a href="docs/ARCHITECTURE.md">docs/ARCHITECTURE.md</a> 참고.
</p>

<hr />

## 현재 릴리즈: v0.2.0

[v0.2.0 릴리즈](https://github.com/hkjang/ArgosAISecurity/releases/tag/v0.2.0) · [Linux 바이너리 설치](docs/INSTALL_BINARY.md) · [변경 및 업그레이드 안내](docs/releases/v0.2.0.md)

2026-09-27 기준, 정책 재사용 방지·다중 시간 구간 탐지·Linux 설정 의미 감시·사건별 복구 지점 보존·증거 패키지를 제공합니다. 자동 차단은 기본 비활성이며 다중 시간 구간과 내용 표본 분석은 선택 활성화합니다. 배포 바이너리는 Linux x86_64·glibc 2.39 이상용입니다.

워크스페이스 테스트 **144개**, 배포용 바이너리의 보안 시나리오 **8개**와 탐지·복구·인증 시험을 통과했습니다. 이는 운영 탐지율·성능 인증이 아니며 [검증 기록](docs/PLATFORM_VALIDATION.md)에 시험 범위를 구분했습니다.

| 구성 요소 | 크레이트 | 상태 |
| --- | --- | --- |
| Agent Core (데몬, 파이프라인) | `argos-agent` | 탐지·대응, 상태 보고, 별도 백업·사건 보존·전송 작업자 |
| 파일 이벤트 감시 | `argos-sensor` | notify(기본) + fanotify(Linux, pid 제공) |
| 프로세스 감시 | `argos-sensor` | Linux /proc 폴링, 같은 PID 실행 이미지·자격 정보 변화와 부모 신원 |
| 행위 기반 랜섬웨어 탐지 | `argos-detect` | 센서별 점수·미끼 파일, 선택적 다중 시간 구간·내용 표본 |
| Linux 설정 의미 감시 | `argos-agent` | 지정한 SSH 키·sudoers·cron·systemd 파일 변화 |
| 위험 프로세스 차단 | `argos-response` | PID·시작 시각·부팅 ID 확인, pidfd 종료 및 결과 기록 |
| 네트워크 격리 | `argos-response` | 명시적 관리 연결 허용, IPv4/IPv6 INPUT·OUTPUT·FORWARD 제한 |
| 로컬 근거 저장 | `argos-storage` | SQLite(WAL), 전송 outbox·사건 보존 대기열 |
| 백업·복구 | `argos-recovery` | 정상본 판정·미리보기·복구 시험, 사건별 보존과 승인 해제 |
| 정책 신뢰·재생 | `argos-policy` | Ed25519, 버전·기간·대상·키 ID, 감사 기록·승인 롤백·과거 이벤트 비교 |
| AI Threat Summary / Copilot | `argos-brain` | Anthropic/Ollama, 기간·PID별 근거 및 조회 누락 표시 |
| 중앙관리 서버 + 대시보드 | `argos-central` | 인증된 등록·수집·조회, 생존 신호·전달 중복 제거 |
| CLI | `argos-cli` | 운영 조회·복구·정책·조사, 조회형 MCP, HTML 보고서·증거 패키지 |

## 빌드 및 실행

```bash
# 빌드 (Rust 1.86+, 릴리즈 검증: 1.93.1)
cargo build --workspace --locked

# 테스트
cargo test --workspace --locked

# 에이전트 실행 (예제 설정의 ./watched 감시)
cp config/argos.example.toml argos.toml
mkdir -p watched argos-data
cargo run -p argos-agent

# 다른 터미널에서 CLI
cargo run -p argos-cli -- status
cargo run -p argos-cli -- events -n 50
cargo run -p argos-cli -- threats
cargo run -p argos-cli -- scan ./watched
cargo run -p argos-cli -- doctor

# 파일 복구 (백업본에서)
cargo run -p argos-cli -- restore ./watched/important.docx --list   # 버전 확인
# 아래 복구는 검토 후 --mark-good으로 지정한 정상본이 있을 때 실행 (하단 절차 참고)
cargo run -p argos-cli -- restore ./watched/important.docx          # 최신 정상 판정 버전 복구
cargo run -p argos-cli -- restore ./watched/important.docx --before-ms 1760000000000

# AI 사고 분석 / 자연어 질의 (Anthropic 예; Ollama는 아래 안내 참고)
export ANTHROPIC_API_KEY='<API 키>'
export ARGOS_AI_MODEL='<사용할 모델 ID>'
cargo run -p argos-cli -- explain 1                      # ID는 `argos threats`에서 확인
cargo run -p argos-cli -- ask "지난 1시간 동안 위험한 활동 있었어?"

# 프로세스 실행 이력 (Linux)
cargo run -p argos-cli -- processes -n 20

# 정책 서명·사전 확인 (정책 메타데이터·신뢰 키 설정은 정책 안내 참고)
umask 077
cargo run -p argos-cli -- policy gen-key > keys.txt      # 서명키/검증키 생성
# keys.txt의 서명키 아래 64자리 hex 값만 signing.key에 저장하고 policy.toml 작성 후:
cargo run -p argos-cli -- policy sign policy.toml --key-file signing.key
cargo run -p argos-cli -- policy verify                  # 읽기 전용 사전 확인
# argos.toml [policy] 설정 후 에이전트를 재시작해야 운영 활성화
cargo run -p argos-cli -- policy status                  # 수락·거부 감사 기록
cargo run -p argos-cli -- policy show                    # 마지막 수락 정책

# 네트워크 격리 (Linux, root)
cargo run -p argos-cli -- isolate --allow in:192.0.2.20:22 --allow out:10.0.0.5:8420 --dry-run
sudo ./target/debug/argos isolate --allow in:192.0.2.20:22 --allow out:10.0.0.5:8420
sudo ./target/debug/argos isolate --release

# 중앙관리 서버 + 대시보드
export ARGOS_CENTRAL_TOKEN='<관리자 조회 토큰>'
cargo run -p argos-central -- --listen 0.0.0.0:8420 --agent-tokens /etc/argos/agent-tokens.json
# ARGOS_CENTRAL_TOKEN에는 조회용 관리자 토큰, agent-tokens.json에는 {"server-a":"개별토큰"}
# 로컬 개발: cargo run -p argos-central -- --development --listen 127.0.0.1:8420
#  → http://localhost:8420/ 에서 대시보드 (토큰 입력 후 현황 확인)
curl http://localhost:8420/api/v1/agents -H "Authorization: Bearer <관리자토큰>"
```

Windows 개발 환경에서 Rust 없이 빌드하려면 Docker 사용:

```powershell
docker run --rm -v ${PWD}:/src -v argos-cargo-cache:/usr/local/cargo/registry -v argos-target-cache:/src/target -w /src rust:1.93.1 cargo test --workspace
```

## 개발 환경 참고

- notify 센서와 Linux 조건부 컴파일 경계를 두어 Windows/macOS 개발을 고려한다.
  이번 릴리즈의 실행 검증과 첨부 바이너리는 Linux x86_64 기준이다.
- 운영 배포는 Linux 전용: systemd 유닛은 [packaging/argos-agent.service](packaging/argos-agent.service).

## 랜섬웨어 탐지·대응 동작

1. 센서가 감시 경로의 파일 이벤트 수집 — `notify`(기본) 또는 `fanotify`(Linux, 원인 pid 포함)
2. 기본값은 파일 앞 64 KiB 엔트로피 관찰. `detection.content_sampling.enabled=true`이면 같은 총 예산을 앞·중간·끝에 나누고 위치·유형 힌트·이전 관찰 대비 변화를 저장한다. 이전 관찰은 정상본 판정이 아니다.
3. 알림 억제와 독립적으로 매 이벤트의 위험도와 자동 대응 정책을 평가 (DB·백업보다 먼저)
4. 슬라이딩 윈도우(기본 10초)에서 점수 산정:
   - notify: 대량 변경 40 + 서로 다른 파일의 고엔트로피 비율 35 + 이름 변경·삭제 비율 25
   - fanotify: 대량 변경 40 + 서로 다른 파일의 고엔트로피 비율 60 (수정 이벤트만 수집)
   - 행위 점수는 최소 변경 파일 수·제외 경로 조건을 적용한다. 미끼 파일 변조는 별도 95점 신호다. 도달 불가능한 임계치는 시작 시 경고.
5. 기본 탐지 점수 ≥ 40 → 탐지 기록(+ 중앙 서버 보고). 개별 프로세스 대응 점수 ≥ 80이고 `auto_block=true`, 정책 유효성·PID·시작 ticks·부팅 ID 확인을 모두 충족하면 pidfd 종료 및 결과 기록
6. 별도 크기 제한 큐에서 실제 수집 시각으로 백업. baseline·해시 일치만으로 정상본을 판정하지 않는다.
7. 탐지와 사건 보존 요청을 함께 저장하고 별도 작업자가 관련 정상본을 고정. 검토한 버전은 `argos restore <path> --before-ms <공격시각>`으로 해시 검증 복구

`detection.multi_window.enabled=true`로 10/60/600초별 임계치를 적용할 수 있다. 프로세스 인스턴스, 유효 UID+보호 경로, 보호 경로, 수집된 최대 4단계 부모 계보를 각각 평가한다. **계정·경로·계보 집계는 알림만 생성하며 현재 PID 차단 점수로 전환하지 않는다.** 승인 작업은 조정할 규칙 이름을 개별 지정해야 한다. 기본값은 두 기능 모두 비활성이다.

이벤트·그룹·표본 이력은 상한이 있고 누락을 표시한다. 누락된 인스턴스 집계는 자동 차단 근거로 사용하지 않는다. 다중 위치 표본을 활성화하면 압축·이미지 등의 높은 엔트로피만으로 내용 변화 증거를 추가하지 않는다. 기본 앞부분 엔트로피 평가는 압축 파일에도 높은 점수를 줄 수 있다. 구체적인 설정과 합성 검증 범위는 [탐지 기능](docs/FEATURE_DETECTION.md), [설정 예시](config/argos.example.toml)를 참고한다. 샘플 밖 부분 암호화와 실제 운영 오탐률은 별도 검증 대상이다.

## 알려진 한계 (로드맵)

- `notify` 센서는 원인 PID가 없어 파일·경로 집계에 사용하며 개별 프로세스를 차단할 수 없다. `sensor = "fanotify"`(Linux, root)로 전환하면
  수정 이벤트에 원인 pid가 포함된다. 실제 차단에는 프로세스 신원 확인과 유효한 대응 정책도 필요하다.
  fanotify는 수정 계열 이벤트만 수집한다. 프로세스 감시는 /proc 폴링이며, eBPF 실행·네트워크 이벤트 수집은 후속 범위다.
- 중앙 서버 운영 모드는 관리자 조회 토큰과 에이전트별 수집 토큰을 필수로 요구한다. HTTPS는 별도 TLS 프록시에서 구성하며 mTLS 인증서는 후속 단계다.
- 서명 정책의 버전·기간·대상 검증은 구현되어 있다. 중앙 자동 정책 배포, 외부 승인자 인증, 실행 파일 신뢰·서비스 영향 분석은 [후속 개발 계획](docs/ROADMAP.md)을 참고한다.

## 안전한 복구와 정책 사전 검증

```bash
argos restore /data/contract.docx --list
argos restore /data/contract.docx --version 1 --preview /tmp/contract.preview.docx
argos restore /data/contract.docx --mark-good 1 --note "업무 원본 대조 완료"
argos restore /data/contract.docx --recommend --before-ms 1760000000000
argos recovery-status --test /data/contract.docx
argos policy simulate --candidate candidate.toml --from-ms 1760000000000 --to-ms 1760086400000
```

정책 재생은 DB를 읽기 전용으로 열고 실제 정책 적용이나 차단을 하지 않는다.
알림 수·예상 차단 PID·차이·근거 ID·조회 누락을 함께 출력한다. 저장 데이터가 누락되거나 PID가 재사용된 경우 한계를 표시한다.
변경 정책은 관찰 모드에서 검토하고 지정한 소수 서버에 서명 정책을 적용한 뒤 확대한다.

## 근거 기반 AI 조사

`[ai]`에서 provider(`anthropic`/`ollama`), endpoint, model을 지정한다. 모델은 설치/사용 가능한 ID를 명시한다.
Ollama 기본 주소는 `http://127.0.0.1:11434/api/chat`이며 외부 AI 키를 자동으로 전달하지 않는다.

```bash
argos evidence --from-ms 1760000000000 --to-ms 1760086400000 --pid 1234
argos ask "지난 24시간 위험한 활동이 있었어?"
argos ask --from-ms 1760000000000 --to-ms 1760086400000 --pid 1234 "이 프로세스의 근거는?"
argos mcp # 설정한 단일 호스트 DB를 조회하는 stdio MCP 서버
```

기간별 전체 건수와 조회 상한으로 생긴 누락을 표시한다. 근거 ID는 파일·탐지·프로세스 종류와 함께 인용한다.
캘린더 날짜처럼 자동 해석하지 않는 기간은 epoch ms로 지정한다. AI가 보는 데이터 범위는 현재 설정의 로컬 DB다.

검증 범위와 재현 명령은 [플랫폼 검증 기록](docs/PLATFORM_VALIDATION.md)에 정리했다.
릴리즈 실행 파일의 요구사항과 서비스 설치 절차는 [Linux 바이너리 설치](docs/INSTALL_BINARY.md)를 참고한다.
`argos incident ID --html NEW_FILE`은 시간순 조사 화면을, `argos recovery-status --html NEW_FILE`은 복구 준비도 화면을 생성한다.
탐지와 실제 대응 결과는 별도 저장하며 `evidence`와 MCP의 `response_results`에서 확인할 수 있다.


## 정책 신뢰와 Linux 조사 확장

서명 정책 활성화는 버전·기간·호스트/그룹·키 ID를 검증하고 수락 원문과 감사 기록을 원자적으로 저장한다. 구버전 재적용을 거부하며 롤백도 새 높은 버전과 승인 근거가 필요하다. 기존 `pubkey` 설정에서 운영 활성화로 전환하는 절차는 [정책 신뢰](docs/FEATURE_POLICY.md)를 참고한다.

- [Linux 설정 의미·UID/GID·capability 변화](docs/FEATURE_LINUX_ANALYSIS.md)
- [사건별 복구 지점 보존과 승인 해제](docs/FEATURE_RECOVERY.md)
- [마스킹·해시를 포함한 사고 증거 패키지](docs/FEATURE_EVIDENCE_PACKAGE.md)
- 실제 임시 파일·프로세스를 사용하는 시나리오: `python3 scripts/security-scenarios.py --bin-dir target/debug --report /tmp/argos-scenarios.json`

다중 시간 구간·내용 표본은 예제 설정에서 선택 활성화한다. 자동 차단 기본값은 비활성이다. 운영 탐지율·처리량이나 외부 승인자 인증은 별도 검증·연동 범위다.

## 문서 안내

| 목적 | 문서 |
| --- | --- |
| 처음 설치·업그레이드 | [바이너리 설치](docs/INSTALL_BINARY.md), [v0.2.0 변경 사항](docs/releases/v0.2.0.md) |
| 일상 운영·사고 조사 | [운영자](docs/ROLE_OPERATOR.md), [분석가](docs/ROLE_ANALYST.md), [관리자](docs/ROLE_ADMINISTRATOR.md) |
| 명령·서비스 설정 | [CLI](docs/SERVICE_CLI.md), [에이전트](docs/SERVICE_AGENT.md), [중앙 서버](docs/SERVICE_CENTRAL.md) |
| 구현과 후속 요구 | [아키텍처](docs/ARCHITECTURE.md), [코드 분석](docs/SOURCE_CODE_ANALYSIS.md), [요건서](docs/REQUIREMENTS.md), [로드맵](docs/ROADMAP.md) |
| 검증 및 재현 | [플랫폼 검증 기록](docs/PLATFORM_VALIDATION.md) |
