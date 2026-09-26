<p align="center">
  <img src="docs/images/logo.svg" alt="Argos AI Security Logo" width="160" height="160" />
</p>

<h1 align="center">Argos AI Security</h1>

<p align="center">
  <strong>AI 기반 Linux 서버 보안 플랫폼</strong><br />
  랜섬웨어 · 이상 행위 · 권한 상승 · 파일 변조 실시간 탐지 · 차단 · 복구
</p>

<p align="center">
  전체 제품 요건은 <a href="docs/REQUIREMENTS.md">docs/REQUIREMENTS.md</a>, 구조 설명은 <a href="docs/ARCHITECTURE.md">docs/ARCHITECTURE.md</a> 참고.
</p>

<hr />

## 현재 상태: MVP Phase 1 + 2 + 3 핵심

| 구성 요소 | 크레이트 | 상태 |
| --- | --- | --- |
| Agent Core (데몬, 파이프라인) | `argos-agent` | 구현 |
| 파일 이벤트 감시 | `argos-sensor` | notify(기본) + fanotify(Linux, pid 제공) |
| 프로세스 감시 | `argos-sensor` | /proc 폴링 (Linux) → eBPF는 후속 |
| 행위 기반 랜섬웨어 탐지 | `argos-detect` | 슬라이딩 윈도우 점수 + 엔트로피 |
| 위험 프로세스 차단 | `argos-response` | Linux SIGKILL/SIGSTOP (기본 dry-run) |
| 네트워크 격리 | `argos-response` | iptables 기반 (`argos isolate`) |
| 로컬 로그 저장 | `argos-storage` | SQLite(WAL) |
| 백업·복구 | `argos-recovery` | 내용 주소 저장 + 해시 검증 복구 |
| 정책 서명·검증 | `argos-policy` | Ed25519 — 서명된 정책만 적용 |
| AI Threat Summary / Copilot | `argos-brain` | Claude API (`argos explain` / `argos ask`) |
| 중앙관리 서버 + 대시보드 | `argos-central` | REST API + HTML 대시보드 |
| CLI | `argos-cli` | status/events/threats/processes/scan/doctor/restore/explain/ask/isolate/policy |

## 빌드 및 실행

```bash
# 빌드 (Rust 1.86+, 릴리즈 검증: 1.93.1)
cargo build --workspace

# 테스트
cargo test --workspace

# 에이전트 실행 (argos.toml 없으면 기본값: ./watched 감시)
cp config/argos.example.toml argos.toml
cargo run -p argos-agent

# 다른 터미널에서 CLI
cargo run -p argos-cli -- status
cargo run -p argos-cli -- events -n 50
cargo run -p argos-cli -- threats
cargo run -p argos-cli -- scan ./watched
cargo run -p argos-cli -- doctor

# 파일 복구 (백업본에서)
cargo run -p argos-cli -- restore ./watched/important.docx --list   # 버전 확인
cargo run -p argos-cli -- restore ./watched/important.docx          # 최신 정상 판정 버전 복구
cargo run -p argos-cli -- restore ./watched/important.docx --before-ms 1760000000000

# AI 사고 분석 / 자연어 질의 (ANTHROPIC_API_KEY 필요)
export ANTHROPIC_API_KEY=sk-ant-...
cargo run -p argos-cli -- explain 1                      # ID는 `argos threats`에서 확인
cargo run -p argos-cli -- ask "지난 1시간 동안 위험한 활동 있었어?"

# 프로세스 실행 이력 (Linux)
cargo run -p argos-cli -- processes -n 20

# 정책 서명·배포 (요건서 11장 — 서명된 정책만 적용)
cargo run -p argos-cli -- policy gen-key > keys.txt      # 서명키/검증키 생성
# policy.toml 작성 후:
cargo run -p argos-cli -- policy sign policy.toml --key-file signing.key
cargo run -p argos-cli -- policy verify                  # argos.toml [policy] 설정 사용
cargo run -p argos-cli -- policy show

# 네트워크 격리 (Linux, root)
cargo run -p argos-cli -- isolate --allow in:192.0.2.20:22 --allow out:10.0.0.5:8420 --dry-run
sudo cargo run -p argos-cli -- isolate --allow in:192.0.2.20:22 --allow out:10.0.0.5:8420
sudo cargo run -p argos-cli -- isolate --release

# 중앙관리 서버 + 대시보드
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

- 워크스페이스는 **Windows/macOS에서도 컴파일·실행**된다 (notify 센서가 크로스 플랫폼).
  Linux 전용 기능(fanotify, 프로세스 차단)은 `cfg(target_os = "linux")`로 분리.
- 운영 배포는 Linux 전용: systemd 유닛은 [packaging/argos-agent.service](packaging/argos-agent.service).

## 랜섬웨어 탐지·대응 동작

1. 센서가 감시 경로의 파일 이벤트 수집 — `notify`(기본) 또는 `fanotify`(Linux, 원인 pid 포함)
2. 수정 이벤트는 파일 앞 64KB의 Shannon 엔트로피 계산 (암호화 데이터 ≈ 7.2+)
3. 알림 억제와 독립적으로 매 이벤트의 위험도와 자동 대응 정책을 평가 (DB·백업보다 먼저)
4. 슬라이딩 윈도우(기본 10초)에서 점수 산정:
   - notify: 대량 변경 40 + 서로 다른 파일의 고엔트로피 비율 35 + 이름 변경·삭제 비율 25
   - fanotify: 대량 변경 40 + 서로 다른 파일의 고엔트로피 비율 60 (수정 이벤트만 수집)
   - 최소 변경 파일 수·제외 경로 조건을 만족해야 대응 후보가 된다. 도달 불가능한 임계치는 시작 시 경고.
5. 점수 ≥ 40 → 탐지 기록(+ 중앙 서버 보고), 점수 ≥ 80 + `auto_block=true` + pid 식별 → 프로세스 차단
6. 별도 크기 제한 큐에서 실제 수집 시각으로 백업. baseline·해시 일치만으로 정상본을 판정하지 않는다.
7. 검토한 버전을 정상본으로 지정한 뒤 `argos restore <path> --before-ms <공격시각>`으로 해시 검증 복구

## 알려진 한계 (로드맵)

- `notify` 센서는 pid가 없어 호스트 단위 탐지만 가능. `sensor = "fanotify"`(Linux, root)로 전환하면
  수정 이벤트에 원인 pid가 포함되어 프로세스 단위 차단이 동작한다.
  fanotify는 수정 계열 이벤트만 수집하며, 생성/삭제/이름변경 + 프로세스·네트워크 감시는 Phase 3 eBPF에서 확장.
- 중앙 서버 운영 모드는 관리자 조회 토큰과 에이전트별 수집 토큰을 필수로 요구한다. HTTPS는 별도 TLS 프록시에서 구성하며 mTLS 인증서는 후속 단계다.
- 서명 정책 수동 적용·중앙 대시보드·근거 기반 AI 질의는 구현되어 있다. 중앙 자동 정책 배포와 추가 탐지·정책 신뢰성 강화는 [후속 개발 계획](docs/ROADMAP.md)을 참고한다.

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
