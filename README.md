# Argos AI Security

AI 기반 Linux 서버 보안 플랫폼 — 랜섬웨어·이상 행위·권한 상승·파일 변조를 실시간 탐지·차단·복구.

전체 제품 요건은 [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md), 구조 설명은 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 참고.

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
# 빌드 (Rust 1.75+)
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
cargo run -p argos-cli -- restore ./watched/important.docx          # 최신 버전 복구
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
sudo cargo run -p argos-cli -- isolate --allow 10.0.0.5  # 중앙 서버 등은 자동 허용
sudo cargo run -p argos-cli -- isolate --release

# 중앙관리 서버 + 대시보드
cargo run -p argos-central -- --listen 0.0.0.0:8420 --token <공유토큰>
#  → http://localhost:8420/ 에서 대시보드 (토큰 입력 후 현황 확인)
curl http://localhost:8420/api/v1/agents -H "Authorization: Bearer <공유토큰>"
```

Windows 개발 환경에서 Rust 없이 빌드하려면 Docker 사용:

```powershell
docker run --rm -v ${PWD}:/src -v argos-cargo-cache:/usr/local/cargo/registry -v argos-target-cache:/src/target -w /src rust:1.83 cargo test --workspace
```

## 개발 환경 참고

- 워크스페이스는 **Windows/macOS에서도 컴파일·실행**된다 (notify 센서가 크로스 플랫폼).
  Linux 전용 기능(fanotify, 프로세스 차단)은 `cfg(target_os = "linux")`로 분리.
- 운영 배포는 Linux 전용: systemd 유닛은 [packaging/argos-agent.service](packaging/argos-agent.service).

## 랜섬웨어 탐지·대응 동작

1. 센서가 감시 경로의 파일 이벤트 수집 — `notify`(기본) 또는 `fanotify`(Linux, 원인 pid 포함)
2. 수정 이벤트는 파일 앞 64KB의 Shannon 엔트로피 계산 (암호화 데이터 ≈ 7.2+)
3. 변경 내용을 내용 주소(SHA-256) 백업 저장소에 버전으로 보관 → 공격 전 버전이 복구 지점
4. 슬라이딩 윈도우(기본 10초)에서 점수 산정:
   - 대량 변경(최대 40점) + 고엔트로피 쓰기 비율(최대 35점) + 이름 변경·삭제 비율(최대 25점)
5. 점수 ≥ 40 → 탐지 기록(+ 중앙 서버 보고), 점수 ≥ 80 + `auto_block=true` + pid 식별 → 프로세스 차단
6. `argos restore <path> --before-ms <공격시각>`으로 해시 검증 복구

## 알려진 한계 (로드맵)

- `notify` 센서는 pid가 없어 호스트 단위 탐지만 가능. `sensor = "fanotify"`(Linux, root)로 전환하면
  수정 이벤트에 원인 pid가 포함되어 프로세스 단위 차단이 동작한다.
  fanotify는 수정 계열 이벤트만 수집하며, 생성/삭제/이름변경 + 프로세스·네트워크 감시는 Phase 3 eBPF에서 확장.
- 중앙 서버 인증은 공유 토큰(Bearer) 1단계 — mTLS 인증서 기반은 Phase 4 (요건서 11장).
- 정책 배포, 대시보드, AI Copilot은 Phase 3+ (요건서 16장 MVP 우선순위 참조).
