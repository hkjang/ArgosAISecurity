# Argos AI Security

AI 기반 Linux 서버 보안 플랫폼 — 랜섬웨어·이상 행위·권한 상승·파일 변조를 실시간 탐지·차단·복구.

전체 제품 요건은 [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md), 구조 설명은 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 참고.

## 현재 상태: MVP Phase 1 스캐폴딩

| 구성 요소 | 크레이트 | 상태 |
| --- | --- | --- |
| Agent Core (데몬, 파이프라인) | `argos-agent` | 골격 구현 |
| 파일 이벤트 감시 | `argos-sensor` | notify 기반 구현 (fanotify/eBPF는 Phase 3) |
| 행위 기반 랜섬웨어 탐지 | `argos-detect` | 슬라이딩 윈도우 점수 + 엔트로피 구현 |
| 위험 프로세스 차단 | `argos-response` | Linux SIGKILL/SIGSTOP 구현 (cfg-gated) |
| 로컬 로그 저장 | `argos-storage` | SQLite(WAL) 구현 |
| CLI | `argos-cli` | status/events/threats/scan/doctor 구현 |

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
```

## 개발 환경 참고

- 워크스페이스는 **Windows/macOS에서도 컴파일·실행**된다 (notify 센서가 크로스 플랫폼).
  Linux 전용 기능(프로세스 차단)은 `cfg(target_os = "linux")`로 분리되어 있고,
  비 Linux에서는 DryRunResponder가 로그만 남긴다.
- 운영 배포는 Linux 전용: systemd 유닛은 [packaging/argos-agent.service](packaging/argos-agent.service).

## 랜섬웨어 탐지 동작 (Phase 1)

1. 센서가 감시 경로의 생성/수정/삭제/이름 변경/권한 변경 이벤트 수집
2. 수정 이벤트는 파일 앞 64KB의 Shannon 엔트로피 계산 (암호화 데이터 ≈ 7.2+)
3. 슬라이딩 윈도우(기본 10초)에서 점수 산정:
   - 대량 변경 (최대 40점) + 고엔트로피 쓰기 비율 (최대 35점) + 이름 변경·삭제 비율 (최대 25점)
4. 점수 ≥ 40 → 탐지 기록, 점수 ≥ 80 + `auto_block=true` → 프로세스 차단

## 알려진 Phase 1 한계

- notify 센서는 **pid를 제공하지 않아** 호스트 단위 탐지만 가능 (자동 차단은 pid 식별 전까지 비활성).
  → Phase 3에서 fanotify(FAN_REPORT_FID)/eBPF로 교체하면 프로세스 단위 탐지·차단이 된다.
- 백업·복구, 중앙관리, AI 분석은 Phase 2+ (요건서 16장 MVP 우선순위 참조).
