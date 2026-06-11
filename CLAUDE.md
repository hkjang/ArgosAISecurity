# Argos AI Security

AI 기반 Linux 서버 보안 플랫폼 (랜섬웨어 탐지·차단·복구). Rust 워크스페이스.
제품 요건: docs/REQUIREMENTS.md (단일 진실 공급원 — 기능 추가 전 반드시 확인).

## 빌드/테스트

```bash
cargo build --workspace
cargo test --workspace
cargo run -p argos-agent              # 데몬 (argos.toml 또는 기본값)
cargo run -p argos-cli -- status      # CLI (바이너리 이름: argos)
```

개발 머신이 Windows여도 전체 워크스페이스가 컴파일된다.
Linux 전용 코드는 `#[cfg(target_os = "linux")]`로 격리할 것 — cfg 없이 libc 시그널/fanotify 코드를 넣지 말 것.

## 구조

- `crates/argos-common` — 이벤트·탐지·설정 타입. 다른 모든 크레이트가 의존. 여기에 로직 넣지 말 것.
- `crates/argos-sensor` — 파일 이벤트 수집. 현재 notify 기반(pid 없음, pid=0). 공개 API `spawn_fs_sensor`는 fanotify/eBPF 교체 후에도 유지.
- `crates/argos-detect` — 행위 점수(BehaviorScorer) + 엔트로피. 순수 로직, I/O는 file_entropy만.
- `crates/argos-storage` — SQLite(WAL). 에이전트가 쓰고 CLI는 read-only로 연다.
- `crates/argos-response` — 대응 실행. pid 0 차단은 반드시 거부 (kill(0)은 프로세스 그룹 전체 시그널).
- `crates/argos-agent` — 데몬 바이너리. 파이프라인: sensor → (entropy) → store → detect → respond.
- `crates/argos-cli` — `argos` 바이너리. DB read-only 조회만, 에이전트 상태 변경 금지.

## 컨벤션

- 의존성 버전은 루트 Cargo.toml `[workspace.dependencies]`에서만 관리.
- 점수 체계: 0~100. Severity 경계: 40 Medium / 65 High / 85 Critical. 변경 시 scorer.rs와 README 동기화.
- 차단(자동 대응)은 기본 비활성(`auto_block=false`)이 정책 — 오탐으로 인한 업무 중단이 1순위 리스크 (요건서 18장).
- 주석·로그·CLI 출력은 한국어.
