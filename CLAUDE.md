# Argos AI Security

AI 기반 Linux 서버 보안 플랫폼 (랜섬웨어 탐지·차단·복구). Rust 워크스페이스.
현재 릴리즈: v0.7.0. 제품 목표와 미구현 요구는 docs/REQUIREMENTS.md, 실제 구현 경계는 docs/ARCHITECTURE.md와 docs/ROADMAP.md, 실행 검증 범위는 docs/PLATFORM_VALIDATION.md를 확인한다. 기능 추가 전 요건서와 현재 코드를 함께 확인한다.

## 빌드/테스트

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo run -p argos-agent              # 데몬 (argos.toml 또는 기본값)
cargo run -p argos-cli -- status      # CLI (바이너리 이름: argos)
```

notify 기반 개발과 비 Linux 조건부 컴파일 경계를 유지한다. v0.7.0 배포·실행 검증은 Linux x86_64 기준이다.
Linux 전용 코드는 `#[cfg(target_os = "linux")]`로 격리할 것 — cfg 없이 libc 시그널/fanotify 코드를 넣지 말 것.

실제 CLI·에이전트 검증은 `scripts/smoke-test.sh`, `scripts/platform-smoke.py`, `scripts/security-scenarios.py`를 사용한다. 사용자/네트워크 네임스페이스에서 격리를 검증하는 `scripts/test-isolation-netns.py`도 있다. 운영 호스트의 방화벽을 직접 바꾸는 시험으로 대체하지 않는다. 각 실행 파일 경로 지정법과 검증 한계는 검증 기록을 참고한다.

## 구조

- `crates/argos-common` — 이벤트·탐지·설정 타입. 다른 모든 크레이트가 의존. 여기에 로직 넣지 말 것.
- `crates/argos-sensor` — 파일 이벤트 수집. 공개 API `spawn_sensor(kind, paths, tx)`. 백엔드: notify(기본, pid=0) / fanotify(Linux, root, pid 제공 — src/fanotify.rs). procmon.rs는 /proc 폴링으로 프로세스 시작 신원·실행 이미지·UID/GID·capability 변화와 파일 이벤트의 부모 계보를 수집한다. 폴링 사이 변화는 누락될 수 있다.
- `crates/argos-detect` — 센서별 행위 점수·승인 작업·미끼 파일, 선택적 다중 시간 구간 집계. 내용 I/O는 file_entropy와 ContentSampler에서 수행하며 표본 예산·이력 상한을 둔다. 계정·경로·계보 집계 알림을 현재 PID의 차단 점수로 전환하지 않는다. 동일 프로세스 인스턴스의 충분한 개별 근거는 차단 평가에 반영한다.
- `crates/argos-storage` — SQLite(WAL) 이벤트·탐지·대응 근거, 전송 outbox·보존 요청 큐. 탐지와 관련 큐 요청은 트랜잭션으로 기록한다. 조회 CLI는 이벤트 DB를 읽기 전용으로 연다.
- `crates/argos-response` — 신원 확인 후 pidfd 대응 실행·결과 확인. pid 0 차단은 반드시 거부 (kill(0)은 프로세스 그룹 전체 시그널). isolate.rs는 IPv4/IPv6의 ARGOS_INPUT·ARGOS_OUTPUT·ARGOS_FORWARD 체인을 관리한다. ARGOS_ISOLATE는 구형 규칙 정리 대상이다. 명령 생성은 OS 무관해 단위 테스트 가능하며 실행만 cfg-gated다.
- `crates/argos-recovery` — 내용 주소(SHA-256) 백업, 정상본 판정·미리보기·복구 시험, 독립 사건 참조·승인 해제. 정상본 및 사건 보존 버전은 정리에서 제외한다. 해시는 정상 내용의 증명이 아니다. 백업 dir는 감시 경로 밖에 둘 것.
- `crates/argos-policy` — 한 번 읽은 동일 바이트의 Ed25519 검증·파싱. 로컬 신뢰 키와 정책 ID·버전·기간·대상을 검사하고 SQLite에 수락 원문·최대 버전·감사를 원자적으로 저장한다. 설정한 정책 검증 실패 시 에이전트 시작을 중단하며 기본 설정으로 우회하지 않는다. verify는 읽기 전용 사전 확인, 활성화는 에이전트 시작 경로다.
- `crates/argos-brain` — Anthropic/Ollama HTTP 호출 (모델·주소·제공자는 [ai] 설정, 키는 환경변수). 프롬프트에 storage의 실제 이벤트만 근거로 제공 — hallucination 방지 원칙.
- `crates/argos-central` — axum 중앙 서버 (등록/수집/조회). 인증: 관리자 조회/개별 에이전트 수집 토큰 분리. mTLS는 후속.
- `crates/argos-agent` — 데몬 바이너리. sensor → 프로세스 맥락·내용 표본 → detect/respond → audit/store → 별도 backup/retention/report 작업자. semantic.rs는 지정한 Linux 설정 파일의 의미 변화를 분석한다. 중앙 보고는 SQLite outbox와 reporter.rs의 전용 std 스레드 (tokio 안에서 reqwest blocking 금지). 실행 중 정책 기간 이탈 시 자동 차단을 중지하고 보호 저하를 표시한다.
- `crates/argos-cli` — `argos` 바이너리. 근거·상태·정책 조회, 정책 재생, AI·조회형 MCP·HTML 보고서·증거 패키지. restore/retention/isolate처럼 명시적으로 요청한 복구·보존·격리 명령은 관련 저장소/파일/방화벽을 변경한다. 정책 show/status는 마지막 수락 상태이며 센서의 실제 가동 성공 증명이 아니다. update는 미구현이다.

## 컨벤션

- 의존성 버전은 루트 Cargo.toml `[workspace.dependencies]`에서만 관리.
- 점수 체계: 0~100. Severity 경계: 40 Medium / 65 High / 85 Critical. 변경 시 scorer.rs와 README 동기화.
- 차단(자동 대응)은 기본 비활성(`auto_block=false`)이 정책 — 오탐으로 인한 업무 중단이 1순위 리스크 (요건서 18장).
- 주석·로그·CLI 출력은 한국어.

## 보호·복구 검증 확장

`argos-vault`는 별도 추가 전용 보관 서버와 서명 수신증명 클라이언트다. 업로드/조회 토큰·고정 공개키를 분리한다. coverage_worker는 수집 경로 공백을 별도 스레드에서 검사한다. 서비스 복구는 SQLite Backup API와 bwrap PostgreSQL 새 클러스터에서만 수행하며 운영 DB 연결 옵션을 제공하지 않는다. 예외 감사는 저장 이벤트 재생이며 실제 적용 원장이 아니다. AI의 구조화 인용 검사는 주장의 의미까지 증명하지 않는다. 각 기능 문서와 추가 시나리오 스크립트를 함께 갱신한다.

보관 전송은 `vault queue enqueue`가 당시 바이트와 목적지/공개키를 고정하며, 명시적인 `drain`이 SQLite 상태를 갱신한다. 선택 설치한 systemd timer가 drain을 예약 실행한다. 완료 수신증명은 별도 archive 테이블로 이동하며 자동 삭제하지 않는다. 활성 항목 수와 총 archive 예약 슬롯 상한을 구별한다. 네트워크 전송 중 전체 flock을 유지하지 않고 토큰/만료 시각이 있는 항목 임대를 사용한다. 서버는 Linux 작성자 잠금·시작 시 용량 재구성·신규 요청 한도를 검사한다. 복구 v2 보고서의 `verify`는 계획/기대값/백업 해시·검사 결과·나이를 대조하지만 무서명 보고서의 출처를 인증하지 않는다. `scripts/durability-scenarios.py`로 실제 CLI 경계를 시험한다.

복구 묶음은 `argos-vault::bundle` 및 서버의 bundle 모듈과 CLI `vault_bundle.rs`로 구현한다. 백업 한 파일(최대 1GiB)을 16MiB 청크로 나누며 원본 에이전트 설정·DB 없이 원격 list/review/fetch/test를 수행한다. bundle enqueue는 manifest·청크·게시 작업을 schema v3 큐에 함께 고정하며 drain이 register/complete를 자동 재개한다. 원격 판정은 최초 unknown이고 관리자 검토만 good/revoked를 추가한다. 내장 계획의 backup_path만 새 파일로 바꾸며 기존 supervise_report의 시간·프로세스·출력 제한을 유지한다. 서버의 서명 완료/검토와 report_authenticated=false인 로컬 시험을 혼동하지 않는다. 사건 3파일 자동 원자 묶음, 로컬 정상본 취소 자동 전파, 시험 실행자 서명은 후속이다. 상세 절차는 docs/FEATURE_RECOVERY_BUNDLE_CLI.md를 따른다.

승인 전 `test --preapproval`는 complete+unknown만 허용하고 성공해도 recommended/operational_restore_authorized=false다. SQLite는 Linux x86_64 GNU+bwrap 전용 격리를 사용하고 불가하면 거부한다. PG는 기존 namespace 경계를 유지한다. 보관 서버의 취소 예약은 한정된 논리 예산·물리 여유 정책이며 ENOSPC를 무조건 해결하지 않는다. 귀속을 검증한 번들 오류만 개별 보류하고 귀속 불명·카탈로그 유실은 전역 보류한다. 사설 TLS CA는 tls_ca_pem에 명시하고 큐 대상에 그 원문 SHA-256을 고정한다.
