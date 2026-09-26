# 검증 가능한 보안 플랫폼: 구현과 검증 기록

기준: `v0.3.0`과 이전 릴리즈 검증 기록. v0.3.0 검증일: 2026-09-27. v0.2.0 릴리즈 검증일: 2026-09-27, v0.1.0 검증일: 2026-09-26. 자동 차단 기본값은 계속 비활성이다.

## 구현 범위

| 영역 | 구현 |
| --- | --- |
| 자동 차단 | fanotify/notify별 점수, 도달 불가 경고, 매 이벤트 대응 판단, 알림 억제 분리, PID·시작 ticks·부팅 ID 확인, pidfd 신호와 종료 확인, 결과 감사 |
| 확장 탐지 | 선택적 10/60/600초 인스턴스·계정·경로·계보 집계, 총 읽기 예산 안의 앞·중간·끝 표본, 근거 상한·누락 표시 |
| Linux 분석 | 지정한 SSH 키·sudoers·cron·systemd 파일의 의미·순서·권한 변화, /proc 실행 이미지·UID/GID·capability 및 부모 신원 근거 |
| 정상 작업 | 시간·경로·실행 파일·유효 UID·완전한 프로세스 신원이 모두 맞는 승인 작업만 해당 규칙 조정. 미끼 파일 변경은 별도 95점 신호 |
| 안전한 복구 | 새 baseline과 정상 판정 이력이 없는 백업은 미검토로 시작. 기존 v0.1.0 정상 판정은 유지. 정상 판정·취소·공격 이전 추천·원본 유지 미리보기·복구 시험, UID/GID 보존과 특수 권한 제거 |
| 사건 보존 | 정상본 판정과 독립된 다중 사건 참조·승인 해제·감사 이력, 정리 제외, 별도 영속 요청 큐와 작업자 |
| 정책 사전 검증 | 저장된 엔트로피/프로세스 맥락을 재생, 기존/후보 차이·예상 대상·근거 ID·누락 표시, 신원별 대상 비교. 실제 정책/프로세스 변경 없음 |
| 정책 신뢰 | 동일 바이트 검증·파싱, 로컬 신뢰 키와 버전·기간·대상 검사, 수락 상태·최대 버전·감사 원자적 저장, 새 버전 승인 롤백 |
| 운영 신뢰성 | 감시/백업 제한 큐와 누락 지표, 별도 백업 작업자, 논리 파일 바이트 기준 처리 예산, 생존 신호, 디스크 outbox, 재전송과 전달 ID 중복 제거 |
| 인증/격리 | 운영 관리자/개별 에이전트 토큰 필수, loopback 개발 모드, 비밀값 마스킹, 명시적 관리 IP·방향·포트만 허용, IPv4/IPv6 INPUT/OUTPUT/FORWARD 제한 |
| 조사 | 기간·PID 기반 근거 조회, 조회 누락·근거 ID, Anthropic/Ollama 설정, 조회형 MCP, 시간순 재생 HTML, 복구 준비도 HTML |
| 증거 패키지 | 기본 문자열 마스킹, 사건 근거·대응 이력·수락 정책 스냅샷, SHA-256 manifest 및 파일 목록 검증 |

## v0.3.0 보호·복구·근거 검증

- `cargo test --workspace --offline --locked`: **188개 통과**, PostgreSQL 도구가 필요한 선택 시험 1개는 별도 실행했다. 해당 PostgreSQL 18.6 시험도 통과했다. 기본 회귀 시험은 외부 모델·운영 DB를 사용하지 않는다.
- `cargo build --release --workspace --offline --locked` 성공. 최종 최적화 바이너리의 기존 스모크·보안 및 신규 보호/보관/DB 시나리오를 실행했다. `argos --version`은 `argos 0.3.0`이다. 네 실행 파일의 최대 요구 glibc는 2.39다.
- `coverage` 코어/작업자: 등록 경로 일치·루트/별칭 교체·접근·마운트 범위/중첩·심볼릭 링크·검사 예산·오래된 결과·작업자 종료를 검사했다. 실제 notify 시험 파일은 새 DB 이벤트와 경로·내용·정리 결과를 대조했다.
- 예외 감사: 같은 저장 스냅샷, 신원·기간·경로·실행 파일·유효 UID, 겹치는 예외 우선순위, 규칙별 매칭·집계·미끼 파일 유지, 표본/조회 누락을 검사했다. 합성 승인 이벤트 2건의 예외 제거 재생에서 알림 0→1과 해당 신원의 예상 차단 증가를 확인했다. 운영 오탐률 측정은 아니다.
- AI: 두 제공자의 모의 HTTP 응답과 실제 Ollama 경로의 `ask` CLI로 정상 인용 수락, 없는 ID·종류·출처·시각 불일치, 범위 밖 입력, JSON/크기 상한, 누락 표시를 확인했다. 실제 외부 모델 호출·한국어 분석 품질 평가는 수행하지 않았다.
- 보관: 실제 loopback HTTP에서 역할/에이전트 분리·DELETE/PUT 거부, 고정 키·본문/메타데이터 변조·redirect 거부, 재전송 및 서버 재시작 후 동일 수신증명, 원본 삭제 후 검증 복원을 검사했다. 별도 호스트의 TLS 배포·디스크 관리자 공격·WORM 검증은 아니다.
- DB 복구: SQLite Backup API와 PostgreSQL 18.6 custom 아카이브를 별도 작업 경로에 복원했다. 스키마·최소 행 수·제약·쓰기/읽기/롤백, 원본 불변, 기존 출력·SQL 식별자·실행 중 SQLite sidecar 거부, 비밀값 비노출, 타임아웃 및 서버 정리를 검사했다. PostgreSQL 도구는 호스트 설치를 변경하지 않고 `/tmp`에 패키지를 추출해 사용했다.

### CLI 통합 시나리오

| 스크립트 | 실행 범위 |
| --- | --- |
| `smoke-test.sh`, `platform-smoke.py` | 실제 파일 변경·탐지·정상본 복구, 중앙 인증/수집/중복 제거·생존 신호, MCP·HTML |
| `security-scenarios.py` | 기존 Linux 의미·프로세스·보존·정책 신뢰 등 8개 시나리오 |
| `assurance-scenarios.py` | 실제 notify 전달·루트 교체·수집 중단, 예외 제거 재생, AI 인용 수락/거부 5개 |
| `vault-scenarios.py` | 실제 CLI의 감사 파일·정상본·증거 패키지 업로드/원본 삭제/복원, 변조 거부 4개 |
| `service-recovery-scenarios.py --pg-root ROOT` | SQLite/PostgreSQL 네이티브 복구·실패·타임아웃 등 15개 검사 |

```bash
cargo test --workspace --offline --locked
cargo build --release --workspace --offline --locked
python3 scripts/assurance-scenarios.py --bin-dir target/release --report /tmp/argos-assurance.json
python3 scripts/vault-scenarios.py --bin-dir target/release --report /tmp/argos-vault.json
python3 scripts/service-recovery-scenarios.py --bin-dir target/release --pg-root /path/to/trusted/postgresql/root
ARGOS_TEST_POSTGRES_ROOT=/path/to/trusted/postgresql/root cargo test -p argos-recovery --offline --locked -- --ignored
```

`--report`는 존재하지 않는 새 파일을 지정한다. PostgreSQL 도구가 없으면 서비스 시나리오에서 `--pg-root`를 생략해 SQLite만 검사한다. PostgreSQL은 신뢰한 도구·일반 사용자·작동하는 bubblewrap이 필요하며, 없을 때 호스트 DB 실행으로 대체하지 않는다. namespace·시간/파일/출력/작업량 상한은 VM이나 디스크 quota를 대신하지 않는다. 커널 I/O 정지 상태의 프로세스가 SIGKILL 직후 소멸한다고 보장하지 않는다.

프로브 성공은 한 파일의 전달, DB 성공은 계획한 DB 검사, 수신증명은 지정 키의 보관 수락, AI 검사는 인용 형식/존재를 확인한 결과다. 전체 감시·서비스 RTO/RPO·서버 관리자 삭제 방지·AI 문장 의미의 참으로 확대 해석하지 않는다.


## v0.3.0 배포 산출물 확인

태그와 `BUILD_INFO.json`의 소스 커밋은 `d7681053036c51ecdbbe343a9578ffa2f95a2f57`이다. 업로드한 [릴리즈 압축 파일](https://github.com/hkjang/ArgosAISecurity/releases/tag/v0.3.0)을 다시 내려받아 `SHA256SUMS`, 패키지 내부 네 실행 파일의 해시·크기 및 소스 정보를 확인했다. 문서·설정·검증 스크립트 포함과 각 실행 파일의 도움말 실행도 검사했다.

`argos-v0.3.0-linux-x86_64-gnu.tar.gz`의 SHA-256:

```text
78316959ae17557ac9c23c3c1f4c48619d1c78e80010e2c637249ffcdb0ad642
```

실행 파일 요구 glibc는 `argos` 2.39, `argos-agent`·`argos-central`·`argos-vault` 2.34다. 이후 `main`의 배포 검증 문서 갱신은 발행한 태그·압축 파일을 변경하지 않는다.

## 기존 v0.1.0 실행 결과

- `cargo test --workspace`: **96개 단위/회귀 테스트 통과**.
- `cargo build --workspace`: 성공.
- `scripts/smoke-test.sh`: 실제 notify 파일 변경 → 탐지 → 정상본 지정 → 별도 미리보기 → 원본 복구 → 정책 재생·서명/변조 거부 통과.
- `scripts/platform-smoke.py`: 운영 인증 거부/개발 모드 제한/에이전트 사칭 거부/수집 중복 제거/생존 신호, 실제 에이전트·안전 복구, MCP 초기화·읽기 전용·기간 조회, HTML 데이터 주입 방지·기존 파일 보호 통과.
- `scripts/test-isolation-netns.py`: 별도 사용자/네트워크 네임스페이스에서 실제 IPv4/IPv6 TCP 패킷 검증 통과. 관리 연결 유지, 기존/새 의심 연결 차단, 전달 경로 차단, 재적용 멱등성, 해제 후 통신 복원, 관련 없는 규칙 보존. 호스트 규칙은 변경하지 않음.
- Linux 대응 테스트: 잘못된 시작 신원은 거부하고 테스트 자식은 계속 살아 있음. 올바른 신원의 pidfd로 해당 자식만 SIGKILL 종료 확인.
- 로컬 모의 중앙 서버: 등록 503, 저장 후 ACK 유실, 302 응답을 성공으로 오인하지 않음, 고정 전달 ID 재시도, 유휴 생존 신호 통과.
- 정상 배포 고정 시나리오: 고엔트로피 파일 30개의 알림 **3→0**, 차단 임계치 이벤트 **16→0**. 승인 범위 밖 실행 파일의 공격은 탐지 유지. 운영 오탐률의 실측 결과는 아님.
- 복구 시험: 기존 소유권 유지, `06755 → 0755`, 신규 파일 `0600`, 원본 심볼릭 링크 거부.
- `git diff --check`, 변경 Rust 파일 포맷, 보고서 JavaScript 문법 검사 통과.

## v0.2.0 정책 신뢰·Linux 분석 검증

- `cargo test --workspace --offline --locked`: **144개 단위/회귀 테스트 통과**. `cargo build --release --workspace --offline --locked` 성공.
- v0.2.0 배포용 최적화 바이너리로 `scripts/smoke-test.sh`, `scripts/platform-smoke.py`, `scripts/security-scenarios.py`를 실행해 모두 통과했다. `argos --version`은 `argos 0.2.0`이며 패키지의 최대 요구 glibc 버전은 2.39다.
- 정책: 동일 바이트 검증·파싱, 버전 재사용·다운그레이드·기간·대상·키 ID 거부, 승인된 새 버전 롤백, 재시작·동시 적용·감사 기록 실패 시 원자성 검증. 실행 중 기간 이탈은 대응 직전 재검사하고 자동 차단을 중단한다.
- 탐지: 10/60/600초 시간창, 분산 PID·유효 계정·부모 계보·보호 경로 집계, PID 재사용·규칙별 예외·근거 상한, 중간/끝 부분 변조와 ZIP 기준·실제 읽기 예산 검증. 합산 경보만으로 개별 PID를 차단하지 않는다.
- Linux 설정: 주석·공백/키 설명과 실제 SSH·sudoers·cron·systemd 변경 분리, 인용 옵션·지시문 순서·중복 보존, 초기 읽기 실패의 보호 상태 표시. 실제 `/proc`의 같은 PID 실행 변경과 UID/GID·capability 근거 확인.
- 복구: 독립 사건 참조·정상 판정 취소·`prune(0)`·동시 고정/정리·재시작·승인 재사용 거부. 백업 DB 쓰기 잠금 중에도 탐지 기록이 2초 이내 완료되며, 보존 요청은 별도 스레드에서 대기한 뒤 재시작 후 중복 없이 완료된다. 이는 테스트 환경의 제한된 잠금 시험이며 운영 지연 보장이 아니다.
- 보존 요청은 탐지와 같은 트랜잭션에 저장하며 10,000건 상한 초과에서도 탐지를 유지하고 누락을 영속 계수한다. 재시도·ACK 중복·상태 보존을 검증했다.
- 증거 패키지: 숫자 근거 ID 유지, 명령행/경로/문자열 ID 마스킹, 개별 SHA-256·파일 목록 검증, 변조·추가 파일·기존 출력 덮어쓰기 거부.
- `scripts/security-scenarios.py`: 실제 CLI/에이전트의 정상/의미 변경, 자동 사건 보존, 같은 PID exec·자격 정보, 승인 해제, 증거 패키지, 분산 정책 재생, 영속 정책 신뢰 등 **8개 시나리오 통과**. 예상 결과와 실제 결과를 JSON으로 저장한다.

외부 승인자 인증, 완전한 Linux 유효 설정 평가, 사건 당시 실제 실행 정책 증명, 실행 파일 해시/패키지 신뢰, 서비스 영향 및 CPU/디스크 기반 자동 축소는 이 구현의 완료 범위가 아니다. 서명 정책 상태와 백업 저장소는 로컬 관리자/root에 대한 별도 외부 보존 경계를 제공하지 않는다.

## v0.2.0 배포 산출물 검증

[v0.2.0 릴리즈](https://github.com/hkjang/ArgosAISecurity/releases/tag/v0.2.0)의 태그와 `BUILD_INFO.json`은 소스 커밋 `0a3fc4c38d1d76d02464bf57adbe6e33f794fdfa`를 가리킨다. 패키지 내 실행 파일별 해시·크기, CLI 버전, 도움말 실행, 문서·설정·시험 스크립트 포함을 확인했다. 업로드한 파일을 다시 내려받아 `SHA256SUMS`와 일치함을 확인했다.

`argos-v0.2.0-linux-x86_64-gnu.tar.gz`의 SHA-256:

```text
a44819e6a9a4aa3e5b81bc89ff88bbbecc24adc00ebefe603a4730b897109a6a
```

실행 파일 요구 glibc는 `argos` 2.39, `argos-agent`·`argos-central` 2.34이므로 패키지는 **glibc 2.39 이상**을 요구한다. 바이너리 설치와 설정 이전은 [설치 안내](INSTALL_BINARY.md)를 따른다. 이후 `main` 문서 갱신은 발행된 태그·압축 파일을 변경하지 않는다.

## 릴리즈 이후 문서 점검 (2026-09-27)

README·설치·역할별 운영·기능·구조 문서를 v0.2.0 코드 및 배포 바이너리의 도움말과 대조했다. Markdown/HTML 상대 링크·앵커, TOML 예제, 사이트 JSON-LD·언어별 번역 키, `node --check docs/app.js`를 확인했다. 한국어·영어 CLI 데모의 5개 탭·FAQ·모바일 메뉴는 DOM 모의 실행으로 검사했으며 실제 브라우저의 시각 검사는 수행하지 않았다.

이 점검은 문서와 정적 사이트 변경에 대한 검증이다. 위 144개 테스트·8개 시나리오는 v0.2.0 릴리즈 바이너리 검증 결과이며, 문서 갱신으로 운영 탐지율이나 지원 플랫폼 범위가 확대되지는 않는다.

## 재현

```bash
cargo test --workspace
cargo build --workspace
sh scripts/smoke-test.sh
python3 scripts/platform-smoke.py --bin-dir target/debug
python3 scripts/security-scenarios.py --bin-dir target/debug --report /tmp/argos-scenarios.json
python3 scripts/test-isolation-netns.py --argos target/debug/argos
```

기본 target 디렉터리가 쓰기 불가인 현재 환경에서는 `CARGO_TARGET_DIR=/tmp/argos-recovery-target`을 사용했다. Python 시험에 해당 `--bin-dir`/`--argos` 경로를 지정한다. 격리 시험은 `unshare`, `ip`, `iptables`/`ip6tables` 계열 도구와 사용자 네임스페이스 지원이 필요하다. 설치되지 않은 도구는 시험 시 `/tmp`에만 추출해 사용했다.

소스에서 배포용 최적화 바이너리를 검증하려면 다음처럼 실행한다. `--report`의 출력 파일은 새 경로여야 한다.

```bash
cargo build --release --workspace --locked
ARGOS_BIN_DIR="$PWD/target/release" sh scripts/smoke-test.sh
python3 scripts/platform-smoke.py --bin-dir target/release
python3 scripts/security-scenarios.py --bin-dir target/release --report /tmp/argos-release-scenarios.json
```

## 도입 순서와 후속 검증

1. 관찰 모드에서 센서 유실·백업 누락·전송 대기열을 확인하고 정책 재생 결과를 보관한다.
2. 검토된 정상본을 명시적으로 지정하고 중요 경로별 별도 복구 시험을 수행한다.
3. 서명된 후보 정책을 운영자가 선택한 소수 서버에 배포하고 결과 감사와 업무 영향을 확인한 뒤 확대한다. 중앙 자동 정책 배포는 아직 구현 범위 밖이다.

실제 fanotify 커널 권한을 사용하는 수집·차단 전체 경로, 운영 처리량/CPU/I/O 목표, 사내 LLM 품질, 실제 분석가의 조사 시간 단축은 배포 환경에서 추가 측정해야 한다. 현재 테스트는 운영 성능 인증이 아니다.

ITSM 자동 수집 커넥터, Suricata/Zeek 연결 상관분석, eBPF, mTLS, Kubernetes는 후속 통합이다. 승인 작업은 현재 서명 가능한 정책에 입력한다. 격리 규칙은 패킷을 차단하며 소켓 객체 자체를 삭제하지 않는다. 백업은 파일시스템의 원자적 스냅샷이 아니고, 해시가 정상 내용을 보증하지 않는다. ACL/xattr/SELinux·완전한 디렉터리 권한 메타데이터 복원은 후속 과제다.
