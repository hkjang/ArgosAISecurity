# Argos AI Security 소스 코드 안내

기준: **v0.5.0, 2026-09-27**. 현재 함수와 데이터 흐름을 따라 읽는 개발자용 안내다. 설계 전체는 [아키텍처](ARCHITECTURE.md), 요구·미구현 항목은 [요건서](REQUIREMENTS.md), 실행 검증은 [검증 기록](PLATFORM_VALIDATION.md)을 참고한다. 이 문서의 코드 대조를 새로운 실행 시험이나 운영 성능 측정으로 해석하지 않는다.

## 워크스페이스 입구

[Cargo.toml](../Cargo.toml)은 Rust 2021·최소 Rust 1.86과 공통 의존성을 정의한다. 아래 11개 크레이트 중 마지막 세 개가 실행 파일이다.

| 크레이트 | 먼저 읽을 파일 |
| --- | --- |
| `argos-common` | [event.rs](../crates/argos-common/src/event.rs), [config.rs](../crates/argos-common/src/config.rs) |
| `argos-sensor` | [lib.rs](../crates/argos-sensor/src/lib.rs), [fanotify.rs](../crates/argos-sensor/src/fanotify.rs), [procmon.rs](../crates/argos-sensor/src/procmon.rs), [health.rs](../crates/argos-sensor/src/health.rs) |
| `argos-detect` | [lib.rs](../crates/argos-detect/src/lib.rs), [scorer.rs](../crates/argos-detect/src/scorer.rs), [multi_window.rs](../crates/argos-detect/src/multi_window.rs), [entropy.rs](../crates/argos-detect/src/entropy.rs) |
| `argos-storage` | [lib.rs](../crates/argos-storage/src/lib.rs), [evidence.rs](../crates/argos-storage/src/evidence.rs), [outbox.rs](../crates/argos-storage/src/outbox.rs), [response_audit.rs](../crates/argos-storage/src/response_audit.rs) |
| `argos-policy` | [lib.rs](../crates/argos-policy/src/lib.rs), [trust.rs](../crates/argos-policy/src/trust.rs), [simulation.rs](../crates/argos-policy/src/simulation.rs) |
| `argos-response` | [lib.rs](../crates/argos-response/src/lib.rs), [isolate.rs](../crates/argos-response/src/isolate.rs) |
| `argos-recovery` | [lib.rs](../crates/argos-recovery/src/lib.rs), [retention.rs](../crates/argos-recovery/src/retention.rs) |
| `argos-brain` | [lib.rs](../crates/argos-brain/src/lib.rs) |
| `argos-agent` | [main.rs](../crates/argos-agent/src/main.rs), [backup_worker.rs](../crates/argos-agent/src/backup_worker.rs), [reporter.rs](../crates/argos-agent/src/reporter.rs), [semantic.rs](../crates/argos-agent/src/semantic.rs) |
| `argos-central` | [main.rs](../crates/argos-central/src/main.rs), [dashboard.html](../crates/argos-central/src/dashboard.html) |
| `argos-cli` | [main.rs](../crates/argos-cli/src/main.rs), [investigation.rs](../crates/argos-cli/src/investigation.rs), [reports.rs](../crates/argos-cli/src/reports.rs), [evidence_package.rs](../crates/argos-cli/src/evidence_package.rs) |

## 1. 공통 데이터와 수집 신원

`FileEvent`는 시각·PID·경로·행위·크기·엔트로피에 더해 선택적 `process`와 `content`를 담는다. `FileProcessContext`의 실행 파일·유효 UID·시작 ticks·부팅 ID는 승인 작업과 대응 신원 판단의 근거다. `ancestors`에는 당시 확인한 최대 4단계 부모 `ProcessIdentity`를 저장한다. 과거 맥락을 현재 `/proc`로 채우지 않는다.

`ContentEvidence`는 관측 시각·파일 크기·총 표본 예산·실제 읽은 바이트·형식 추정·위치별 엔트로피와 이전 관측 대비 차이를 저장한다. `complete`는 읽은 바이트 수가 관측 파일 크기와 같은지를 나타내며, 큰 파일의 부분 표본에서는 false다. 내용이 정상이라는 판정은 아니다. `ProcessEvent`는 실행 신원 외에 선택적 `ProcessCredentials`로 real/effective/saved-set/filesystem UID·GID와 capability 집합을 저장한다. 이전 자료나 미수집 값은 `None`으로 남긴다.

`spawn_sensor(kind, paths, tx)`는 notify와 fanotify를 선택한다. notify는 기본값이며 PID를 모르면 0이다. fanotify는 Linux에서 `FAN_MODIFY`·`FAN_CLOSE_WRITE`를 받고 마운트 마크 후 감시 경로를 필터링한다. 삭제·이름 변경 등 모든 `FileAction`을 이 백엔드가 수집한다고 가정하면 안 된다. `/proc` 모니터는 폴링 전후 신원을 확인하지만 매우 짧은 실행과 폴링 사이 변화는 놓칠 수 있다.

## 2. 에이전트 시작과 이벤트 처리

`argos-agent/main.rs::main()`의 순서는 다음과 같다.

1. `AgentConfig::load()` 후 서명 정책이 설정되어 있으면 `argos_policy::activate_file()`을 호출한다. 실패는 시작 실패로 전파하며 로컬 기본 탐지 설정으로 우회하지 않는다.
2. `validate_configuration()`으로 센서·점수·승인·집계 설정을 검사하고 도달 불가능한 임계치를 경고한다.
3. 감시 경로를 정규화하고 이벤트 DB·탐지 엔진·의미 분석·선택적 내용 샘플러를 만든다. 백업 디렉터리가 감시 경로 안에 있으면 거부한다.
4. 백업/보존 및 중앙 보고 작업자를 시작하고 파일 큐 8192건·프로세스 큐 1024건을 연결한다.
5. `tokio::select!`에서 파일·프로세스 이벤트와 30초 상태 기록을 처리한다. 파일 센서 채널 종료는 보호 저하와 오류 종료로 나타낸다.

`process_event()`의 실제 처리 순서는 아래와 같다.

```text
필요한 내용 표본 수집
  → DetectionEngine::evaluate
  → SemanticMonitor::observe의 추가 알림 병합
  → 정책 기간 재검사 + 매 이벤트 대응 판단 + 필요 시 신원 확인 종료
  → 대응 결과 감사 저장
  → 파일 이벤트 저장
  → Create/Modify 백업 큐에 비차단 삽입
  → 기본/추가 탐지 각각 기록 + 전송/보존 요청 트랜잭션
```

대응은 알림 재보고 여부·전체 파일 백업·중앙 HTTP 완료를 기다리지 않는다. 다만 내용 표본·의미 분석·로컬 SQLite·대응 실행은 동기 구간을 포함한다. `guard_policy_time()`은 실행 중 서명 정책이 기간을 벗어나면 자동 대응을 끄고 해당 실행에서 다시 켜지 않도록 한다.

`response_actions`에는 `succeeded`, `failed_or_unconfirmed`, `rejected`, `observed_threshold`를 구별해 기록한다. 파일 이벤트·대응 감사·각 탐지는 별도 저장 작업이다. 프로세스를 종료한 뒤 DB가 실패할 수 있으므로 탐지 행만으로 대응 성공이나 감사의 완전성을 추정하지 않는다.

## 3. 탐지 API와 점수

`DetectionEngine::with_sensor(config, sensor)`로 센서 종류를 지정하고 `evaluate(&FileEvent)`를 사용한다. 반환 `Evaluation`은 `score`, `pid`, `eligible`, `alert`, `additional_alerts`, `approved_change_id`, `evidence_truncated`를 제공한다. `block_candidate()`는 임계치 후보, `should_block()`는 자동 대응 설정까지 반영한다. 호환 API `observe()`는 기본 `alert`만 반환하므로 에이전트 대응과 추가 알림 처리를 대신할 수 없다.

`scorer.rs`의 기본 점수는 대량 변경 최대 40점, 엔트로피 최대 notify 35/fanotify 60점, 이름 변경·삭제 notify 최대 25점이다. 기본 시간창 10초·최소 변경 파일 5개·대량 변경 기준 30개·탐지 40점·차단 80점이며, 자동 차단 기본값은 false다. 알림 재보고 억제와 점수 평가는 분리되어 있다.

승인 작업은 기간·경로·실행 파일·유효 UID·시작 신원을 모두 확인한다. `adjusted_rules`에 이름을 적은 규칙만 조정하며 범위 밖 증거는 유지한다. 미끼 파일의 수정·삭제·이름 변경은 95점이며 일반 승인으로 사라지지 않는다.

`multi_window.rs`는 선택적 여러 시간창의 동일 인스턴스·계정/경로·보호 경로·부모 계보를 집계한다. 동일 인스턴스의 근거만 개별 대응 점수에 참여한다. 여러 인스턴스의 합산 알림은 `pid=0`과 범위·참여 PID를 표시하고 `additional_alerts`로 전달한다. 이벤트·그룹·경로 길이 상한과 시각 역전 등으로 근거가 빠지면 표시하며, 재생도 이벤트 시각에 따라 같은 로직을 실행한다.

`entropy.rs::ContentSampler::new(total_bytes, max_files, history_secs)`와 `observe(path, observed_at_ms)`는 총 예산을 앞·중간·끝에 나눈다. 기본 64 KiB, 설정 최대 1 MiB이며 별도의 앞부분 엔트로피 읽기를 중복 수행하지 않는다. 비교 가능한 이전 표본의 증가량을 사용하고 압축 형식의 높은 초기 엔트로피만으로 신호를 만들지 않는다. 표본 이력은 정상본 저장소가 아니며 특정 PID가 작성한 바이트의 증명도 아니다. 구성과 경계는 [탐지 기능](FEATURE_DETECTION.md)에 있다.

`semantic.rs`는 별도 `[semantic].files`의 SSH·sudoers·cron·systemd 내용을 제한적으로 비교한다. 원문 비밀값을 알림에 넣지 않으며 의미 변화는 추가 탐지로 기록한다. 읽기/분석 누락은 상태로 구별한다. 완전한 Linux 설정 평가나 실제 권한 상승 성공 판정은 아니다.

## 4. 정책 신뢰와 재생

| API | 역할과 주의점 |
| --- | --- |
| `sign_bytes` / `verify_bytes` | Ed25519 원문 바이트 서명·검증 |
| `activate_file` | 제한된 일반 파일 읽기, 동일 바이트 검증·파싱, 메타데이터·설정·영속 버전 검사와 수락/감사 트랜잭션 |
| `read_state` / `load_active_policy` | 저장된 마지막 수락 상태·설정 조회 |
| `load_trusted` | 신뢰 키·기간·대상·설정의 읽기 전용 사전 검사. 영속 수락을 대신하지 않음 |
| `simulate` | 읽기 전용 이벤트 DB의 기간·상한 내 자료로 기준/후보 정책 비교 |

정책 원문의 키 ID는 로컬 `trusted_keys`에 있어야 한다. 동일 버전의 다른 바이트와 다운그레이드는 거부하고, 동일 버전·동일 해시 재시작도 기간·대상·키를 다시 확인한다. 롤백은 과거 수락 버전·해시·설정 및 미사용 승인 ID를 참조하는 더 높은 새 버전이다. 상태 디렉터리/파일 권한, 서명 파일 종류·크기, 감사 실패의 트랜잭션 취소도 `trust.rs`에서 처리한다. 로컬 관리자/root의 상태 전체 삭제·디스크 롤백과 외부 승인자 인증은 처리하지 않는다.

`simulation.rs`는 두 정책의 활성 시간창 중 가장 긴 준비 구간을 포함한다. 저장된 엔트로피·내용 표본·프로세스 맥락만 사용하고 시각·DB ID 순으로 재생한다. 현재 파일·`/proc` 접근, 실제 종료, 정책 적용을 하지 않는다. 집계 알림·개별 임계치·프로세스 인스턴스별 예상 대상과 근거 ID·조회 누락을 구별한다. 실제 차단 뒤 달라질 이벤트 흐름이나 다른 위치/크기의 내용 표본을 재현하지 못한다. [정책 기능](FEATURE_POLICY.md)이 운영 절차를 설명한다.

## 5. 이벤트 저장과 비동기 작업

`EventStore::open()`은 SQLite WAL 스키마를 초기화/이전하며 이벤트 DB 동기화는 `NORMAL`이다. CLI 조회는 `open_readonly()`를 사용한다. 과거 DB에 신원·내용 JSON이 없으면 읽을 때 미확인 값으로 반환하며 조회만으로 마이그레이션하지 않는다.

| 테이블/모듈 | 용도 |
| --- | --- |
| `file_events`, `process_events`, `detections` | 기본 조회 열과 이벤트 JSON으로 원본 맥락·표본 및 탐지를 보존 |
| `response_actions` / `response_audit.rs` | 대응 결과와 실제 프로세스 신원, `insert_response_result`·`response_results` |
| `detection_outbox`, `delivery_counters` | 고정 전달 ID, 시도·성공·실패 통계 |
| `retention_jobs`, `retention_counters` | 탐지별 보존 요청, 재시도·완료·상한 초과 통계 |
| `evidence.rs` | `EvidenceQuery`, `EvidencePage`, `EvidenceBundle`, `query_evidence` |

`record_detection(detection, agent_id, pin_recovery)`는 탐지와 필요한 outbox·보존 요청을 같은 트랜잭션에 쓴다. 보존 큐가 10,000건을 넘으면 탐지 자체는 유지하고 요청 누락을 계수한다. `query_evidence()`는 시작·종료 포함, 선택적 PID, 종류별 1~10,000건 상한을 검사한다. 파일·프로세스·탐지와 전체 건수는 같은 읽기 스냅샷이며 대응 결과 조회는 별도 스냅샷이다. 종류별 ID가 겹칠 수 있어 근거에는 테이블 종류도 표시한다.

`backup_worker.rs::BackupWorker`는 백업과 사건 보존에 별도 스레드를 둔다. 백업 큐는 메모리 상한과 비차단 삽입을 사용하고 시작 베이스라인도 작업자에서 진행한다. 지연 후 읽은 내용을 이벤트 과거 시각의 백업으로 표시하지 않고 실제 수집 시각을 사용한다. 논리 파일 크기에 따른 대기는 평균 처리 예산이며 물리 디스크 I/O 상한이 아니다. 이 메모리 큐는 영속 큐가 아니다.

사건 보존 작업자는 이벤트 DB 요청을 읽은 뒤 DB 읽기 잠금을 풀고 백업 DB에서 탐지 경로의 탐지 이전 정상본을 고정한다. 사건/버전 고유 참조로 부분 성공과 재시작을 처리한다. 정상본이 없거나 저장소에 접근하지 못하면 실패·재시도 상태를 표시한다. 보존 작업 대기는 다음 이벤트의 판단 경로에서 발생하지 않는다.

`reporter.rs`는 용량 1의 깨우기 채널과 디스크 outbox를 사용한다. 전용 `std::thread`가 blocking HTTP를 수행하며 실패 시 1~60초 간격으로 재시도한다. 중앙 성공 응답 후에만 삭제하고 생존 신호는 탐지가 없어도 보낸다. 보장은 로컬 트랜잭션이 성공한 데이터에 한하며 센서 누락·디스크 고장을 복구하지 못한다.

## 6. 복구·사건 보존·대응 실행

`BackupStore::backup()`은 읽은 현재 파일을 SHA-256 객체와 `index.db` 버전으로 보관한다. 시작 베이스라인도 `known_good=false`다. **변경 전 복사나 원자적 파일시스템 스냅샷을 구현한 함수가 아니다.**

| 복구 API | 의미 |
| --- | --- |
| `versions`, `mark_known_good`, `revoke_known_good` | 버전 조회, 근거를 남기는 정상 판정·취소 |
| `recommend(path, before_ms)` | 정상본 중 최신 선택. 시각 지정 시 엄격히 그 이전 버전 |
| `preview` | 해시를 검증한 후 별도 새 경로에 검토용 복원 |
| `restore` | 정상본만 원래 경로에 복구. 임시 파일 작성·동기화 후 교체 |
| `readiness`, `test_restore` | 관측 경로별 정상본·제외·시험 상태와 별도 복구 시험 |
| `pin_version`, `pin_known_good_before` | 정상 판정과 별개인 사건 보존 참조 |
| `release_pin`, `release_incident`, `retention_audit` | 승인 근거로 해제하고 이력 조회 |
| `prune` | 경로별 미검토 버전 수 제한. 정상본과 활성 사건 고정 버전은 유지 |

해시 일치는 내용의 정상성을 증명하지 않으며 사건 고정도 정상 판정을 부여하지 않는다. 복구 시 기존 일반 파일의 UID/GID를 보존하고 특수 권한 비트를 제거한다. ACL/xattr·애플리케이션 일관성·원본 상위 경로의 동시 교체까지 해결하는 스냅샷 복구는 아니다. [복구 기능](FEATURE_RECOVERY.md)에 정확한 거부 조건과 운영 경계를 둔다.

`argos-response`의 `Responder::execute()`는 조치 결과를 반환한다. 에이전트는 `ResponseAction::KillProcessInstance`로 PID·시작 ticks·부팅 ID를 검증하고 pidfd에 신호를 보내 종료를 확인한다. PID 0은 거부한다. 일반 프로세스 API와 별개로 실제 에이전트 자동 차단 경로의 신원 확인을 유지해야 한다.

`isolate.rs`의 `isolation_commands()`는 명령 계획을 만들고 `isolate_host()`는 적용·확인한다. IPv4/IPv6 각각 `ARGOS_INPUT`, `ARGOS_OUTPUT`, `ARGOS_FORWARD`를 사용하며 `ARGOS_ISOLATE`는 구형 체인 정리 대상이다. 명시적 관리 연결 외 기존 의심 연결의 패킷도 차단한다. 두 주소 계열의 부분 실패와 별도 네임스페이스 트래픽 한계를 성공으로 감추지 않는다. 호스트 방화벽 시험은 [별도 네임스페이스 스크립트](../scripts/test-isolation-netns.py)로 수행한다.

## 7. 중앙·CLI·AI 조사

`argos-central`의 등록·생존 신호·탐지 POST는 에이전트별 토큰, 에이전트/탐지 GET은 관리자 토큰으로 인증한다. `(agent_id, delivery_id)` 중복 제거는 재전송에 적용한다. `/healthz`는 HTTP 서버 응답 확인이며 센서 정상 수집의 증명이 아니다. 중앙 전체 기능과 운영 TLS 구성은 [중앙 서비스](SERVICE_CENTRAL.md)에 있다.

CLI의 `Command`·`PolicyAction`·`RetentionAction`은 명령 정의의 기준이다. 조회·정책 재생과 달리 `restore`, `retention`, `isolate`, 미끼 파일 생성은 명시적 변경 작업이다. `policy verify`는 사전 검증, 실제 활성화는 에이전트 시작 경로다. `update`는 아직 미구현이다. 전체 명령은 [CLI 안내](SERVICE_CLI.md)를 따른다.

`ThreatExplainer::from_config()`는 제공자·모델·주소·환경변수 키를 적용하고 `ask_investigation()` 등으로 조회한 근거와 대응 결과를 전달한다. AI는 자동 대응 결정을 실행하지 않는다. `investigation.rs::time_range()`는 지원하는 상대 기간 또는 명시적 epoch 구간을 처리하며 임의의 자연어 달력 표현을 모두 해석하지 않는다. `serve_mcp()`는 설정한 단일 로컬 DB의 `query_evidence`만 노출한다.

`reports.rs`는 HTML 이스케이프와 독점 파일 생성으로 사건·복구 준비도 보고서를 쓴다. `evidence_package.rs::export()`·`verify()`는 마스킹된 근거·마지막 수락 정책 상태와 SHA-256 manifest를 만들고 검사한다. 해시 manifest는 발급자 서명이나 사건 당시 정책 실행 증명이 아니다. 모델 품질, 전체 호스트 간 상관관계와 사건 인과관계 확정은 별도 검증 대상이다.

## 8. 수정 시 함께 확인할 시험

| 변경 영역 | 연결된 검증 |
| --- | --- |
| 점수·예외·신원·집계 | `argos-detect`, `argos-policy`, `argos-agent`, `argos-response`의 회귀 테스트 |
| 저장·전송·보존 | `argos-storage`, `argos-agent`, `argos-central`, `argos-recovery` 테스트 |
| 정책 신뢰·롤백 | `argos-policy`의 파일 종류·기간·버전·대상·권한·동시 수락·감사 실패 테스트 |
| 사용자 흐름 | [smoke-test.sh](../scripts/smoke-test.sh), [platform-smoke.py](../scripts/platform-smoke.py), [security-scenarios.py](../scripts/security-scenarios.py) |
| 네트워크 격리 | [test-isolation-netns.py](../scripts/test-isolation-netns.py)의 IPv4/IPv6 실제 패킷 시험 |

릴리즈 시험은 [검증 기록](PLATFORM_VALIDATION.md)에 결과와 한계를 남긴다. 시험 통과를 초당 처리량·탐지 지연·운영 오탐률·전체 fanotify 통합 경로의 검증으로 확대 해석하지 않는다.

## v0.3.0 검증 확장 파일

| 경로 | 읽을 부분 |
| --- | --- |
| `argos-sensor/src/coverage.rs` | 등록 기준, FD 기반 경로 순회, 마운트 파싱과 검사 상한 |
| `argos-agent/src/coverage_worker.rs` | 별도 작업자·단조 시계 나이·보호 상태 연계 |
| `argos-cli/src/coverage.rs` | 고유 시험 파일·별도 자식·읽기 전용 DB 이벤트 확인 |
| `argos-recovery/src/service.rs`, `service/` | 네이티브 DB 복원과 고정 검사, PostgreSQL 격리 |
| `argos-cli/src/service_recovery.rs` | 동일 계획 전달·자식 프로세스 감독·시간 제한 |
| `argos-vault/src/{lib,client,server}.rs` | 수신증명 형식·서명·해시, 역할별 인증·독점 객체 게시 |
| `argos-cli/src/vault.rs` | 정상본·증거 패키지 어댑터와 새 파일 복원 |
| `argos-policy/src/exception_audit.rs` | 예외 매칭 표본과 동일 이벤트 스냅샷의 예외 제거 재생 |
| `argos-brain/src/validation.rs` | 근거 목록 검증·응답 JSON 인용 대조·고정 누락 안내 |

구현 경계와 결과 해석은 [아키텍처 확장](ARCHITECTURE.md#v030-검증-경로와-별도-보관-경계)에 정리한다.

## v0.4.0 내구성·일관성 검사 경로

| 경로 | 읽을 부분 |
| --- | --- |
| `argos-vault/src/queue.rs`, `queue/tests.rs` | 고정 바이트·대상, SQLite 게시/재시도, 수신증명 커밋 후 정리 |
| `argos-vault/src/quota.rs`, `quota_tests.rs` | Linux 작성자 잠금, 시작 스캔, 논리 계수·디스크 여유·요청 승인 |
| `argos-recovery/src/service/verification.rs` | 정규화 계획·기대값 해시, 안정 파일 읽기, v2 검사·시각·백업 대조 |
| `scripts/durability-scenarios.py` | 실제 CLI의 오프라인 큐·재시작·한도·복구 보고서 재검증 |

## v0.5.0 큐 운영 경로

`argos-vault/src/queue.rs`와 하위 모듈은 schema v2 이전·완료 이력·임대·내보내기를 담당한다. `client.rs`는 HTTP/연결/무결성 오류를 민감 본문 없이 분류한다. `packaging/argos-vault-upload.{service,timer}`는 별도 계정의 제한된 drain 호출을 예약한다. 실제 동시 등록·이력 검증은 `scripts/queue-operations-scenarios.py`를 참고한다.
