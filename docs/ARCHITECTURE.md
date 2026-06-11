# Argos 아키텍처 (MVP Phase 1 + Phase 2)

## 컴포넌트와 크레이트 매핑

| 요건서 컴포넌트 | 크레이트 | Phase |
| --- | --- | --- |
| Argos Agent | argos-agent | 1 |
| Argos Sensor | argos-sensor | 1 (notify) + 2 (fanotify) → 3 (eBPF) |
| Argos Detect | argos-detect | 1 |
| Argos Response | argos-response | 1 (프로세스 차단만) |
| (로컬 저장) | argos-storage | 1 |
| Argos Recovery | argos-recovery | 2 (백업·해시 검증 복구) |
| Argos Central | argos-central | 2 (등록/수집/조회 API) |
| Argos Brain | argos-brain | 2 (AI Threat Summary) |
| Argos Copilot | (미착수) | 3 |

## 데이터 흐름

```
 감시 경로
    │  파일 생성/수정/삭제/이름변경/권한변경
    ▼
 argos-sensor (백엔드 선택: sensor 설정)
    │  notify   : 크로스 플랫폼, pid=0
    │  fanotify : Linux+root, 수정 이벤트에 원인 pid 포함
    │  FileEvent { ts, pid, path, action, size }
    │  tokio mpsc 채널 (버퍼 8192, backpressure)
    ▼
 argos-agent 파이프라인 (tokio)
    │  1. Modify면 file_entropy() 계산 (앞 64KB 샘플)
    │  2. EventStore.insert_file_event()        ──→ SQLite (WAL)
    │  3. Create/Modify면 BackupStore.backup()  ──→ 내용 주소 저장소
    │  4. DetectionEngine.observe()
    │       └ BehaviorScorer: pid별 슬라이딩 윈도우(10s) 점수
    │  5. 점수 ≥ detect_score → Detection 저장 + 중앙 보고 채널
    │  6. 점수 ≥ block_score && pid != 0 && auto_block
    │       └ Responder.execute(KillProcess)
    ▼                                ▼
 argos-cli                      reporter 스레드 (std thread + blocking HTTP)
   status/events/threats          │ POST /api/v1/detections (Bearer)
   scan/doctor                    ▼
   restore  ← argos-recovery   argos-central (axum + SQLite)
   explain  ← argos-brain        에이전트 등록 / 탐지 수집 / 현황 조회
              (Claude API)
```

## 위험 점수 모델 (Phase 1)

윈도우(기본 10초) 내에서:

| 요소 | 가중 | 근거 |
| --- | --- | --- |
| 변경 파일 수 / mass_change_threshold | 최대 40점 | 랜섬웨어의 대량 파일 변경 |
| 고엔트로피(≥7.2) 쓰기 비율 | 최대 35점 | 암호화 데이터의 엔트로피 증가 |
| 이름 변경 + 삭제 비율 | 최대 25점 | 확장자 변경(.locked 등), 원본 삭제 |

Severity: 40+ Medium, 65+ High, 85+ Critical.
요건서 8장의 나머지 요소(프로세스 신뢰도, 사용자 권한, 자산 중요도)는 fanotify pid 확보 후(Phase 2~3) 추가한다.

## 주요 설계 결정

1. **notify 우선, fanotify 나중** — 요건서 18장 "커널 버전 호환성: fanotify 기본, eBPF 선택 적용"의 전 단계.
   notify는 pid를 못 주므로 Phase 1의 자동 차단은 사실상 dry-run이다.
   `argos-sensor`의 공개 API(`spawn_fs_sensor(paths, tx)`)를 고정해 두어 센서 교체가 다른 크레이트에 영향을 주지 않게 했다.
2. **SQLite + WAL** — 요건서 7장 "SQLite 또는 RocksDB" 중 SQLite 선택.
   CLI가 데몬과 동시에 read-only로 열 수 있고, 운영 디버깅이 쉽다.
   초당 20,000 이벤트 요건은 Phase 2에서 배치 insert + 이벤트 필터링으로 대응.
3. **자동 차단 기본 비활성** — 요건서 18장 1순위 리스크(오탐으로 인한 업무 중단) 대응.
   `auto_block=true` + Linux + pid 식별이 모두 충족될 때만 SIGKILL.
   pid 0 차단 요청은 Responder가 무조건 거부한다 (kill(0)은 프로세스 그룹 전체 시그널 — 자살 방지).
4. **워크스페이스 분리** — 컴포넌트 경계 = 크레이트 경계. Phase 2의 Central/Recovery/Brain도 같은 패턴으로 크레이트 추가.

## Phase 2 구현 메모

1. **fanotify 센서** — FAN_MARK_MOUNT로 마운트 단위 마크 후 경로 prefix 필터.
   수정 계열(FAN_MODIFY/FAN_CLOSE_WRITE)만 수집하며 원인 pid를 제공한다.
   생성/삭제/이름변경은 FAN_REPORT_FID(kernel 5.1+)가 필요해 Phase 3 eBPF에서 확장.
   에이전트 자신의 pid 이벤트는 무시한다 (백업 쓰기 피드백 루프 방지).
2. **백업·복구** — 내용 주소 저장(SHA-256, 중복 제거) + SQLite 버전 인덱스.
   복구 시 객체 해시를 재검증하고 임시 파일 + rename으로 원자적 복원.
   `prune(keep)`이 경로당 보존 버전 수를 적용하고 미참조 객체를 청소한다.
3. **중앙 서버** — axum + SQLite. 인증은 Bearer 공유 토큰(개발 단계).
   에이전트 쪽 보고는 전용 std 스레드 — 전송 실패가 탐지 파이프라인을 막지 않는다.
   Phase 4: mTLS(rustls), 정책 배포, 재전송 outbox 큐, 대시보드.
4. **AI Threat Summary** — Anthropic Messages API 직접 HTTP 호출(공식 Rust SDK 부재).
   탐지 메타데이터 + 전후 이벤트 로그만 근거로 제공하고 근거 밖 추정을 금지하는
   시스템 프롬프트 사용 (요건서 18장 hallucination 대응).

## Phase 3 진입 시 우선 작업

1. eBPF 센서 (프로세스 exec/네트워크/권한 상승 이벤트)
2. 정책 파일(서명 검증) + `argos policy` / `argos update`
3. 네트워크 격리 (`argos isolate`) + 승인 기반 대응
4. AI Copilot (자연어 질의), Threat Graph
