# Argos 아키텍처 (MVP Phase 1 + Phase 2)

## 컴포넌트와 크레이트 매핑

| 요건서 컴포넌트 | 크레이트 | Phase |
| --- | --- | --- |
| Argos Agent | argos-agent | 1 |
| Argos Sensor | argos-sensor | 1 (notify) + 2 (fanotify) → 3 (eBPF) |
| Argos Detect | argos-detect | 1 |
| Argos Response | argos-response | 프로세스 신원 확인 차단·IPv4/IPv6 격리 |
| (로컬 저장) | argos-storage | 1 |
| Argos Recovery | argos-recovery | 백업·정상본 판정·미리보기·복구 시험 |
| Argos Central | argos-central | 2 (등록/수집/조회 API) |
| Argos Brain / Copilot | argos-brain + argos-cli | AI 분석·기간 질의·조회형 MCP |

## 데이터 흐름

```
 감시 경로
    │  파일 생성/수정/삭제/이름변경/권한변경
    ▼
 argos-sensor (백엔드 선택: sensor 설정)
    │  notify   : 크로스 플랫폼, pid=0
    │  fanotify : Linux+root, 수정 이벤트에 원인 pid 포함
    │  FileEvent { ts, pid, path, action, size }
    │  tokio mpsc 채널 (버퍼 8192, 포화 시 유실 계수)
    ▼
 argos-agent 파이프라인 (tokio)
    │  1. Modify면 file_entropy() 계산 (앞 64KB 샘플)
    │  2. DetectionEngine.evaluate(): 센서별 점수 + 승인 작업 맥락
    │  3. 알림 억제와 독립적으로 매 이벤트 대응 판단
    │       └ 신원 일치 시 pidfd 종료 + 결과 확인
    │  4. 이벤트·탐지·대응 결과 감사 저장      ──→ SQLite (WAL)
    │  5. 탐지 전달 outbox 기록               ──→ 디스크 재전송 큐
    │  6. Create/Modify 백업 작업 큐          ──→ 별도 작업자·I/O 예산
    ▼                                ▼
 argos-cli                      reporter 스레드 (std thread + blocking HTTP)
   status/events/threats          │ POST /api/v1/detections (Bearer)
   scan/doctor                    ▼
   restore  ← argos-recovery   argos-central (axum + SQLite)
   explain  ← argos-brain        에이전트 등록 / 탐지 수집 / 현황 조회
              (Anthropic / Ollama)
```

## 위험 점수 모델

윈도우(기본 10초) 내에서:

| 요소 | notify | fanotify | 근거 |
| --- | --- | --- | --- |
| 변경 파일 수 / mass_change_threshold | 최대 40점 | 최대 40점 | 랜섬웨어의 대량 파일 변경 |
| 고엔트로피(≥7.2) 파일 비율 | 최대 35점 | 최대 60점 | 암호화 데이터의 엔트로피 증가 |
| 이름 변경 + 삭제 비율 | 최대 25점 | 수집하지 않음 | 확장자 변경(.locked 등), 원본 삭제 |

미끼 파일 변경은 별도 95점 신호이며, 센서별 도달 불가능한 임계치는 시작 시 경고한다.

Severity: 40+ Medium, 65+ High, 85+ Critical.
요건서 8장의 나머지 요소(프로세스 신뢰도, 사용자 권한, 자산 중요도)는 fanotify pid 확보 후(Phase 2~3) 추가한다.

## 주요 설계 결정

1. **notify 우선, fanotify 나중** — 요건서 18장 "커널 버전 호환성: fanotify 기본, eBPF 선택 적용"의 전 단계.
   notify는 pid를 못 주므로 Phase 1의 자동 차단은 사실상 dry-run이다.
   `argos-sensor`의 공개 API는 `spawn_sensor(kind, paths, tx)`로 백엔드를 선택한다.
2. **SQLite + WAL** — 요건서 7장 "SQLite 또는 RocksDB" 중 SQLite 선택.
   CLI가 데몬과 동시에 read-only로 열 수 있고, 운영 디버깅이 쉽다.
   초당 20,000 이벤트 요건은 Phase 2에서 배치 insert + 이벤트 필터링으로 대응.
3. **자동 차단 기본 비활성** — 요건서 18장 1순위 리스크(오탐으로 인한 업무 중단) 대응.
   `auto_block=true` + Linux + PID·시작 ticks·부팅 ID 일치가 모두 충족될 때만 pidfd로 SIGKILL 후 종료를 확인한다.
   pid 0 차단 요청은 Responder가 무조건 거부한다 (kill(0)은 프로세스 그룹 전체 시그널 — 자살 방지).
4. **워크스페이스 분리** — 컴포넌트 경계 = 크레이트 경계. Phase 2의 Central/Recovery/Brain도 같은 패턴으로 크레이트 추가.

## Phase 2 구현 메모

1. **fanotify 센서** — FAN_MARK_MOUNT로 마운트 단위 마크 후 경로 prefix 필터.
   수정 계열(FAN_MODIFY/FAN_CLOSE_WRITE)만 수집하며 원인 pid를 제공한다.
   생성/삭제/이름변경은 FAN_REPORT_FID(kernel 5.1+)가 필요해 Phase 3 eBPF에서 확장.
   에이전트 자신의 pid 이벤트는 무시한다 (백업 쓰기 피드백 루프 방지).
2. **백업·복구** — 내용 주소 저장(SHA-256, 중복 제거) + SQLite 버전 인덱스.
   기존 버전과 시작 시 baseline은 미검토로 보존하며, `restore --mark-good --note`로 정상 판정한 버전만 원본에 복구한다. 별도 경로 미리보기와 복구 시험을 지원한다.
   복구 시 객체 해시를 재검증하고 임시 파일 + rename으로 원자적 복원한다. 해시 일치가 정상 내용을 보증하지 않는다.
   `prune(keep)`은 경로당 미검토 버전 수를 제한하되, 정상 판정 버전은 명시적 취소 전 보존한다.
3. **중앙 서버** — axum + SQLite. 운영 인증은 관리자 조회/에이전트별 수집 Bearer 토큰을 분리하며, 무인증 개발 모드는 loopback으로 제한한다.
   에이전트 쪽 보고는 전용 std 스레드와 디스크 outbox를 사용하고 중앙은 전달 ID로 중복 제거한다. 생존 신호·센서 상태를 대시보드에서 조회한다.
   mTLS와 중앙 자동 정책 배포는 후속 과제다. HTTPS는 별도 TLS 프록시에서 구성한다.
4. **AI 분석·질의** — Anthropic/Ollama 제공자·주소·모델을 설정한다.
   기간·PID별 실제 저장 근거와 ID·조회 누락을 제공하고 근거 밖 추정을 금지하는 시스템 프롬프트를 사용한다. CLI에는 조회형 MCP와 사건 HTML 보고서가 있다.

## Phase 3 진입 시 우선 작업

1. eBPF 센서 (프로세스 exec/네트워크/권한 상승 이벤트)
2. 서명 정책의 중앙 자동 배포 (로컬 서명 검증·정책 재생은 구현)
3. 관리자 승인 워크플로 (명시적 관리 연결만 허용하는 IPv4/IPv6 격리는 구현)
4. 네트워크 이벤트 통합 Threat Graph와 운영 조사 시간 실측
