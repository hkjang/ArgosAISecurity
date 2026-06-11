# Argos 아키텍처 (MVP Phase 1)

## 컴포넌트와 크레이트 매핑

요건서 3장의 컴포넌트 중 Phase 1 범위만 구현한다.

| 요건서 컴포넌트 | 크레이트 | Phase |
| --- | --- | --- |
| Argos Agent | argos-agent | 1 |
| Argos Sensor | argos-sensor | 1 (notify) → 3 (fanotify/eBPF) |
| Argos Detect | argos-detect | 1 |
| Argos Response | argos-response | 1 (프로세스 차단만) |
| (로컬 저장) | argos-storage | 1 |
| Argos Recovery | (미착수) | 2 |
| Argos Central | (미착수) | 2 |
| Argos Brain / Copilot | (미착수) | 2~3 |

## 데이터 흐름

```
 감시 경로
    │  파일 생성/수정/삭제/이름변경/권한변경
    ▼
 argos-sensor (notify 콜백 스레드)
    │  FileEvent { ts, pid(=0), path, action, size }
    │  tokio mpsc 채널 (버퍼 8192, backpressure)
    ▼
 argos-agent 파이프라인 (tokio)
    │  1. Modify면 file_entropy() 계산 (앞 64KB 샘플)
    │  2. EventStore.insert_file_event()        ──→ SQLite (WAL)
    │  3. DetectionEngine.observe()
    │       └ BehaviorScorer: pid별 슬라이딩 윈도우(10s) 점수
    │  4. 점수 ≥ detect_score → Detection 저장   ──→ SQLite
    │  5. 점수 ≥ block_score && pid != 0 && auto_block
    │       └ Responder.execute(KillProcess)
    ▼
 argos-cli (read-only SQLite)
      status / events / threats / scan / doctor
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

## Phase 2 진입 시 우선 작업

1. fanotify 센서 (pid 확보) → 프로세스 단위 점수·차단 활성화
2. 변경 전 백업(copy-on-write 저장소) + `argos restore`
3. 중앙 서버 전송 큐 (mTLS, gRPC) — storage에 outbox 테이블 추가
4. AI Threat Summary — Detection + 근거 이벤트를 LLM에 RAG로 전달
