# Argos Central (중앙관리 서버 및 대시보드) 상세 분석서

**Argos Central**(`argos-central`)은 전사 호스트 시스템들에 기동되고 있는 Argos 에이전트들로부터 실시간 정보 등록 신호 및 탐지된 보안 위해 사항들을 비동기 통합 수집(Ingest)하고, 중앙 통제용 SQLite DB 인덱스에 적재하여 관리자가 원격 브라우저에서 서버 위험도를 감사할 수 있는 관제용 경량 중앙 웹 서버 컴포넌트입니다.

v0.2.0은 등록·탐지 수집·생존 신호·현황 조회를 제공한다. 원격 정책 배포·차단·복구·
전체 이벤트 검색 API는 제공하지 않는다. 사건 원본과 자격 근거는 해당 호스트의
[CLI](SERVICE_CLI.md)로 조회한다.

---

## 1. 주요 역할 및 책임

1. **에이전트 라이프사이클 관리**: 신규 에이전트의 원격 등록 처리를 지원하고, 주기적인 신호 전송 주기를 모니터링하여 에이전트의 최종 통신 응답 시간(`last_seen_ms`)을 실시간 갱신합니다.
2. **이벤트 수집(Ingestion) 및 적재**: 여러 호스트의 에이전트로부터 전달되는 탐지·보호 상태 알림을 통합 SQLite DB(`central.db`)에 영구 적재합니다.
3. **보안 API 인증**: 관리자 조회 토큰과 에이전트별 수집 토큰을 분리합니다. 에이전트는 자신의 ID로 등록·수집·생존 신호 전송만 할 수 있습니다.
4. **웹 콘솔 현황판 배포**: 관제 서버 접속 시 에이전트들의 활성 여부 및 누적 위협 건수를 도식화하는 HTML 및 바닐라 JS 대시보드 인터페이스를 브라우저에 공급합니다.

---

## 2. 웹 서버 기술 스펙 및 API 명세

`argos-central`은 비동기 러스트 웹 프레임워크인 **Axum** 및 **Tokio** 비동기 런타임을 이용해 동적 서빙 포트를 바인딩합니다.

### 2.1. 웹 서버 가동 및 DB 초기화
- 프로그램 실행 시 `--listen` 대기 주소, `--db` 경로, 관리자 토큰(`ARGOS_CENTRAL_TOKEN` 또는 `--token`), `--agent-tokens` JSON 파일 경로를 접수합니다. 운영 모드는 관리자 토큰과 에이전트별 서로 다른 토큰이 모두 필요합니다.
- `--agent-tokens` 파일 형식은 `{"agent-db-01":"<해당 에이전트 전용 토큰>"}`입니다. 인증 없는 개발 모드는 `--development --listen 127.0.0.1:8420`처럼 loopback 주소에서만 실행할 수 있습니다. HTTPS는 별도 TLS 프록시에서 구성합니다.
- 기본 수신 주소는 `0.0.0.0:8420`, 기본 DB는 `./argos-central-data/central.db`다. 인증 없는 개발에서는 기본 수신 주소를 그대로 쓸 수 없으므로 loopback을 명시한다. 토큰 파일은 시작 시 읽으며 변경 적용에는 재시작이 필요하다.
- `central.db` 데이터베이스가 존재하지 않는 경우 상위 폴더를 강제 자동 구성하여 연결을 개설하고, I/O 효율성 극대화를 위해 `journal_mode=WAL` 성능 최적화 PRAGMA 질의문을 강제 실행합니다.
- 다음 2가지의 통합 관리 테이블을 구성합니다:
  - `agents`: 에이전트 고유 식별자(`agent_id`), 호스트명, 태그 정보 JSON, 등록 시간, 최근 통신 시간(`last_seen_ms`), 마지막 생존 신호(`last_heartbeat_ms`), 보호 상태 및 전송 대기·실패 건수.
  - `detections`: 탐지 인서트 ID, 전송 에이전트 ID, 타임스탬프, 매핑 룰 명칭, 스코어 점수, 심각도, 위협 요약문, PID, 타겟 파일 경로 목록 JSON과 중복 제거용 `delivery_id`.

---

### 2.2. REST API 엔드포인트 명세

운영 모드의 `/api/v1` 요청은 Bearer 인증을 거칩니다. POST에는 본문의 `agent_id`에 해당하는 에이전트 토큰, GET에는 관리자 토큰을 사용합니다. `/healthz`와 대시보드 HTML 자체는 인증 없이 접근할 수 있으며, 대시보드 데이터 조회에는 관리자 토큰이 필요합니다.

#### ① `POST /api/v1/agents/register` (에이전트 등록)
- **요청 본문 (JSON)**:
  ```json
  {
    "agent_id": "hostname-uuid",
    "hostname": "linux-prod-db-01",
    "tags": ["prod", "database"]
  }
  ```
- **역할**: 에이전트 등록 요청을 수신해 SQLite `agents` 테이블에 인서트합니다. 만약 동일 에이전트 ID가 존재하는 경우 `ON CONFLICT(agent_id) DO UPDATE` 구문을 동작시켜 호스트명과 태그, 생존 시간 정보를 업데이트합니다.

#### ② `POST /api/v1/detections` (위협 정보 Ingest)
- **요청 본문 (JSON)**:
  ```json
  {
    "agent_id": "hostname-uuid",
    "delivery_id": "hostname-uuid-delivery-1",
    "timestamp_ms": 1700000000000,
    "rule": "behavior.ransomware_pattern",
    "score": 88.0,
    "severity": "critical",
    "summary": "10초 내 파일 42개 변경 (이벤트 84건, 위험 점수 88)",
    "pid": 2490,
    "paths": ["/home/user/doc1.locked", "/home/user/doc2.locked"]
  }
  ```
- **역할**: 먼저 등록된 에이전트의 탐지 상세 내용을 `detections` 테이블에 적재하고, 해당 에이전트의 `last_seen_ms`를 갱신합니다. 동일 에이전트의 동일 `delivery_id` 재전송은 중복 적재하지 않습니다. 이전 에이전트는 `delivery_id`를 생략할 수 있지만 중복 제거를 제공받지 못합니다.

#### ③ `GET /api/v1/agents` (에이전트 노드 리스트 조회)
- **응답 본문 (JSON)**:
  - 에이전트 정보 배열을 반환하며, 서브쿼리를 실행해 개별 에이전트별로 누적된 실시간 탐지 위협 수(`detection_count`)를 함께 연산해 출력합니다.

#### ④ `GET /api/v1/detections` (통합 탐지 이력 조회)
- **쿼리 파라미터**: `?limit=N` (기본값: 50, 1~1,000 범위로 제한)
- **역할**: 중앙 서버에 취합된 최신 탐지의 `agent_id`, `timestamp_ms`, `rule`, `score`, `severity`, `summary`를 반환합니다. 로컬 탐지 ID·PID·경로·전체 원본 이벤트를 조회하는 API는 아닙니다.

#### ⑤ `POST /api/v1/agents/heartbeat` (생존 신호)
- **요청 본문**: `agent_id`, `sensor_healthy`, `outbox_pending`, `failed_attempts`.
- **역할**: 등록된 에이전트의 생존 시각과 보호·재전송 상태를 갱신합니다. `/api/v1/agents`와 대시보드는 이 정보로 통신 단절과 보호 저하를 표시합니다.
- 에이전트는 기본 30초마다 보고합니다. `last_seen_ms`는 등록·탐지·생존 신호로 갱신하며 최근 60초까지 `online`, 60초 초과~120초까지 `stale`, 120초 초과는 `offline`입니다. `last_heartbeat_ms`와 `sensor_healthy`도 함께 확인합니다.
- `sensor_healthy`에는 센서뿐 아니라 로컬 분석·의미 감시·정책 기간·사건 보존 상태가 반영됩니다. 세부 `backup.pin_*`와 `policy` 지표는 중앙 본문에 포함하지 않으므로 해당 호스트의 `status`에서 확인합니다.

---

## 3. 모던 바닐라 웹 대시보드 (`dashboard.html`)

- `argos-central` 내부에 파일 스트림 문자열 상수(`include_str!("dashboard.html")`)로 기입되어 기동 시 프로세스 메모리에 적재되어 배포됩니다.
- Tailwind CSS 등 외부 라이브러리 연동 없이도 화려한 웹 컴포넌트 렌더링이 가능하도록 Vanilla CSS Grid 및 Flexbox, 다크 모드 지향 글래스모피즘(Glassmorphism) UI를 내장했습니다.
- JavaScript `Fetch API` 비동기 요청을 활용해 5초 주기로 `/api/v1/agents` 및 `/api/v1/detections`를 폴링 조회하여, 등록 노드의 위험 상태 및 실시간 위협 통계 그래프 데이터를 갱신합니다.
- 토큰 인증 방식을 지원하도록 헤더 주입 필드를 탑재하였습니다.


## 운영·개발 실행 예

운영 모드에서는 관리자 토큰을 `ARGOS_CENTRAL_TOKEN`에 설정하고 에이전트 ID별 토큰을
제한된 JSON 파일로 준비한다. 아래 운영 예는 같은 호스트의 TLS 프록시 뒤에서 수신한다.

```bash
argos-central --listen 127.0.0.1:8420 --db /var/lib/argos-central/central.db \
  --agent-tokens /etc/argos/agent-tokens.json
# 별도의 로컬 개발 환경: 인증 없이 loopback에서만 수신
argos-central --development --listen 127.0.0.1:8420
```

`/healthz`는 HTTP 서버가 응답함을 확인하며 에이전트의 센서·백업·차단 성공을 검증하지 않는다.
자체 TLS/mTLS와 자동 토큰 회전은 제공하지 않는다. 인증 구성은
[보안 관리자](ROLE_ADMINISTRATOR.md), 재시도·중복 제거는 [전송 신뢰성](FEATURE_RELIABILITY.md)을 따른다.
