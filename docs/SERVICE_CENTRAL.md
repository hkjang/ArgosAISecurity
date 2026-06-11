# Argos Central (중앙관리 서버 및 대시보드) 상세 분석서

**Argos Central**(`argos-central`)은 전사 호스트 시스템들에 기동되고 있는 Argos 에이전트들로부터 실시간 정보 등록 신호 및 탐지된 보안 위해 사항들을 비동기 통합 수집(Ingest)하고, 중앙 통제용 SQLite DB 인덱스에 적재하여 관리자가 원격 브라우저에서 서버 위험도를 감사할 수 있는 관제용 경량 중앙 웹 서버 컴포넌트입니다.

---

## 1. 주요 역할 및 책임

1. **에이전트 라이프사이클 관리**: 신규 에이전트의 원격 등록 처리를 지원하고, 주기적인 신호 전송 주기를 모니터링하여 에이전트의 최종 통신 응답 시간(`last_seen_ms`)을 실시간 갱신합니다.
2. **이벤트 수집(Ingestion) 및 적재**: 다중 감염 분산 에이전트로부터 전달되는 탐지 구조체 정보를 통합 SQLite DB(`central.db`)에 영구 적재합니다.
3. **보안 API 인증**: HTTP API 전송 시 Bearer 공유 인증 토큰 대조 로직을 적용해, 불법적인 외부 공격자의 서버 오염 행위를 필터링합니다.
4. **웹 콘솔 현황판 배포**: 관제 서버 접속 시 에이전트들의 활성 여부 및 누적 위협 건수를 도식화하는 HTML 및 바닐라 JS 대시보드 인터페이스를 브라우저에 공급합니다.

---

## 2. 웹 서버 기술 스펙 및 API 명세

`argos-central`은 비동기 러스트 웹 프레임워크인 **Axum** 및 **Tokio** 비동기 런타임을 이용해 동적 서빙 포트를 바인딩합니다.

### 2.1. 웹 서버 가동 및 DB 초기화
- 프로그램 실행 시 아규먼트로 `--listen` 대기 주소, `--db` 경로, `--token` 보안 비밀을 접수합니다.
- `central.db` 데이터베이스가 존재하지 않는 경우 상위 폴더를 강제 자동 구성하여 연결을 개설하고, I/O 효율성 극대화를 위해 `journal_mode=WAL` 성능 최적화 PRAGMA 질의문을 강제 실행합니다.
- 다음 2가지의 통합 관리 테이블을 구성합니다:
  - `agents`: 에이전트 고유 식별자(`agent_id`), 호스트명, 태그 정보 JSON, 등록 시간, 최근 생존 신호 수신 시간(`last_seen_ms`).
  - `detections`: 탐지 인서트 ID, 전송 에이전트 ID, 타임스탬프, 매핑 룰 명칭, 스코어 점수, 심각도, 위협 요약문, PID, 타겟 파일 경로 목록 JSON.

---

### 2.2. REST API 엔드포인트 명세

모든 API 호출은 설정 시 Bearer 인증을 경유합니다.

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
    "timestamp_ms": 1700000000000,
    "rule": "behavior.ransomware_pattern",
    "score": 88.0,
    "severity": "critical",
    "summary": "10초 내 파일 42개 변경 (이벤트 84건, 위험 점수 88)",
    "pid": 2490,
    "paths": ["/home/user/doc1.locked", "/home/user/doc2.locked"]
  }
  ```
- **역할**: 전송받은 감염 노드의 탐지 상세 내용을 `detections` 테이블에 적재하고, 해당 에이전트 레코드의 `last_seen_ms` 상태값을 현재 시각으로 즉시 갱신 처리합니다.

#### ③ `GET /api/v1/agents` (에이전트 노드 리스트 조회)
- **응답 본문 (JSON)**:
  - 에이전트 정보 배열을 반환하며, 서브쿼리를 실행해 개별 에이전트별로 누적된 실시간 탐지 위협 수(`detection_count`)를 함께 연산해 출력합니다.

#### ④ `GET /api/v1/detections` (통합 탐지 이력 조회)
- **쿼리 파라미터**: `?limit=N` (기본값: 50)
- **역할**: 중앙 서버에 취합된 최신 위협 리스트를 지정 수량만큼 내림차순(최신순) 덤프하여 반환합니다.

---

## 3. 모던 바닐라 웹 대시보드 (`dashboard.html`)

- `argos-central` 내부에 파일 스트림 문자열 상수(`include_str!("dashboard.html")`)로 기입되어 기동 시 프로세스 메모리에 적재되어 배포됩니다.
- Tailwind CSS 등 외부 라이브러리 연동 없이도 화려한 웹 컴포넌트 렌더링이 가능하도록 Vanilla CSS Grid 및 Flexbox, 다크 모드 지향 글래스모피즘(Glassmorphism) UI를 내장했습니다.
- JavaScript `Fetch API` 비동기 요청을 활용해 5초 주기로 `/api/v1/agents` 및 `/api/v1/detections`를 폴링 조회하여, 등록 노드의 위험 상태 및 실시간 위협 통계 그래프 데이터를 갱신합니다.
- 토큰 인증 방식을 지원하도록 헤더 주입 필드를 탑재하였습니다.
