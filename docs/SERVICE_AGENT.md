# Argos Agent (에이전트 데몬 서비스) 상세 분석서

**Argos Agent**(`argos-agent`)는 감시 대상 호스트 시스템(Linux 서버 등)에 설치되어 상주하며 파일 시스템과 프로세스 이벤트를 실시간 포착하고, 침해 행위 스코어링을 통해 즉각적인 프로세스 차단 및 원본 캐시 백업, 중앙 관리 서버 보고를 주도하는 핵심 백그라운드 데몬 서비스입니다.

---

## 1. 주요 역할 및 책임

1. **설정 및 보안 정책 로드**: 에이전트 설정 파일(`argos.toml`)을 읽고, 암호 서명 검증을 마친 외부 정책이 존재할 경우 보안 변수를 동적 대체 적용합니다.
2. **감시 경로 베이스라인 수립**: 에이전트 기동 순간 감시 대상 디렉터리를 재귀적으로 전수 탐색하여 원본 상태의 CAS(Content-Addressed Storage) 백업 기점을 확보합니다.
3. **센서 스트림 제어**: OS 플랫폼 및 권한에 부합하는 적정 센서 모듈(notify/fanotify)을 초기화하여 Tokio 비동기 채널로 릴레이합니다.
4. **이벤트 처리 파이프라인 가동**: Tokio 비동기 멀티플렉싱 이벤트 루프를 운용하며 로깅, CAS 백업 기록, 위협 탐지 스코어링 관찰, 프로세스 자동 차단을 제어합니다.
5. **비동기 격리 리포팅**: 메인 탐지 및 차단 루프가 네트워크 대기 시간으로 인해 멈추지 않도록 독자 스레드 환경에서 중앙 서버 연동을 처리합니다.

---

## 2. 세부 컴포넌트 아키텍처 및 소스 코드 명세

### 2.1. 시동 및 초기화 제어 흐름
에이전트 데몬이 시작되면 `main.rs`의 비동기 메인 함수(`#[tokio::main] async fn main()`)가 가동됩니다.

```
[에이전트 가동] ──► argos.toml 로드 ──► policy.path 확인 ──► Ed25519 서명 검증
                                                                    │
   ┌────────────────────────────────────────────────────────────────┘
   ├─► [검증 실패] ──► 경고 출력 후 argos.toml 기본 설정 적용
   └─► [검증 성공] ──► DetectionConfig/ResponseConfig 동적 덮어쓰기 적용
                               │
                               ▼
  [감시 대상 디렉터리 준비 및 생성] ──► SQLite WAL 로컬 DB 오픈
                               │
                               ▼
  [Baseline 백업 수행] ──► 센서 스레드 기동 ──► 비동기 select! 루프 진입
```

1. **설정 암호 검증 및 동적 갱신**:
   - `config.policy`에 경로가 등록되어 있으면 [argos-policy](file:///d:/project/ArgosAISecurity/crates/argos-policy/src)의 `load_verified`를 통해 서명을 대조합니다.
   - `.sig` 서명 파일이 불일치할 경우 에이전트는 해당 구성을 거절하고 기존 설정 정보를 고수해 설정 변조 공격을 방어합니다.
2. **SQLite WAL 로컬 로깅 DB 연결**:
   - [argos-storage](file:///d:/project/ArgosAISecurity/crates/argos-storage/src) 라이브러리를 호출하여 `EventStore::open`으로 SQLite DB를 생성 및 초기화합니다.
3. **시동 기점 베이스라인 백업 (`baseline_backup`)**:
   - 감시 경로 내의 기존 파일들을 대상으로 DFS(깊이 우선 탐색) 디렉터리 순회를 하여 [argos-recovery](file:///d:/project/ArgosAISecurity/crates/argos-recovery/src)를 활용해 CAS 중복제거 백업본을 작성합니다.
   - 이를 통해 부팅 시점에 즉시 침투하여 작동하는 랜섬웨어 공격이 발생하더라도 해를 입지 않은 최초 시점으로 안전하게 원복할 수 있는 복구 지점을 제공합니다.

---

## 3. 메인 이벤트 처리 파이프라인 (`process_event`)

이벤트 수집 채널을 통해 들어온 `FileEvent`는 다음 흐름에 따라 물리적으로 순차 가공 처리됩니다.

```
[센서 채널 이벤트 수신]
        │
        ▼
[FileAction::Modify?] ──► 예 ──► file_entropy() 계산 및 entropy 변수 바인딩
        │
        ▼
[SQLite DB 기록] ──► insert_file_event()
        │
        ▼
[Create / Modify?] ──► 예 ──► BackupStore::backup() 원본 CAS 캐싱 백업
        │
        ▼
[탐지 엔진 스코어링 평가] ──► DetectionEngine::observe()
        │
        ├─► 스코어 미만? ──► [종료]
        │
        ▼
[위협 탐지 선언] ──► SQLite detections 테이블에 탐지 이력 보존
        │
        ├─► [백그라운드 리포터 채널 전송] ──► 중앙서버 전송
        │
        ▼
[auto_block == true && pid != 0 && score >= block_score?]
        │
        ├─► 예 ──► libc::kill(pid, SIGKILL) 실행 및 프로세스 강제 종료
        └─► 아니오 ──► [경고 로그 출력 후 종료 (Dry-Run)]
```

1. **엔트로피 연산**: 수정 이벤트인 경우 파일 전반부(64KB)의 Shannon 엔트로피를 동적으로 연산하여 파일 변조 및 암호화 여부의 수치 지표로 활용합니다.
2. **이벤트 로깅 및 백업**: 변경사항을 SQLite에 기록하고 백업 CAS 저장소에 데이터 해시별 중복제거 저장을 릴레이합니다.
3. **스코어링 평가**: `BehaviorScorer`의 슬라이딩 윈도우 점수가 위험 등급에 이르면 탐지 결과를 SQLite 및 중앙관리 리포터 스레드로 포워딩합니다.
4. **자동 대응**: `auto_block`이 켜져 있고 유효한 PID가 검출되면 Responder를 구동해 해당 위협 프로세스를 시그널링 차단합니다.

---

## 4. 리포터 서브시스템 (`reporter.rs`)

네트워크 전송 대기 현상(HTTP TCP 핸드셰이크 지연 등)이 에이전트의 이벤트 처리 루프를 가로막지 않도록 스레드가 완전히 격리되어 분리 운용됩니다.

* **동작 원리**:
  - `spawn` 실행 시 `std::sync::mpsc::channel`을 연결하고, `argos-reporter` 스레드를 물리 구동합니다.
  - 전송 작업은 Rust의 블로킹 HTTP 클라이언트인 `reqwest::blocking::Client`를 독립 스레드에서 직접 가동합니다.
  - 중앙 서버의 주소가 등록되어 작동하기 시작하면 `POST /api/v1/agents/register`로 에이전트 기본 정보를 제공하고, 에이전트 기동 도중 위협 발생 시 채널로 들어온 `Detection` 구조체 데이터를 JSON 구조로 포장하여 `POST /api/v1/detections`에 즉시 전송합니다.
  - 전송 실패가 발생하더라도 메인 에이전트 데몬 루프는 무해하게 작동을 지속하므로 서비스 거부 공격 및 통신 마비로 인한 탐지 정지 현상을 극복합니다.
