# Argos CLI (관리자 명령행 도구) 상세 분석서

**Argos CLI**(`argos-cli`)는 관리자가 Argos 에이전트의 작동 상태를 즉각 모니터링하고, 수집된 감사 로그와 침해 위협을 현장에서 추적 및 분석하며, 비정상 암호화 피해가 발생한 파일을 원본 버전으로 원복하고 정책 설정을 서명 배포하는 고기능 콘솔 통제 도구(바이너리명: `argos`)입니다.

---

## 1. 주요 역할 및 책임

1. **상태 모니터링 및 진단**: 에이전트 구성 변수 상태 및 로컬 DB 파일 누적 지표를 조회하고(`status`), 시스템 헬스체크 및 API 환경을 진단합니다(`doctor`).
2. **이벤트 로그 및 위협 추적**: 로컬 디렉터리에 적재된 SQLite 감사 레코드를 파싱하여 최근 활동 및 정밀 위협 목록을 화면에 렌더링합니다(`events`, `threats`).
3. **AI 기반 침해 요약 분석**: 로컬 DB 윈도우 시점의 로그를 슬라이스해 컨텍스트를 구성하고 Claude API에 전송하여 심층 원인 보고서를 요청합니다(`explain`, `ask`).
4. **암호화 피해 파일 롤백**: CAS 백업본의 해시 무결성을 현장에서 직접 검산하고 덮어씌워 파일 원복을 단행합니다(`restore`).
5. **네트워크 단절 통제**: 비정상 연결 프로세스 차단 및 아웃바운드 패킷 방어를 iptables 체인을 생성해 수동 적용하거나 롤백합니다(`isolate`).
6. **Ed25519 설정 정책 서명**: 정책 설정 구성에 전자 서명 파일(`.sig`)을 날인하여 변조된 공격을 무력화하는 무결성 서명 정책을 빌드합니다(`policy`).

---

## 2. CLI 서브커맨드 상세 명세 및 동작 원리

`argos-cli`는 사용자 명령어 인자 분기를 위해 `clap` 파서를 탑재하였으며, 에이전트 서비스와 리소스를 유기적으로 분담합니다.

### 2.1. `status` & `doctor`
- **`status`**:
  - 에이전트 설정상의 SQLite DB 경로와 감시 대상 경로 목록, 백업 CAS 위치, 자동 차단 기능 활성 여부 등을 가독성 있게 정렬합니다.
  - 에이전트 DB와의 잠금 충돌을 회피하기 위해 `rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY` 플래그로만 DB를 열어 누적된 이벤트 카운트를 출력합니다.
- **`doctor`**:
  - OS 계층 정보(Windows/Linux 등), 설정 파일과 SQLite DB 및 CAS 디렉터리 접근 가능 권한 유무를 검사합니다.
  - AI 분석용 환경 변수인 `ANTHROPIC_API_KEY` 탑재 상태 및 비 Linux 여부에 따른 커널 제약 사양을 리포트합니다.

### 2.2. `events` & `threats` & `processes`
- **`events`**:
  - `EventStore::recent_events`를 호출하여 최신 수집된 파일 액션(생성, 수정, 삭제, 이름변경) 이력을 시간순 테이블 포맷으로 나열합니다.
- **`threats`**:
  - `EventStore::recent_detections_with_id` 쿼리를 실행해 탐지된 침해 패턴 목록을 출력합니다. 각 레코드는 고유 ID 번호 및 점수, 위협 레벨을 표기합니다.
- **`processes`** (Linux 전용):
  - 프로세스 모니터가 수집한 신규 Exec 실행 로그(`/proc` 스캔 결과)를 출력해 관리자가 위협 시점 전후에 가동된 비정상 명령행(`cmdline`)을 매핑할 수 있게 돕습니다.

### 2.3. `explain` & `ask`

`explain <ID>`는 탐지 시간창과 이후 5초의 근거를 조회한다. 다중 시간 구간 규칙은 설정된 가장 긴 시간창을 포함한다. `ask`는 질문에서 해석한 기간 또는 명시한 `--from-ms`/`--to-ms`와 선택 PID로 조회한다. 근거 ID·종류별 전체 건수·상한으로 인한 누락과 대응 결과를 AI에 전달한다. 제공자·주소·모델은 설정하며 상세한 범위는 [AI/조사 문서](FEATURE_AI.md)를 따른다.

### 2.4. `restore` (내용 주소 지정 백업 복구)
- 사용자가 복구를 희망하는 대상 경로와 선택 매개변수(`--before-ms` 등)를 확인합니다.
- 복구 엔진인 [argos-recovery](file:///d:/project/ArgosAISecurity/crates/argos-recovery/src)를 로컬 직접 열어 versions 테이블을 조회합니다.
- `--list` 옵션 지정 시 해당 파일의 과거 누적 백업 해시와 타임스탬프 이력을 조회하여 표출합니다.
- 복구 명령 발동 시 CAS 객체의 데이터를 로드해 SHA-256 해시 무결성을 재검수하여, 백업 데이터 자체가 오염되거나 임의 변조되었을 시 복구 절차를 즉시 에러로 중단하고 방어합니다. 검증 성공 시 원자적 파일 rename 교체를 통해 롤백을 단행합니다.

### 2.5. `isolate` (네트워크 차단 격리)
- `iptables` 호출 유틸리티를 호출합니다 (리눅스 전용, 루트 권한 필요).
- `--release` 유무를 체크하여 `ARGOS_ISOLATE` 체인을 생성하여 OUTPUT 체인에 인서트하거나 소거 롤백을 처리합니다.

### 2.6. `policy` (Ed25519 설정 무결성 서명)
- **`gen-key`**: Ed25519 타원곡선 키쌍을 생성해 콘솔에 출력합니다. 서명키는 로컬 파일(예: `signing.key`)로 안전 보관하고 검증키는 `argos.toml`의 `[policy.trusted_keys]`에서 키 ID에 연결합니다.
- **`sign`**: 대상 `policy.toml` 파일 바이트 전체와 서명키 파일을 로드해 전자 서명을 연산하고 동명의 서명 파일 `policy.toml.sig`를 생성합니다.
- **`verify`**: 서명 정책 파일과 `.sig` 파일을 검증키로 대조하여 정형 변조 여부를 1차 검증합니다.
- **`show`**: 에이전트에 현재 로드되어 실 작동하고 있는 설정 정책의 세부 사항 및 검증 성공 상태를 표시합니다.


## 검증 가능한 대응·복구 명령 (2026-09)

- `policy simulate --candidate PATH --from-ms N --to-ms N [--max-events N]`: 기존/후보 정책을 저장 근거에 재생한다. 실제 차단이나 적용은 없다.
- `restore PATH --list`: 무결성과 별개인 정상 판정 상태/근거를 확인한다.
- `restore PATH --mark-good ID --note TEXT`, `--revoke-good ID --note TEXT`: 정상 판정 지정/취소.
- `restore PATH --version ID --preview NEW_PATH`: 미검토 버전도 별도 새 파일로 검사한다.
- `restore PATH [--before-ms N]`: 지정 구간의 정상 판정 버전만 복구한다. 미검토 최신본으로 자동 대체하지 않는다.
- `recovery-status [--test PATH] [--html NEW_PATH]`: 복구 준비도와 원본 유지 복구 시험. 중요 경로의 현재 파일 중 미기록 파일도 표시하며, 10,000개 경로 검사 상한/접근 실패는 부분 검사로 알린다.
- `evidence`, `ask`, `mcp`, `incident`: [AI/조사 문서](FEATURE_AI.md) 참조.
- `canary-init ABSOLUTE_PATH`: 설정된 미끼 파일을 기존 파일 덮어쓰기 없이 만든다. 센서 시작 전에 설치한다.
- `isolate --allow in:192.0.2.20:22 --allow out:10.0.0.5:8420 --dry-run`: 격리 계획 출력. 적용·해제는 [격리 문서](FEATURE_RESPONSE.md) 참조.

잘못된 TOML 설정은 기본값으로 무시하지 않고 오류로 종료한다. `status`는 로컬 생존 신호 시각과 큐/백업/센서 지표를 표시한다. 오래된 신호나 기록 없음은 안전하다는 의미가 아니다.


## 정책 신뢰·사건 보존·증거 패키지

- `argos policy status --limit 100`: 마지막 수락 정책과 거부/재시작/롤백 감사 기록. `policy show`는 후보 파일 대신 마지막 수락 원문을 조회한다.
- `argos retention pin PATH --version ID --incident INC --actor USER --reason TEXT`: 정상 판정과 별도로 사건 보존 참조를 추가한다.
- `argos retention list --incident INC`, `argos retention audit --incident INC`: 활성 참조와 감사 이력.
- `argos retention release --incident INC --approval APPROVAL_ID --approver USER --reason TEXT`: 별도 승인 근거로 사건 참조 해제.
- `argos evidence-export ID --out NEW_DIR`: 기본 마스킹을 적용한 사건 증거 패키지.
- `argos evidence-verify DIR`: 파일 목록·크기·SHA-256 검증.

상세 조건은 [정책 신뢰](FEATURE_POLICY.md), [복구 보존](FEATURE_RECOVERY.md), [증거 패키지](FEATURE_EVIDENCE_PACKAGE.md)를 참고한다.
