# Argos 보안 관리자(Security Administrator) 운영 가이드

이 문서는 Argos AI Security 플랫폼의 보안 정책을 수립, 서명 및 배포하고, 전체 시스템 노드의 관제 매개변수를 제어하는 **보안 관리자(Security Administrator)**를 위한 상세 운영 매뉴얼입니다.

v0.7.0 기준이다. 실제 가동·복구는 [운영자](ROLE_OPERATOR.md), 사건 근거·격리는
[분석가](ROLE_ANALYST.md)와 연결한다. 이 역할 구분은 업무 안내이며 CLI의 사용자별
RBAC 기능을 뜻하지 않는다. 로컬 설정·DB 접근은 OS 계정과 파일 권한으로 통제한다.

---

## 1. 역할 정의 및 업무 범위

보안 관리자는 Argos 시스템의 암호학적 무결성을 수립하고, 비인가 에이전트 및 변조 정책의 침투를 방어하는 핵심 통제 책임자입니다.
- **주요 책임**:
  - 보안 정책 구성 파일(`policy.toml`)의 위협 탐지 및 자동 대응 파라미터 튜닝.
  - Ed25519 타원곡선 서명 키 쌍의 보안 관리.
  - 정책 서명 파일(`.sig`) 날인 및 배포 통제.
  - 중앙 관리 서버 연동 및 에이전트 통신 토큰 관리.

---

## 2. 정책 무결성 및 암호 서명 프로세스 가이드

에이전트 노드의 무단 정책 조작을 차단하기 위해 서명 절차를 반드시 수반해야 합니다. 비밀 키는 항상 안전한 별도의 관리 머신에만 은닉 보관해야 합니다.

### 2.1. 서명 키 쌍 생성
1. 에이전트 통제용 신규 암호화 키 쌍을 생성합니다.
   ```bash
   argos policy gen-key
   ```
2. 출력되는 키 항목을 격리 수집합니다:
   - **서명키 (비밀키)**: 외부 노출이 완전히 금지되는 32바이트(hex 64자) 키입니다. 관리자 전용 금고 머신에 텍스트 파일(예: `signing.key`)로 영구 저장합니다.
   - **검증키 (공개키)**: 각 서버의 `argos.toml`에 키 ID와 함께 `[policy.trusted_keys]`로 배포합니다. 이전 `policy.pubkey`만 있는 설정은 CLI의 서명 확인용이며 운영 활성화에는 사용할 수 없습니다.

서버의 로컬 신뢰 설정 예시입니다. 공개키와 서버·그룹 ID를 실제 배포 대상에 맞게 지정합니다.

```toml
[policy]
path = "/etc/argos/policy.toml"
policy_id = "production"
host_id = "agent-db-01"
groups = ["database"]

[policy.trusted_keys]
release-2026 = "<Ed25519 공개키 hex 64자>"
```

### 2.2. 정책 구성서 (`policy.toml`) 작성
[정책 신뢰 문서의 전체 정책 예제](FEATURE_POLICY.md#서명과-활성화)를 사용합니다. 탐지·대응 설정 외에 정책 ID, 키 ID, 버전, 발급·시작·만료 시각, 대상 호스트 또는 그룹이 필요합니다. 예제의 시각은 형식 안내이므로 실제 배포 기간으로 바꿉니다. 호스트와 그룹을 모두 지정하면 두 조건이 모두 일치해야 합니다.

`version`은 마지막 수락 버전보다 높게 지정하며, 같은 버전·같은 바이트만 재시작 복원으로 허용합니다. `auto_block=false`로 관찰·정책 재생을 확인한 뒤 소수 서버에서 자동 차단을 검증합니다. 서명이 유효해도 기간·대상·키·버전이나 설정이 잘못되면 시작을 거부합니다. 검증 실패 시 로컬 기본 정책으로 전환하지 않습니다. 서명 정책은 탐지·대응 설정을 덮어쓰며, 감시 경로·백업·중앙 인증·`semantic.files` 등 나머지 로컬 설정까지 서명하는 것은 아닙니다.

### 2.3. 정책 날인 서명 실행
비밀 서명키가 들어 있는 경로를 활용해 `policy.toml` 파일에 암호 증명을 날인합니다:
```bash
argos policy sign policy.toml --key-file signing.key
```
- 실행 완료 시, 타겟 경로 하위에 정형 서명 파일인 `policy.toml.sig`가 즉시 생성됩니다.
- 정책 배포 시 원본 `policy.toml`과 함께 `policy.toml.sig` 파일이 타겟 에이전트 서버의 지정 디렉터리에 반드시 동시 안착되어야 합니다.
- `argos --config argos.toml policy verify`는 읽기 전용 검증입니다. 영속 버전 검사와 활성화는 에이전트 시작 시 실행하며, `policy status`에서 수락 결과를 확인합니다. 이전 설정 이전·키 교체·새 버전으로 승인된 롤백·전용 상태 경로 권한은 [정책 신뢰 문서](FEATURE_POLICY.md)를 따릅니다.

### 2.4. 배포 전 비교와 수락 결과 확인

기존 정책을 운영 중인 호스트에서 후보를 저장 이벤트에 재생합니다. 아래 시각은 실제
비교 기간으로 바꿉니다. `policy simulate`는 프로세스를 종료하거나 정책을 적용하지 않습니다.

```bash
argos --config /etc/argos/argos.toml policy simulate --candidate candidate-policy.toml \
  --from-ms 1760000000000 --to-ms 1760086400000 --max-events 100000
argos --config /etc/argos/argos.toml policy status --limit 100
argos --config /etc/argos/argos.toml policy show
```

서명 정책이 설정된 호스트는 마지막 **수락** 원문을 비교 기준으로 사용하며 수락 상태가
없으면 실패합니다. 첫 배포의 관찰 시험은 서명 정책을 구성하기 전의 로컬 설정으로
별도 시험 환경에서 수행할 수 있습니다. `coverage`의 누락과 후보의 `threshold_targets`,
`would_block_pids`, `aggregate_alerts`를 함께 확인합니다. 집계 알림을 PID 종료 대상으로
해석하지 않습니다.

승인한 파일과 서명을 설치하고 운영 절차에 따라 에이전트를 재시작한 뒤 수락 버전·해시와
가동·보호 상태를 다시 확인합니다. 중앙 서버가 자동 배포하거나 실행 중 정책을 교체하지는
않습니다. 실행 중 정책이 만료되면 자동 차단은 중단되고 탐지는 유지됩니다. 만료 시각을
갱신한 더 높은 버전의 정책을 서명·배포하여 재시작합니다.

### 2.5. 사건 보존 승인과 추가 탐지 범위

[사건 고정](FEATURE_RECOVERY.md)은 정상본 판정과 별도입니다. 자동 고정 대기가 끝났는지
`retention list --incident detection-<탐지 ID>`로 확인하고, 해제에는 최초 요청자와 다른
승인자·새 승인 ID·사유를 남깁니다. 입력한 승인자 이름은 외부 ITSM 인증을 대신하지 않습니다.

다중 시간창·부분 암호화 표본은 [탐지 설정](FEATURE_DETECTION.md)에서 명시적으로 켭니다.
[Linux 의미 분석](FEATURE_LINUX_ANALYSIS.md)은 감시 범위 안의 파일을 별도로 지정해야
합니다. [시나리오 검증](../scripts/security-scenarios.py)으로 정상 주석 변경·설정 변화·정책
재적용 거부·사건 보존을 확인한 뒤 배포 범위를 늘립니다.

---

## 3. 중앙 관리 관제 연동 제어

전사 에이전트의 실시간 수집 인프라를 통제하기 위해 중앙 서버 설정을 조율합니다.

1. **관리자·에이전트별 토큰 인증 수립**:
   - 조회용 관리자 토큰을 `ARGOS_CENTRAL_TOKEN` 환경변수로 설정하고, 관리자 토큰 및 다른 에이전트 토큰과 서로 다른 토큰을 `/etc/argos/agent-tokens.json`에 저장합니다. 파일 형식은 `{"agent-db-01":"<에이전트 전용 토큰>"}`입니다. 파일과 환경변수의 접근 권한을 관리자에게 제한합니다.
     ```bash
     argos-central --listen 0.0.0.0:8420 --agent-tokens /etc/argos/agent-tokens.json
     ```
   - 운영 통신에는 별도 TLS 프록시로 HTTPS를 구성합니다. 인증 없는 로컬 개발은 `argos-central --development --listen 127.0.0.1:8420`으로 명시합니다.
2. **에이전트 연동 활성화**:
   - 배포 대상 에이전트 노드들의 `argos.toml` 내에 중앙 제어 연결 정보를 등록합니다:
     ```toml
     [central]
     url = "https://<중앙서버TLS주소>"
     token = "<agent-tokens.json의 agent-db-01 전용 토큰>"
     agent_id = "agent-db-01"            # 빈칸 시 호스트명 자동 매핑
     ```
   - 에이전트가 `/api/v1/agents/register`로 등록한 뒤 `/api/v1/agents/heartbeat`로 생존·센서·재전송 상태를 보냅니다. 대시보드 조회에는 관리자 토큰을 입력합니다.

중앙 관리자 토큰은 조회 권한이며 에이전트 등록·수집에 사용하지 않습니다. 에이전트 토큰은 다른 ID나 관리자 조회에 사용할 수 없습니다. 중앙 API는 원격 정책 배포·복구·프로세스 종료를 제공하지 않습니다. [중앙 서비스](SERVICE_CENTRAL.md)에 API 범위와 연결 상태 해석을 설명합니다.

## v0.3.0 추가 확인

예외 정리 전 [정책 예외 감사](FEATURE_EXCEPTION_AUDIT.md)의 기간·누락·예외 제거 차이를 확인한다. [보관 서버](FEATURE_REMOTE_VAULT.md)는 에이전트 업로드 토큰과 관리자 조회 토큰·서명키를 분리해 운영한다.

## v0.4.0 보관 운영 정책

[서버·에이전트별 한도](FEATURE_VAULT_CAPACITY.md)와 최소 디스크 여유를 정한다. 부분 게시나 알 수 없는 파일로 신규 쓰기가 막혔을 때 자동 삭제로 정상 자료를 잃지 않도록 정합성을 검토한다. [전송 큐](FEATURE_VAULT_QUEUE.md)의 완료 수신증명 이력 보존·큐 교체 절차도 정한다. 복구 보고서 허용 나이는 업무별로 지정하며 무서명 보고서 재검증을 실행 출처 인증으로 간주하지 않는다.

v0.5.0부터 [예약 전송](FEATURE_VAULT_SCHEDULER.md)을 선택 설치할 수 있다. pending/leased/failed 상태와 archive 예약 슬롯을 점검하고, 완료 수신증명은 [별도 내보내기](FEATURE_VAULT_QUEUE.md)로 보관한다. 업그레이드 전에 구버전 작업자를 모두 종료한다.


## v0.7.0 원격 복구 판정 관리

[복구 묶음](FEATURE_RECOVERY_BUNDLE.md)의 업로드와 관리자 조회/검토 토큰을 분리한다. 보관 완료만으로 정상본이 되지 않으므로 구성 목록·계획·업무 내용을 검토한 뒤 `vault bundle review --decision good`를 실행한다. 취소는 새 request-id의 revoked 기록이며 실패 응답을 적용 성공으로 취급하지 않는다. 로컬 정상본 취소는 자동 전파되지 않는다.

서버 저장소·카탈로그·키를 함께 보존하고 전체 10,000개/에이전트 1,000개 묶음 및 객체 용량을 관리한다. 번들별 검토는 100개이며 마지막 슬롯은 취소에 사용한다. 번들 게시 뒤 저장소를 v0.5 이하 서버로 그대로 되돌리지 않는다. 개인 승인자 인증과 시험 실행자 서명은 아직 제공하지 않는다. [명령 절차](FEATURE_RECOVERY_BUNDLE_CLI.md)를 참고한다.

## v0.7.0 운영 흐름

승인 전 시험 결과와 출처 근거를 검토한 뒤 명시적 good/revoked를 추가한다. 취소 예약 자원과 개별/전역 보류를 확인하고 예약 예산·실제 디스크 여유가 소진된 오류를 성공으로 처리하지 않는다. actor는 아직 개인 인증이 아니다. [상태·재개·취소 안내](FEATURE_BUNDLE_OPERATIONS.md)를 따른다.
