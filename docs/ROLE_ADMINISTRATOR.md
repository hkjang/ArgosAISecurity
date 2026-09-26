# Argos 보안 관리자(Security Administrator) 운영 가이드

이 문서는 Argos AI Security 플랫폼의 보안 정책을 수립, 서명 및 배포하고, 전체 시스템 노드의 관제 매개변수를 제어하는 **보안 관리자(Security Administrator)**를 위한 상세 운영 매뉴얼입니다.

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
   - **검증키 (공개키)**: 각 서버 에이전트의 `argos.toml` 파일 내부 `[policy] pubkey` 파라미터에 사전 입력 배포할 키입니다.

### 2.2. 정책 구성서 (`policy.toml`) 작성
서명 및 배포할 신규 설정 데이터의 가중치를 튜닝해 파일을 작성합니다:
```toml
version = 1                  # 감사용 버전 번호
[detection]
window_secs = 10             # 슬라이딩 윈도우 시간 (10초)
mass_change_threshold = 30   # 대량 쓰기 판단 기준 파일 수 (30개)
min_changed_files = 5        # 최소 탐지 유발 파일 수 (5개)
entropy_threshold = 7.2      # 암호화 의심 Shannon 엔트로피 (7.2)
detect_score = 40.0          # 탐지 생성 하한 점수 (40점)
entropy_sample_bytes = 65536 # 엔트로피 실측 샘플 크기 (64KB)

[response]
auto_block = false           # 관찰·정책 재생 후 소수 서버에서 자동 차단 검증
block_score = 80.0           # 자동 차단 발동 점수 (80점)
```

### 2.3. 정책 날인 서명 실행
비밀 서명키가 들어 있는 경로를 활용해 `policy.toml` 파일에 암호 증명을 날인합니다:
```bash
argos policy sign policy.toml --key-file signing.key
```
- 실행 완료 시, 타겟 경로 하위에 정형 서명 파일인 `policy.toml.sig`가 즉시 생성됩니다.
- 정책 배포 시 원본 `policy.toml`과 함께 `policy.toml.sig` 파일이 타겟 에이전트 서버의 지정 디렉터리에 반드시 동시 안착되어야 합니다.

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
