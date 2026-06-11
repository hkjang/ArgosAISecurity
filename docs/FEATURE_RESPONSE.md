# Argos 위협 대응 및 차단 기능 분석서

**Argos 위협 대응 엔진**은 침해 위협 점수가 한계를 돌파했을 때 해를 입히고 있는 원인 프로세스를 커널 시그널을 이용하여 강제 중단하거나, 호스트 시스템의 패킷 통신망을 동적으로 격리 조치하여 피해 확산을 실시간 차단하는 실시간 침해 조치 컴포넌트입니다.

---

## 1. 핵심 설계 및 컴포넌트

위협 대응 및 격리는 [argos-response](file:///d:/project/ArgosAISecurity/crates/argos-response/src) 라이브러리가 전담합니다.
- **`Responder` 트레잇** ([lib.rs](file:///d:/project/ArgosAISecurity/crates/argos-response/src/lib.rs)): 다중 플랫폼 기동 및 자동 차단 구성 설정 온오프에 유기적으로 호환 동작하기 위해 선언된 공통 조치 인터페이스입니다.
- **`LinuxResponder`**: 리눅스 환경에서 실제 커널 시그널을 가동시키는 물리 대응 클래스입니다.
- **`DryRunResponder`**: 자동 차단 옵션 비활성화(`auto_block=false`) 상태에서 조치는 하지 않고 관제 로그만 전송하는 모의 대응 클래스입니다.
- **`isolate` 모듈** ([isolate.rs](file:///d:/project/ArgosAISecurity/crates/argos-response/src/isolate.rs)): 리눅스 iptables 도구와 연동하여 아웃바운드 인터넷 연결을 물리 격리하는 방어 서브시스템입니다.

---

## 2. 프로세스 시그널링 차단 및 안전 메커니즘

수집된 센서 데이터 분석을 거쳐 위협 스코어가 대응 수치(`block_score`, 기본값 80점)를 상회하면 에이전트 데몬은 `Responder::execute`를 수행합니다.

### 2.1. 대응 액션 범주 (`ResponseAction`)
1. **`KillProcess(Pid)`**:
   - 악성 쓰기를 주도하는 프로세스에 `libc::SIGKILL` (시그널 번호 9) 신호를 전달하여 즉각 사살 및 소멸시킵니다.
2. **`SuspendProcess(Pid)`**:
   - 보안 실무자의 위협 상세 포렌식 조사를 지원하기 위해 프로세스의 동작을 메모리 상에 그대로 멈추게 하는 `libc::SIGSTOP` (시그널 번호 19) 신호를 주입합니다.

### 2.2. 안전 제어 장치 (PID 0 오동작 거부)
- `fanotify` 센서가 정상 동작하지 못하는 Fallback notify 센서 가동 시에는 이벤트를 유발한 원인 프로세스의 PID를 디코딩하지 못하고 `0`으로 보고합니다.
- 리눅스 시스콜 상에서 `kill(0, signal)` 명령어 호출을 가동시키면 **에이전트 데몬이 속한 동일 프로세스 그룹의 모든 정상 서버 서비스 프로세스가 함께 SIGKILL을 맞는 최악의 장애(자살 현상)**를 초래하게 됩니다.
- 이를 예방하기 위해 `LinuxResponder` 내부에는 대상 PID가 `0`인 조치 요청이 수신되는 순간 작업을 거절하고 `ResponseError::UnknownPid` 에러를 반환하는 방어망을 견고하게 가동하고 있습니다.

---

## 3. iptables 기반 네트워크 호스트 선별 격리

랜섬웨어가 외부 C2 서버와 통신하며 중요 기밀을 탈취하거나 추가 악성 암호화 키를 발급받는 연결을 끊어버리기 위해 `isolate` 서브시스템을 기동합니다.

### 3.1. 격리 룰 생성 순서 및 원리
`isolation_commands` 함수는 시스템 방화벽 환경에 다음 순서의 동적 격리 명령 셋을 구성해 인계합니다.

```
[커스텀 격리 체인 생성] ➔ iptables -N ARGOS_ISOLATE
                                 │
                                 ▼
[체인 규칙 완전 초기화] ➔ iptables -F ARGOS_ISOLATE
                                 │
                                 ▼
[루프백 패킷 전송 인가] ➔ iptables -A ARGOS_ISOLATE -o lo -j ACCEPT
                                 │
                                 ▼
[기존 세션 통신 유지] ➔ iptables -A ARGOS_ISOLATE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
                                 │
                                 ▼
[중앙 서버 API 주소 예외 인가] ➔ iptables -A ARGOS_ISOLATE -d <중앙서버IP> -j ACCEPT
                                 │
                                 ▼
[나머지 아웃바운드 전체 Drop] ➔ iptables -A ARGOS_ISOLATE -j DROP
                                 │
                                 ▼
[최우선 OUTPUT 인서트] ➔ iptables -I OUTPUT 1 -j ARGOS_ISOLATE
```

1. **기존 접속 유지 (Est/Rel)**: 관리자가 서버를 점검하기 위해 SSH 접속 등을 수행 중인 경우, 네트워크 격리가 기동되자마자 SSH 접속 세션까지 다 차단되어 관리 도구가 차단되는 참사를 방어하기 위해 기존 확립 연결은 정상 흐름을 보장해 줍니다.
2. **관제 전송 유지 (Central IP 예외)**: 에이전트 노드가 고립되더라도 위험 탐지 보고 데이터는 실시간으로 관제 센터에 보고되어 모니터링이 가능해야 하므로, 설정된 `central.url`의 호스트 목적지 패킷은 차단 목록에서 자동 예외 처리합니다.
3. **OUTPUT 체인 멱등 결합**: 이중 결합으로 인한 충돌 방지를 위해 먼저 `OUTPUT` 체인에서 점프 규칙을 탈거한 뒤, 최우선 순위 1번 슬롯으로 `ARGOS_ISOLATE` 체인을 점프 대상으로 강제 인서트(`-I OUTPUT 1`)합니다.

### 3.2. 격리 롤백 원상 복구 (`release`)
위협 상황이 해제되면 CLI 명령어(`argos isolate --release`)를 작동해 iptables 롤백 체인을 가동합니다.
- `release_commands`는 `OUTPUT`의 점프 규칙을 탈거하고, `ARGOS_ISOLATE` 내부 목록을 초기화(`-F`)한 뒤 체인 구조체 자체를 소거(`-X`)하는 복원 작업을 진행합니다.
- 복구 명령들은 이미 해제된 상태에서 중복 호출되더라도 무해하도록 에러를 무시하는 멱등성 실행 모드로 구동됩니다.
