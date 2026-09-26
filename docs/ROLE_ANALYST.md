# Argos 보안 관제·분석가 가이드

분석가는 탐지 근거와 실제 대응 결과를 구분하고, 프로세스 신원·파일 변화·보호 누락을
조사한 뒤 증거를 인계한다. 이 문서는 v0.3.0 기준이다. 정책 변경은
[보안 관리자](ROLE_ADMINISTRATOR.md), 파일 복구는 [운영자](ROLE_OPERATOR.md)와 협업한다.

## 조사 범위 확인

CLI는 지정한 호스트의 로컬 DB를 읽는다. 중앙 대시보드는 에이전트 연결·보호 상태와
탐지 요약을 제공하지만 모든 호스트의 원본 이벤트를 자동으로 모아 조사하는 기능은 없다.
운영 서비스와 같은 설정을 지정한다.

```bash
argos --config /etc/argos/argos.toml status
argos --config /etc/argos/argos.toml threats -n 30
argos --config /etc/argos/argos.toml events -n 50
argos --config /etc/argos/argos.toml processes -n 20
argos --config /etc/argos/argos.toml policy status --limit 100
```

생존 신호가 오래되거나 센서·표본·설정 분석이 누락되었으면 탐지 없음으로 안전을
판정하지 않는다. `policy status`의 수락 기록 역시 현재 에이전트 가동 성공을 의미하지 않는다.

## 근거·사건·자격 변화 조사

`threats`에서 탐지 ID를 고른다. 아래 ID와 epoch 밀리초 값은 조사 대상에 맞게 바꾼다.

```bash
argos --config /etc/argos/argos.toml incident 42 --window-secs 600 --limit 1000 --html /tmp/incident-42.html
argos --config /etc/argos/argos.toml evidence --from-ms 1760000000000 --to-ms 1760000600000 --pid 1234 --limit 1000
```

`incident`는 탐지 앞뒤 각각 `window-secs`의 근거를 조회한다. HTML을 생략하면 JSON을
출력한다. 시간·PID가 겹치는 이벤트는 연관 후보이며 인과관계가 확정된 것은 아니다.
`total_rows`, 반환 건수와 `truncated`를 확인하고 조회 범위를 조절한다.

| 근거 | 조사 시 구분할 사항 |
| --- | --- |
| 프로세스 | PID + 시작 ticks + boot ID를 함께 본다. 같은 PID의 다른 시작 신원은 다른 프로세스다. |
| `credentials` | 네 가지 UID/GID와 capability 집합이다. `processes` 표의 UID는 유효 UID이며 전체 자격은 `evidence`/MCP JSON으로 확인한다. |
| 파일 `content` | 앞·중간·끝 표본과 이전 관찰 대비 차이다. 파일 전체나 검증된 정상본을 뜻하지 않는다. |
| `behavior.multi_window.*` | 여러 시간창의 신호다. 계정·경로·계보 집계의 PID 0을 종료 대상으로 해석하지 않는다. |
| `linux.*` | 지정 SSH·sudo·cron·systemd 파일의 의미 변화다. 실제 서비스 적용·권한 획득 성공은 별도 확인한다. |
| `response_results` | `succeeded`, `failed_or_unconfirmed`, `rejected`, `observed_threshold`를 구분한다. 관찰 모드 임계치 통과는 실행 성공이 아니다. |

`credentials=null`이나 부모 신원 누락은 추정해서 채우지 않는다. `/proc` 폴링은 짧게
끝난 실행·자격 변화를 놓칠 수 있다. 상세한 범위는 [Linux 분석](FEATURE_LINUX_ANALYSIS.md),
[탐지](FEATURE_DETECTION.md), [대응 결과](FEATURE_RESPONSE.md)를 참고한다.

## 근거 기반 AI 조사

[AI 설정](FEATURE_AI.md)에서 Anthropic 또는 사내 Ollama 주소와 모델을 지정한 뒤 사용한다.
모델은 `ai.model` 또는 `ARGOS_AI_MODEL`이 필요하며, Ollama에는 Anthropic 키가 필요하지 않다.

```bash
argos --config /etc/argos/argos.toml explain 42
argos --config /etc/argos/argos.toml ask "지난 1시간 동안 유효 UID 0 프로세스의 의심 근거와 누락을 설명해 줘"
argos --config /etc/argos/argos.toml ask --from-ms 1760000000000 --to-ms 1760000600000 --pid 1234 "실제 대응 결과를 근거 ID와 함께 설명해 줘"
```

호출 전에 표시되는 기간·PID·조회 누락을 확인하고 답변의 근거 ID를 원본 JSON과 대조한다.
AI는 조회 근거의 해석을 제공하며 차단·격리·복구를 실행하지 않는다. 기간 없는 질문은
최근 24시간으로 처리하며 달력 기준이나 복잡한 시간 표현은 명시적 구간을 사용한다.
AI에 전달되는 원본 근거는 증거 패키지의 기본 마스킹과 별개이므로 제공자와 전송 범위를
조직 기준에 맞게 선택한다.

## 사건 보존과 담당자 인계

```bash
argos --config /etc/argos/argos.toml retention list --incident detection-42
argos --config /etc/argos/argos.toml retention audit --incident detection-42
argos --config /etc/argos/argos.toml evidence-export 42 --out /secure/export/incident-42 --window-secs 600 --limit 1000
argos --config /etc/argos/argos.toml evidence-verify /secure/export/incident-42
```

자동 사건 고정은 비동기 작업이다. 탐지가 있더라도 정상본 부재·대기·실패·큐 초과로
참조가 없을 수 있으므로 완료 참조와 `backup.pin_*` 지표를 확인한다. 수동 고정은
정상 여부와 별도로 증거를 보존하며 복구를 승인하지 않는다.

증거 패키지는 새 디렉터리에 기록하고 기본적으로 경로·명령행·요약 등 민감 문자열을
마스킹한다. 원문이 필요하면 허용 범위를 검토하고 `--include-sensitive`를 명시한다.
해시는 파일 일관성을 검사하며 발급자 진위를 보증하지 않는다. 정책 스냅샷도 내보내는
시점의 마지막 수락 정책이다. [패키지 범위](FEATURE_EVIDENCE_PACKAGE.md)를 인계 자료에 포함한다.

## 네트워크 격리

관리 SSH와 중앙 보고에 필요한 숫자 IP·방향·TCP 포트를 지정하고 계획을 먼저 확인한다.
다음 주소는 예시다. 방화벽 적용은 Linux 관리자 권한이 필요하다.

```bash
argos isolate --dry-run --allow in:192.0.2.20:22 --allow out:10.0.0.5:8443
sudo argos isolate --allow in:192.0.2.20:22 --allow out:10.0.0.5:8443
sudo argos isolate --release
```

IP만 지정하는 예전 `--allow 10.0.0.99` 형식은 지원하지 않는다. 중앙 주소나 기존 SSH
연결을 자동 허용하지 않으며 예외 없는 `isolate`는 관리 연결도 끊는다. IPv4·IPv6의
INPUT/OUTPUT/FORWARD를 검사하지만 독립 네임스페이스·우회 데이터 경로까지 보장하지는
않는다. 적용·부분 실패·해제 조건은 [격리 문서](FEATURE_RESPONSE.md)를 따른다.

## v0.3.0 추가 확인

AI 답변은 [인용 검사](FEATURE_AI_VALIDATION.md)를 통과해도 원문 의미의 검토가 필요하다. 인계 패키지는 [외부 보관](FEATURE_REMOTE_VAULT.md)으로 전송하고 서명 수신증명과 manifest를 함께 확인한다.
