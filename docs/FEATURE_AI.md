# 근거 기반 AI 조사와 조회형 MCP

AI는 대응을 실행하지 않고, 로컬 이벤트 저장소를 조회한 근거로 설명한다. `ask`와 `evidence`, MCP가 같은 기간 조회 API를 사용한다.

## 설정

```toml
[ai]
provider = "ollama"
endpoint = "http://127.0.0.1:11434/api/chat"
model = "사내에-설치한-모델-ID"
api_key_env = ""
timeout_secs = 60
evidence_limit = 200
```

`anthropic`도 지원한다. endpoint가 비어 있으면 제공자의 기본 주소를 사용한다. 모델은 `ai.model` 또는 `ARGOS_AI_MODEL`로 명시해야 한다. Anthropic의 키는 기본 `ANTHROPIC_API_KEY`, 다른 환경변수를 지정하려면 `api_key_env`를 설정한다. Ollama에는 기본적으로 외부 제공자 키를 전달하지 않는다. HTTP 리다이렉트는 따르지 않는다.

Ollama는 [공식 Chat API](https://docs.ollama.com/api/chat)의 비스트리밍 메시지 형식을 사용한다. 실제 사내 모델의 정확도·응답 속도는 별도 평가가 필요하다. 통합 테스트는 로컬 모의 HTTP 서버로 요청/응답과 조회 범위 전달을 검증한다.

## 범위와 누락 확인

```bash
argos ask "지난 24시간 위험한 활동이 있었어?"
argos ask --from-ms 1760000000000 --to-ms 1760086400000 --pid 1234 "이 프로세스의 근거는?"
argos evidence --from-ms 1760000000000 --to-ms 1760086400000 --limit 1000
```

질문의 `지난/최근 N시간/N분/N일`, `last N hours/minutes/days`를 해석한다. 기간이 없으면 최근 24시간임을 표시한다. `어제` 등 달력 기준 표현은 명시적 epoch ms 구간을 요구한다. 복잡한 자연어 기간 해석기는 아니므로 정확한 조사에는 `--from-ms/--to-ms`를 사용한다.

조회는 시작·종료를 포함하며, 각각 파일·탐지·프로세스의 전체 건수/반환 건수/`truncated`를 같은 읽기 스냅샷에서 계산한다. 상한은 종류별 1~10,000건이고 결과는 시각·ID 순이다. AI 프롬프트에도 구간과 누락을 전달하며, CLI가 모델 호출 전에 범위를 별도로 출력한다. 저장되지 않은 이벤트는 복원할 수 없다. 개별 테이블 ID가 겹칠 수 있으므로 `files.id`, `detections.id`, `processes.id`를 구분한다.

`ask`의 서버 범위는 현재 설정의 로컬 DB다. 여러 서버의 중앙 비교나 자연어에 등장하는 다른 서버로 자동 전환하지 않는다. 이벤트·경로·명령행 안의 지시는 신뢰할 수 없는 데이터로 취급하도록 프롬프트에 명시한다.

## 조회형 MCP

`argos --config /etc/argos/argos.toml mcp`는 [MCP stdio 전송](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)을 제공한다. 프로토콜은 2025-06-18이다. 초기화 후 노출하는 도구는 `query_evidence(from_ms,to_ms,pid?,limit?)` 하나이며, SQLite를 읽기 전용으로 연다. 서버는 실행 시 설정한 단일 호스트 DB에 고정된다. 임의 SQL, 파일 복구, 정책 적용, 차단 도구는 제공하지 않는다.

표준 출력에는 JSON-RPC 메시지만 쓴다. 요청은 1MiB 이하이며 근거 조회 상한·잘못된 인자를 검사한다. 데이터 접근 권한은 이 로컬 프로세스를 실행하는 계정의 DB 읽기 권한에 따른다.

## 사건 조사 화면

```bash
argos incident 42 --window-secs 300 --limit 1000 --html /tmp/incident-42.html
```

독립형 HTML에서 탐지 주변 이벤트를 시간순 재생하고 프로세스별로 필터링한다. 프로세스 식별자는 PID·부팅 ID·시작 ticks를 함께 표시한다. 예전 자료와 PID 미지원 센서는 신원 미확인으로 표시한다. 부모 PID만 있는 자료에서 부모의 정확한 프로세스 인스턴스를 단정하지 않는다. 기간 내 사건은 연관 후보이며 인과관계 확정이 아니다. 네트워크 이벤트 상관분석은 후속 단계다.

보고서는 기존 파일을 덮어쓰지 않으며 경로·명령행을 HTML로 실행하지 않는다. 외부 스크립트·네트워크 자원 없이 열 수 있다.

`explain ID`도 지정 탐지 앞 탐지 윈도우와 뒤 5초의 기간 조회·누락 표시를 사용한다.
`evidence`/MCP에는 `response_results`가 추가된다. 대응 감사 조회는 같은 기간으로 별도 읽기 스냅샷을 열며, 종류별 상한과 누락을 함께 표시한다. `ask`/`explain`은 실제 대응 결과도 모델에 전달한다.
