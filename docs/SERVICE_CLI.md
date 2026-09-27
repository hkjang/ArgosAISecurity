# Argos CLI 명령 가이드

`argos`는 v0.4.0의 로컬 조사·복구·정책 관리 도구다. 에이전트와 같은 설정을 지정한다.
명령은 해당 DB·백업에 필요한 OS 권한이 있는 계정으로 실행한다. 중앙 관리자 토큰이
로컬 CLI 권한을 부여하지는 않는다. 명령별 옵션은 `argos <명령> --help`, 정책·보존 작업은 `argos policy --help`와
`argos retention --help`에서 확인한다.

```bash
argos --config /etc/argos/argos.toml status
argos --config /etc/argos/argos.toml threats -n 30
```

`-c`/`--config`는 전역 옵션이며 기본 경로는 현재 디렉터리의 `argos.toml`이다.
파일이 없으면 기본값을 사용한다. Linux 기본 감시 경로는 `/home`, DB는
`/var/lib/argos/argos.db`, 백업은 `/var/lib/argos/backup`이다. 예제 설정의 `./watched`와
구분한다. 존재하는 설정 파일이 잘못된 TOML이면 오류로 종료한다.

## 상태와 최근 이력

| 명령 | 동작·기본값 |
| --- | --- |
| `status` | 로컬 설정, 생존 신호와 보호 지표, DB의 누적 이벤트·탐지 건수. 생존 신호가 60초보다 오래되면 경고한다. |
| `doctor` | 탐지 설정 유효성·센서별 임계치 경고, OS와 설정/DB/백업/감시 경로 존재 여부, Anthropic 키 환경변수 유무. |
| `events [-n N]` | 최근 파일 이벤트. 기본 20건. |
| `threats [-n N]` | 최근 탐지의 ID·점수·심각도·요약. 기본 20건. |
| `processes [-n N]` | 저장된 프로세스 관측의 PID·PPID·유효 UID·이름·명령행. 기본 20건. |
| `scan PATH` | 현재 파일 앞부분의 엔트로피를 읽어 고엔트로피 파일을 표시한다. 기본 최대 64 KiB, 기준 7.2. |

DB 이력 조회는 읽기 전용이며 `status`가 데몬에 직접 질의하는 것은 아니다. 표시한
자동 차단 값은 로컬 설정 값이므로 서명 정책의 수락 설정 및 `policy.invalid`와 함께
확인한다. 프로세스 수집은 Linux `/proc` 폴링이며 시작 이후 관측된 실행·자격 변화도
저장한다. 전체 신원·자격은 아래 `evidence` JSON을 사용한다.

`doctor`의 경로 확인은 실제 접근 권한·센서 작동·AI 연결 시험이 아니다. Anthropic 키
항목은 Ollama 구성에서도 출력된다. `scan`은 부분 암호화 비교나 공격 확정 검사가
아니며 에이전트의 다중 위치 표본 설정과 별개다.

## 근거·사건·AI

| 명령 | 옵션·결과 |
| --- | --- |
| `evidence --from-ms N --to-ms N [--pid PID] [--limit N]` | 양 끝을 포함하는 기간의 파일·탐지·프로세스·대응 JSON. 기본 종류별 200건, 허용 1~10,000건. |
| `incident ID [--window-secs N] [--limit N] [--html NEW_PATH]` | 탐지 앞뒤 각각 기본 300초, 종류별 기본 1,000건. JSON 또는 새 HTML 보고서. |
| `explain ID` | 탐지 앞 설정 시간창과 뒤 5초의 근거로 AI 분석. 다중 시간창 규칙은 가장 긴 설정 창을 사용한다. |
| `ask QUESTION... [--from-ms N --to-ms N] [--pid PID]` | 해석한 기간 또는 명시한 구간으로 AI 질문. 기본 기간 24시간, 조회 상한은 `ai.evidence_limit`(기본 200). |
| `mcp` | 단일 로컬 DB의 `query_evidence`만 제공하는 MCP stdio 서버. |
| `evidence-export ID --out NEW_DIR [--window-secs N] [--limit N] [--include-sensitive]` | 기본 앞뒤 300초·종류별 1,000건의 사건 자료와 정책을 새 디렉터리로 저장한다. 기본 마스킹 적용. |
| `evidence-verify DIR` | 패키지 파일 목록·크기·SHA-256 검사. 발급자 서명 검사는 아니다. |

조회에는 전체 건수와 `truncated`가 포함된다. `--pid`는 숫자 PID 필터이므로 같은 PID의
다른 시작 ticks·boot ID를 조사 과정에서 구분한다. AI는 Anthropic과 Ollama를 지원하고
모델 ID를 명시해야 한다. AI 키 없이 근거·HTML·MCP·패키지를 사용할 수 있다.
[AI/조사](FEATURE_AI.md), [자격 근거](FEATURE_LINUX_ANALYSIS.md),
[증거 패키지](FEATURE_EVIDENCE_PACKAGE.md)에 범위와 누락·전송 조건을 설명한다.

## 정상 복구 지점과 사건 보존

```bash
argos restore /srv/data/report.txt --list
argos restore /srv/data/report.txt --version 23 --preview /tmp/report-review.txt
argos restore /srv/data/report.txt --mark-good 23 --note "검토한 배포 원본과 일치"
argos restore /srv/data/report.txt --recommend --before-ms 1760000000000
argos recovery-status --test /srv/data/report.txt --before-ms 1760000000000
argos restore /srv/data/report.txt --before-ms 1760000000000
```

실제 버전·사건 시각과 서비스 설정을 사용한다. 기본 복구는 최신 **정상 판정 버전**만
선택하며, `--before-ms`가 있으면 그 시각보다 이른 정상본만 선택한다. 미검토 최신본으로
대체하지 않는다. `--version`은 `--preview`와 함께 쓰며 임의 버전의 원본 덮어쓰기 옵션은
아니다. 정상 판정 취소는 `restore PATH --revoke-good ID --note TEXT`다.

`recovery-status`는 백업 준비도 JSON을 출력하고 `--html NEW_PATH`로 보고서를 만든다.
`--test PATH`는 원본을 바꾸지 않는 복구 시험 후 결과를 저장하며 출력에 시험 결과
문장도 포함한다. `--before-ms`는 `--test`와 함께 쓴다. 현재 감시 경로의 미기록 파일과
10,000개 경로 검사 상한·접근 실패를 `untracked_paths`/`scan_truncated`로 표시한다.

```bash
argos retention pin /srv/data/report.txt --version 23 --incident INC-42 --actor operator --reason "사건 증거 보존"
argos retention list --incident INC-42
argos retention list --include-released
argos retention release --incident INC-42 --approval CHG-82 --approver reviewer --reason "독립 검토 후 사건 종료"
argos retention audit --incident INC-42
```

보존은 정상본 판정과 독립적이다. 여러 사건의 참조는 각각 해제하며 승인자는 최초
고정 요청자와 달라야 한다. 승인 ID 재사용을 거부하지만 입력한 승인자 문자열 자체를
외부 인증하는 기능은 없다. 자동 고정은 비동기 대기열을 거치므로 완료 참조를 확인한다.
`restore`와 `recovery-status`는 백업이 활성화되어 있어야 한다. `retention`은
백업 수집 활성 여부와 별도로 설정된 저장소를 관리한다. 이 명령들은 로컬 백업
인덱스를 열거나 이전할 수 있다. `argos prune`은 제공하지 않는다. 자세한 조건은
[복구 기능](FEATURE_RECOVERY.md)을 따른다.

## 정책 검증·활성화·사전 비교

| 명령 | 의미 |
| --- | --- |
| `policy gen-key` | 비밀키·공개키를 콘솔에 출력한다. 비밀키는 관리 머신의 제한된 파일에 별도 보관한다. |
| `policy sign PATH --key-file KEY_PATH` | 파일 전체 바이트를 서명해 `PATH.sig`에 저장한다. |
| `policy verify` | 신뢰 키 설정이 있으면 서명·기간·대상·설정을 검사한다. 이전 `pubkey`만 있으면 서명만 검사한다. |
| `policy show` | 서명 정책 사용 시 영속 저장된 마지막 수락 원문을 JSON으로 출력한다. 미사용 시 로컬 탐지 설정을 표시한다. |
| `policy status [--limit N]` | 마지막 수락 버전·해시와 감사 JSON. 기본 100건, 최대 1,000건. |
| `policy simulate --candidate PATH --from-ms N --to-ms N [--max-events N]` | 수락 정책/로컬 설정과 후보를 저장 근거에 재생한다. 기본 100,000건, 준비 구간 포함 최대 1,000,000건. |

`verify`와 `simulate`는 정책을 적용하거나 영구 최대 버전을 증가시키지 않는다. 실제
버전·재사용 검사와 활성화는 에이전트 시작 시 실행한다. `show`/`status`도 현재 프로세스의
가동 여부를 보증하지 않는다. 후보 파일이 거부되어도 마지막 수락 설정을 조회할 수 있다.
서명·대상·기간·승인 롤백·상태 경로 권한은 [정책 신뢰](FEATURE_POLICY.md)를 따른다.

## 미끼 파일·격리·미구현 명령

`canary-init ABSOLUTE_PATH`는 `detection.canary_paths`에 등록된 경로에 새 파일을 만든다.
기존 파일은 덮어쓰지 않는다. 감시 시작 전에 설치하고 [미끼 탐지](FEATURE_DETECTION.md)를
확인한다.

```bash
argos isolate --dry-run --allow in:192.0.2.20:22 --allow out:10.0.0.5:8443
sudo argos isolate --allow in:192.0.2.20:22 --allow out:10.0.0.5:8443
sudo argos isolate --release
```

격리는 IPv4·IPv6 INPUT/OUTPUT/FORWARD의 Argos 규칙을 적용·확인한다. `--allow`는
방향·숫자 IP/CIDR·TCP 포트가 필요하며 중앙·SSH 연결을 자동 허용하지 않는다.
`--dry-run`은 도구나 권한 없이 계획만 출력한다. 실제 적용 조건과 한계는
[대응·격리](FEATURE_RESPONSE.md)를 따른다.

`update`는 아직 안내만 출력하는 자리 표시자다. 정책 배포나 바이너리 업데이트를
실행하지 않는다. `prune`, `kill`, `policy apply` 명령은 제공하지 않는다.

## 보호 검증·DB 복구·원격 보관

| 명령 | 의미 |
| --- | --- |
| `coverage status` | 최근 감시 범위 검사와 누락·마운트/루트 변경. 오래된 건강 상태는 오류 |
| `coverage probe --directory DIR [--timeout-secs 10] [--out NEW_FILE]` | 보호 범위 안의 전용 디렉터리에 작은 파일을 작성하고 새 DB 이벤트를 확인 |
| `service-recovery verify --plan PLAN --report REPORT --max-age-secs N` | 현재 계획·백업·검사 결과·시각과 v2 보고서를 대조. 계획 읽기·검사를 통과한 뒤 보고서 검증 실패는 JSON과 비영 종료 |
| `service-recovery test --plan PLAN --out NEW_DIR` | 네이티브 SQLite/PostgreSQL 백업을 새 격리 작업 경로에 복원하고 고정 검사 |
| `policy audit-exceptions --from-ms N --to-ms N [--max-events 100000] [--expiring-within-hours 24]` | 현재 기준 정책의 예외 매칭·만료·표본과 모든 예외를 제거한 재생 결과 비교 |
| `vault usage --vault-config CONFIG` | 관리자 토큰으로 논리 보관량·한도·여유공간·새 쓰기 차단 상태 조회 |
| `vault queue enqueue --vault-config CONFIG --directory DIR --file FILE --kind audit` | 등록 시점의 파일 바이트와 목적지·고정 공개키를 영속 보존 |
| `vault queue enqueue-backup PATH --version ID --directory DIR --vault-config CONFIG` | 정상 판정한 백업 버전의 검증 스냅샷을 큐에 등록. 에이전트 `--config` 사용 |
| `vault queue enqueue-evidence --package DIR --directory QUEUE --vault-config CONFIG` | 검증한 증거 패키지 세 파일을 각각 등록. 부분 등록·전송 상태 확인 필요 |
| `vault queue drain --directory DIR --vault-config CONFIG [--max-items 16]` | 재시도 시각에 도달한 항목을 전송하고 종료. 실패가 있으면 비영 종료 |
| `vault queue status --directory DIR` | 네트워크·큐 변경 없이 전체 계수와 최근 100개 상태 조회 |
| `vault queue show --directory DIR --id ID` | 특정 항목의 수신증명·재시도 상태 조회 |
| `vault keygen --out KEY_FILE` | 전용 0700 디렉터리에 보관 서버 서명키 생성, 공개키 출력 |
| `vault upload --vault-config CONFIG --file FILE --kind audit --receipt NEW_FILE` | evidence/backup/audit 파일을 보관하고 검증한 수신증명 저장 |
| `vault upload-backup PATH --vault-config CONFIG --version ID --receipt NEW_FILE` | 정상 판정한 로컬 백업 버전의 해시를 확인해 보관. 에이전트 `--config`도 사용 |
| `vault upload-evidence --vault-config CONFIG --package DIR --receipts NEW_DIR` | 검증한 증거 패키지의 같은 바이트를 전송하고 manifest를 마지막에 보관 |
| `vault fetch --vault-config CONFIG --agent-id ID --sha256 HASH --out NEW_FILE --receipt NEW_FILE` | 관리자 토큰으로 내려받아 서명·크기·해시를 검증하고 새 파일로 저장 |
| `vault verify --file FILE --receipt RECEIPT --pubkey HEX` | 원격 호출 없이 고정 공개키와 로컬 파일로 수신증명 검사 |

보관 설정은 별도 TOML이며 Linux에서 현재 계정 소유·0600 권한을 요구한다. DB 복구 시험과 원격 보관은 명시적인 CLI 작업이며 자동 예약·동기화는 제공하지 않는다. `service-recovery`, 보관 키 생성/업로드/검증/받기는 관련 없는 에이전트 설정을 읽지 않는다. `vault upload-backup`과 `vault queue enqueue-backup`은 로컬 백업 설정을 읽는다. 대기열은 명시적 `drain` 호출로 처리하며 자동 스케줄러는 제공하지 않는다.

[보호 공백](FEATURE_COVERAGE.md), [DB 복구](FEATURE_SERVICE_RECOVERY.md), [원격 보관](FEATURE_REMOTE_VAULT.md), [영속 전송](FEATURE_VAULT_QUEUE.md), [용량 보호](FEATURE_VAULT_CAPACITY.md), [예외 감사](FEATURE_EXCEPTION_AUDIT.md), [AI 인용 검사](FEATURE_AI_VALIDATION.md)의 전제와 결과 해석을 따른다. `ask`·`explain`은 잘못된 인용이나 JSON 형식을 오류로 처리하며 검증되지 않은 모델 원문을 대신 출력하지 않는다.
