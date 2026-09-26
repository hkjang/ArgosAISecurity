# Linux 설정 의미와 프로세스 자격 변화

## 지정 파일의 의미 감시

`watch_paths` 안의 파일을 `[semantic].files`에 절대 경로로 명시한다. 지원 대상은 `authorized_keys`/`authorized_keys2`, `sudoers`와 `sudoers.d` 파일, `crontab`/`cron.d`/cron 스풀 파일, systemd `.service`/`.timer`/`.socket` 및 해당 drop-in `.conf`다.

```toml
[semantic]
files = ["/etc/sudoers", "/etc/systemd/system/example.service"]
max_file_bytes = 262144
```

시작 시 현재 내용을 비교 기준으로 관측한다. 기준은 정상 판정이나 백업 인증이 아니다. 이후 파일 이벤트에서 다음 의미를 별도 탐지로 기록한다.

| 규칙 | 표시하는 변화 |
| --- | --- |
| `linux.authorized_keys` | SSH 키 또는 접속 옵션 추가·제거·변경 |
| `linux.sudoers` | 관리자 권한 규칙 추가·제거·변경 |
| `linux.cron` | 예약·자동 실행 항목 또는 환경 변경 |
| `linux.systemd` | 서비스·타이머·소켓 설정 변경 |

전체 행 주석과 인용 밖의 불필요한 공백은 비교에서 제외한다. SSH 키 뒤의 설명도 제외한다. 인용된 명령, 지시문 순서, 중복 항목, systemd의 빈 대입/재설정은 보존한다. 파일의 소유권·권한 변화도 기록한다. 알림에는 원문 명령이나 키 내용을 넣지 않고 추가·제거 수와 파일 경로를 제시한다. 의미 탐지는 자동 종료를 직접 실행하지 않는다.

최대 1024개 파일, 파일당 최대 1 MiB, 파일당 10000개 항목으로 제한한다. 심볼릭 링크·특수 파일·크기 초과·수집 도중 변경·파싱 실패는 `health.semantic_unavailable`로 알린다. 시작부터 읽지 못한 파일 수는 로컬 생존 신호의 `semantic_unavailable`에 유지하며 전체 보호 상태를 저하로 표시한다. 이전 내용을 읽지 못한 파일의 첫 성공 관측은 `health.semantic_baseline`으로 표시한다. 누락을 정상 변경 없음으로 처리하지 않는다.

이 기능은 설정 차이를 분류하는 구문 분석이며 SSH/sudo/systemd의 완전한 유효 설정 평가기는 아니다. include 대상은 자동 탐색하지 않으므로 해당 파일도 명시해야 한다. 패키지 업데이트 승인이나 규칙 예외도 이 의미 알림을 자동으로 없애지 않는다. 실제 서비스 적용 여부·권한 획득 성공은 별도 조사한다. 재시작 시 비교 기준을 새로 수집하므로 에이전트 중단 중 변경은 확정할 수 없다.

## 프로세스 자격과 계보

프로세스 감시는 PID·시작 ticks·부팅 ID와 실행 파일·명령행을 비교한다. 기존 PID의 변경도 이벤트로 저장하며 `credentials`에 다음 내용을 담는다.

- `uids`, `gids`: real/effective/saved-set/filesystem 순서의 네 값.
- `cap_inheritable`, `cap_permitted`, `cap_effective`, `cap_bounding`, `cap_ambient`: 관측한 capability 비트 집합.

기존 `uid` 필드는 유효 UID다. 미수집·이전 이벤트의 `credentials`는 `null`이며 실제 UID나 capability를 추정하지 않는다. `/proc` 관측 전후에 자격·실행 신원이 달라지면 해당 관측을 거부한다. 변경된 자격은 새 이벤트로 기록되어 `evidence`/MCP에 전달된다.

fanotify 파일 이벤트의 `process.ancestors`에는 확인 가능한 부모부터 최대 4단계의 PID·시작 ticks·부팅 ID를 저장한다. PID 재사용·수집 경합·다른 부팅의 부모는 합산하지 않는다. 이 값은 당시의 제한된 부모 관측이며 완전한 역사적 프로세스 트리가 아니다. 폴링 사이에 끝난 exec/자격 변화와 매우 짧은 프로세스는 누락될 수 있다. 실행 파일 해시·패키지 출처·서비스 영향 평가는 후속 범위다.

## 재현

```bash
python3 scripts/security-scenarios.py --bin-dir target/debug --report /tmp/argos-scenarios.json
```

시험은 임시 파일·자식 프로세스를 사용한다. 운영 SSH·sudo·cron·systemd 설정을 수정하지 않는다.
