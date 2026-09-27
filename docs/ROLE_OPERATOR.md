# Argos 시스템·인프라 운영자 가이드

운영자는 에이전트 가동, 센서·백업·전송 상태, 디스크 용량과 실제 파일 복구를 담당한다.
이 문서는 v0.4.0 기준이다. 정책 승인·서명은 [보안 관리자](ROLE_ADMINISTRATOR.md),
사건 조사와 증거 인계는 [분석가](ROLE_ANALYST.md) 가이드와 연결한다.

## 설치와 설정

[바이너리 설치](INSTALL_BINARY.md) 또는 [README의 소스 빌드](../README.md)를 먼저 따른다.
systemd 서비스는 `/usr/bin/argos-agent --config /etc/argos/argos.toml`을 실행한다.
CLI도 같은 설정 파일을 지정해야 같은 DB·백업·정책 상태를 조회한다.

다음은 운영 경로를 명시한 관찰 모드 예시다. `fanotify`에는 Linux와 필요한 root 권한이
필요하다. `notify`는 일반 사용자 시험에 사용할 수 있지만 파일 변경 PID를 제공하지 않는다.

```toml
watch_paths = ["/srv/data"]
db_path = "/var/lib/argos/argos.db"
sensor = "fanotify"

[response]
auto_block = false
block_score = 80.0

[backup]
enabled = true
dir = "/var/lib/argos/backup"
max_file_bytes = 52428800       # 기본 50 MiB
keep_versions = 5              # 경로별 최신 미검토 버전, 정상본·사건 고정은 별도 보존
baseline_on_start = true
queue_capacity = 256
io_bytes_per_sec = 10485760     # 논리 파일 바이트 기준 평균 예산 10 MiB/s
```

백업 디렉터리는 감시 경로 밖에 둔다. 베이스라인은 크기 제한·접근 권한·처리 지연의
영향을 받으며, 수집되었다고 자동 정상본 판정을 받지는 않는다. 기본값과 세부 흐름은
[Agent 서비스](SERVICE_AGENT.md), 보존 조건은 [복구 기능](FEATURE_RECOVERY.md)을 참고한다.

서비스 파일을 설치한 뒤 실행한다.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now argos-agent
sudo systemctl status argos-agent
sudo journalctl -u argos-agent -f -n 100
argos --config /etc/argos/argos.toml doctor
argos --config /etc/argos/argos.toml status
```

## 상태 확인과 용량 관리

`doctor`는 설정 유효성과 경로 **존재 여부** 등을 확인한다. 실제 쓰기 권한·커널 센서
가동·AI 연결 성공을 시험하는 명령은 아니다. Anthropic 키 항목은 Ollama 사용 여부와
무관하게 출력되므로 [AI 설정](FEATURE_AI.md)과 함께 해석한다.

`status`의 생존 신호는 기본적으로 30초마다 기록되며 60초보다 오래되면 경고한다.
설정에서 표시한 자동 차단 값만 보지 말고 `policy.invalid`, 센서·분석 상태를 함께 본다.
서명 정책이 있으면 마지막 수락 설정은 `policy show`, 수락·거부 이력은 `policy status`로 확인한다.

| 확인할 지표 | 운영 조치 |
| --- | --- |
| `sensor.alive`, `errors`, `dropped_events`, `kernel_overflows` | 수집 중단·오류·유실 로그와 감시 범위를 점검한다. |
| `analysis_incomplete`, `semantic_unavailable` | 표본 읽기·집계 상한·지정 설정 파일의 분석 누락을 확인한다. |
| `backup.queued`, `dropped`, `failed`, `oversized`, `delay_ms` | 큐와 읽기 예산·파일 크기 제한을 점검하고 복구 준비도를 조회한다. |
| `backup.pin_pending`, `pin_failed`, `pin_overflow`, `pin_worker_errors` | 사건 고정 대기·재시도·누락을 확인하고 `retention list`에서 실제 완료 참조를 확인한다. |
| 중앙의 `outbox_pending`, `failed_attempts`, 연결 상태 | 통신·인증과 로컬 이벤트 DB의 증가를 확인한다. |

```bash
argos --config /etc/argos/argos.toml recovery-status
argos --config /etc/argos/argos.toml recovery-status --html /tmp/recovery-review.html
argos --config /etc/argos/argos.toml retention list
```

복구 준비도의 `untracked_paths`는 현재 감시 경로에서 발견했지만 백업 상태가 없는 파일이다.
`scan_truncated=true`면 10,000개 경로 검사 상한이나 접근 실패로 부분 검사한 결과다.
보고서 파일은 새 경로여야 한다.

백업 작업자는 성공 처리 100회마다 `keep_versions` 정리를 시도한다. `argos prune` 명령은
없다. 정상본·사건 고정·감사 이력 때문에 저장소가 설정 개수보다 커질 수 있으며,
전송 대기열도 전체 디스크 상한을 제공하지 않는다. [보호 상태와 전송](FEATURE_RELIABILITY.md)을
기준으로 DB·백업 용량을 함께 관리한다.

## 정상본 검토와 파일 복구

탐지·분석 결과로 공격 의심 시각을 정하고, 백업 버전의 내용을 검토한 뒤 복구한다.
아래 버전 `23`과 시각은 예시이며 실제 목록·사건 근거로 바꾼다. 미리보기 경로의 부모는
미리 존재해야 하고, 기존 파일·원본·백업 저장소 내부로는 미리보기를 쓰지 않는다.

```bash
argos --config /etc/argos/argos.toml restore /srv/data/report.txt --list
argos --config /etc/argos/argos.toml restore /srv/data/report.txt --version 23 --preview /tmp/report-review.txt
# 미리보기 내용과 배포 원본 등을 대조한 뒤 정상본 지정
argos --config /etc/argos/argos.toml restore /srv/data/report.txt --mark-good 23 --note "배포 원본 내용 대조 완료"
argos --config /etc/argos/argos.toml restore /srv/data/report.txt --recommend --before-ms 1760000000000
argos --config /etc/argos/argos.toml recovery-status --test /srv/data/report.txt --before-ms 1760000000000
argos --config /etc/argos/argos.toml restore /srv/data/report.txt --before-ms 1760000000000
```

시점을 생략하면 **최신 정상 판정 버전**을 선택한다. 정상본이 없거나 객체 해시가
맞지 않으면 원본을 변경하지 않는다. SHA-256 일치와 정상 내용 판정은 다른 조건이다.
복구 시험은 백업 저장소의 임시 파일로 수행하며 실제 대상 경로의 쓰기 가능성까지
검증하지 않는다.

실제 복구는 대상과 같은 디렉터리의 임시 파일을 기록·동기화한 뒤 이름을 교체한다.
기존 파일의 UID/GID와 기본 권한을 보존하되 setuid/setgid 비트는 제거한다. 파일시스템
스냅샷이나 DB 트랜잭션 복구는 아니며 ACL·확장 속성과 애플리케이션 일관성은 별도 확인한다.
공격자가 상위 디렉터리를 교체할 수 없는 경로에서 수행하고, 이후 업무 서비스가 정상
작동하는지 확인한다.

사건 증거를 남겨야 하면 [사건 보존](FEATURE_RECOVERY.md#사건별-보존-고정과-해제)을 사용한다.
정상 판정 취소와 보존 해제는 별도 작업이다. `retention release`의 승인자 문자열은
외부 인증을 대신하지 않으며, 실제 업무 승인과 OS 파일 권한은 운영 절차로 관리한다.

## v0.3.0 추가 확인

보호 경로별 `coverage probe`와 [DB 복구 시험](FEATURE_SERVICE_RECOVERY.md)을 정기 절차에 포함하고, 검토된 정상본의 [외부 보관 수신증명](FEATURE_REMOTE_VAULT.md)을 보관한다.

## v0.4.0 운영 확인

[대기열](FEATURE_VAULT_QUEUE.md)의 `remaining_pending`, 오래된 재시도, 완료 이력 상한을 점검하고 명시적인 `drain`을 실행한다. [용량 상태](FEATURE_VAULT_CAPACITY.md)는 전체·에이전트 한도와 저장소 정합성을 함께 확인한다. 현재 계획과 백업으로 `service-recovery verify --max-age-secs N`을 실행하고 거부되면 원인을 확인한 후 복구 시험을 다시 수행한다.
