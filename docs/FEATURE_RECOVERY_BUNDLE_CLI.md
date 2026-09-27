# 원본 호스트 없는 복구 묶음 CLI

`argos vault bundle`은 최대 1GiB 백업을 16MiB 청크로 보관하고, 원본 에이전트 DB 없이 새 호스트에서 목록 조회·재조립·DB 복구 시험을 수행한다. 서버 동작과 서명 범위는 [복구 묶음](FEATURE_RECOVERY_BUNDLE.md), 기존 DB 검사와 제한은 [서비스 복구 시험](FEATURE_SERVICE_RECOVERY.md)을 참고한다.

원본 경로·버전·판정 이력은 등록자의 주장이다. 준비 또는 전송 성공만으로 정상본이 되지 않는다. 서버의 완료 증명과 관리자 토큰으로 추가한 현재 `good` 판정이 있어야 일반 `fetch` 및 `test`를 수행한다. 검토 이력의 서버 서명은 요청에 적힌 담당자 개인의 신원 인증을 뜻하지 않는다.

## 준비와 보관

예시의 `/srv/argos-bundle-work`와 `/srv/argos-restore`는 실행 계정 소유 `0700` 전용 디렉터리다. 설정 파일에는 기존 보관 서버 주소·토큰·고정 공개키를 넣고 권한을 `0600`으로 제한한다. 출력 경로는 기존 파일을 덮어쓰지 않으며 상위 경로의 심볼릭 링크·다른 계정의 쓰기 권한을 거부한다.

```bash
install -d -m 700 /srv/argos-bundle-work /srv/argos-restore

# 이 명령은 통신하지 않는다. --plan과 --review-history는 생략 가능하다.
argos vault bundle prepare \
  --file /srv/offline/orders.sqlite3 \
  --out /srv/argos-bundle-work/orders-stage \
  --original-path /var/lib/orders/orders.sqlite3 \
  --version 42 \
  --plan /srv/offline/orders-plan.toml \
  --review-history /srv/offline/review-history.json

# 편의 경로: 직접 업로드·구성 목록 등록·완료 검사. 같은 stage로 재시도 가능하다.
argos vault --vault-config /etc/argos/vault-upload.toml bundle upload \
  --stage /srv/argos-bundle-work/orders-stage
```

준비 디렉터리에는 `manifest.json`과 `chunks/<sha256>.bin`이 생성된다. 파일 전체를 메모리에 읽지 않고 청크 단위로 처리한다. 복구 계획은 최대 64KiB의 고정 형식 TOML이며, 원본 판정 이력 입력 JSON은 최대 128KiB다. 준비 후 stage와 그 구성 목록을 보존해야 전송 재시도 및 `publish`를 수행할 수 있다. 준비 도중 실패한 디렉터리는 완료된 stage가 아니며 자동 삭제하지 않는다.

지속적인 전송에는 영속 큐를 사용할 수 있다.

```bash
argos vault --vault-config /etc/argos/vault-upload.toml bundle enqueue \
  --stage /srv/argos-bundle-work/orders-stage \
  --directory /srv/argos-bundle-work/upload-queue \
  --max-items 1000 --max-bytes 1073741824

argos vault --vault-config /etc/argos/vault-upload.toml queue drain \
  --directory /srv/argos-bundle-work/upload-queue --max-items 64

argos vault --vault-config /etc/argos/vault-upload.toml bundle publish \
  --manifest /srv/argos-bundle-work/orders-stage/manifest.json
```

`enqueue`는 검증한 청크 바이트를 큐에 고정하며 통신하지 않는다. 같은 해시의 청크는 한 번만 등록한다. 여러 청크의 등록은 단일 트랜잭션이 아니므로 중간 실패 시 이미 등록한 항목이 남는다. 큐 상태를 확인하고 같은 stage로 재실행하면 중복 기록을 재사용한다. 기본 큐 바이트 상한은 256MiB이므로 큰 백업에는 적절한 `--max-bytes`가 필요하다. 보관 클라이언트의 `max_object_bytes`는 16MiB 청크를 수용해야 한다.

큐 전송 완료가 곧 묶음 완료를 뜻하지 않는다. `publish`는 구성 목록을 등록하고 서버가 모든 청크·전체 파일 해시를 검사하도록 요청한다. 청크가 없으면 실패하며 묶음은 미완료 상태로 남는다. 큐 예약 전송은 청크를 처리하고, 구성 목록 완료는 명시적인 `publish`에서 수행한다. 미완료 상태와 완료 수신증명 모두 정상 판정과 구분한다.

## 원격 조회와 판정

```bash
argos vault --vault-config /etc/argos/vault-admin.toml bundle list \
  --agent-id orders-host --limit 100

argos vault --vault-config /etc/argos/vault-admin.toml bundle show \
  --agent-id orders-host --id BUNDLE_ID

argos vault --vault-config /etc/argos/vault-admin.toml bundle review \
  --agent-id orders-host --id BUNDLE_ID \
  --request-id review-orders-42 --decision good \
  --actor operator-a --reason '백업 내용과 복구 계획 검토 완료'
```

`list` 응답의 `next_cursor`가 있으면 다음 요청에 `--after CURSOR`를 전달한다. 한 페이지 최대 100개다. `show`는 구성 목록 수신증명·완료 증명·순서가 연결된 검토 이력을 고정 공개키로 검사한다. `review` 재시도에는 같은 요청 ID와 같은 내용을 사용한다. 판정을 변경할 때는 새 요청 ID가 필요하다.

```bash
argos vault --vault-config /etc/argos/vault-admin.toml bundle review \
  --agent-id orders-host --id BUNDLE_ID \
  --request-id revoke-orders-42 --decision revoked \
  --actor operator-a --reason '후속 조사에서 손상 확인'
```

취소는 바이트를 삭제하지 않고 새로운 이력을 추가한다. 이후 일반 복구와 시험은 보류된다. 원본 판정 이력 JSON을 수정하거나 예전에 받은 `good` 응답을 재사용하여 현재 판정을 대신할 수 없다.

## 새 호스트에서 재조립과 시험

```bash
argos vault --vault-config /etc/argos/vault-admin.toml bundle fetch \
  --agent-id orders-host --id BUNDLE_ID \
  --out /srv/argos-restore/orders.sqlite3

argos vault --vault-config /etc/argos/vault-admin.toml bundle test \
  --agent-id orders-host --id BUNDLE_ID \
  --out /srv/argos-restore/orders-drill-42
```

`fetch`는 청크 수신증명과 전체 파일 해시를 확인하고 게시 직전에 현재 판정을 다시 조회한다. 원본 경로는 출력 목적지로 사용하지 않는다. 미확인·취소 묶음을 사고 조사 목적으로 받아야 할 때만 `--evidence-only`를 사용한다. 이 모드는 완성된 묶음의 바이트 검증을 수행하지만 결과를 복구 추천으로 표시하지 않는다.

`test`는 원격의 완료·정상 판정을 확인하고 내장 계획의 `backup_path`만 새 `backup.bin`으로 변경한다. 서버 원본 경로나 로컬 에이전트 DB를 읽지 않는다. 테이블·최소 행 수·검사 ID·DB 엔진·자원 제한 등 다른 계획 필드는 유지한다. 계획이 없거나 유효하지 않으면 시험을 거부한다. PostgreSQL 계획은 새 호스트에 동일한 신뢰 설치 경로가 존재해야 하며 임의 명령이나 운영 DB 연결은 허용하지 않는다.

복구 시험은 기존 고정 작업 프로세스의 시간·출력·파일·메모리 제한과 DB 격리를 사용한다. 시험 성공 후 현재 계획·백업에 대한 보고서 일관성을 재검증하고, 마지막으로 원격 정상 판정과 동일 구성 목록·완료 증명을 다시 확인한다. 이 단계 중 하나라도 실패하면 `recommended=false` 및 0이 아닌 종료 코드를 반환한다.

표준 출력에는 다음 내용을 포함한 단일 JSON이 나온다. 같은 내용을 새 `0600` 파일 `bundle-test.json`에도 저장한다.

| 필드 | 의미 |
|---|---|
| `status`, `recommended`, `failure_code` | 시험 및 최종 현재 판정 결과 |
| `drill_report` | 기존 서비스 복구 시험 결과 |
| `verification` | 현재 계획·백업·보고서 일관성 확인 |
| `remote_review_authenticated` | 조회한 원격 완료·판정 자료의 서버 서명 검증 여부 |
| `report_authenticated` | 항상 `false`: 로컬 시험 보고서는 무서명 |
| `trial_executor_authenticated` | 항상 `false`: 시험 실행자 신원은 인증하지 않음 |
| `original_agent_database_used` | 항상 `false`: 원본 에이전트 DB를 사용하지 않음 |

성공 시 작업 디렉터리에는 `backup.bin`, `plan.toml`, `manifest.json`, `drill/service-recovery.json`, `remote-record.json`, `bundle-test.json`이 남는다. 실패 시에도 생성된 자료를 보존하므로 자동 재시도에는 새 출력 경로를 사용한다. 출력 경로 자체나 저장 권한이 잘못된 경우에는 요약 파일 생성도 실패할 수 있다.

서명된 보관·판정 이력과 무서명 로컬 시험 결과는 다른 근거다. 최종 `good` 조회 뒤 추가 취소가 발생할 수 있으며, 성공한 DB 검사가 업무 서비스 전체의 복구·데이터의 업무적 정상성·RPO를 증명하지는 않는다. 시험 보고서의 실행자 서명과 중앙 검증은 후속 개발 범위다.
