# 원본 호스트 없는 복구 묶음 CLI

`argos vault bundle`은 최대 1GiB 백업을 16MiB 청크로 보관하고, 원본 에이전트 DB 없이 새 호스트에서 목록 조회·재조립·DB 복구 시험을 수행한다. 서버 동작과 서명 범위는 [복구 묶음](FEATURE_RECOVERY_BUNDLE.md), 기존 DB 검사와 제한은 [서비스 복구 시험](FEATURE_SERVICE_RECOVERY.md)을 참고한다.

원본 경로·버전·판정 이력은 등록자의 주장이다. 준비 또는 전송 성공만으로 정상본이 되지 않는다. 서버의 완료 증명과 관리자 토큰으로 추가한 현재 `good` 판정이 있어야 일반 `fetch` 및 `test`를 수행한다. 완성됐지만 아직 `unknown`인 묶음은 명시적인 `test --preapproval`로 격리 시험할 수 있으며, 성공해도 판정이나 운영 복구 승인을 변경하지 않는다. 검토 이력의 서버 서명은 요청에 적힌 담당자 개인의 신원 인증을 뜻하지 않는다.

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

준비 디렉터리에는 `manifest.json`과 `chunks/<sha256>.bin`이 생성된다. 파일 전체를 메모리에 읽지 않고 청크 단위로 처리한다. 복구 계획은 최대 64KiB의 고정 형식 TOML이며, 원본 판정 이력 입력 JSON은 최대 128KiB다. 직접 `upload` 재시도나 수동 `publish`에는 stage 또는 구성 목록을 보존해야 한다. 영속 `enqueue`가 성공한 뒤에는 필요한 청크와 구성 목록이 큐에 고정되므로 stage를 삭제해도 된다. 준비 도중 실패한 디렉터리는 완료된 stage가 아니며 자동 삭제하지 않는다.

지속적인 전송에는 영속 큐를 사용할 수 있다.

```bash
argos vault --vault-config /etc/argos/vault-upload.toml bundle enqueue \
  --stage /srv/argos-bundle-work/orders-stage \
  --directory /srv/argos-bundle-work/upload-queue \
  --max-items 1000 --max-bytes 1073741824

argos vault --vault-config /etc/argos/vault-upload.toml queue drain \
  --directory /srv/argos-bundle-work/upload-queue --max-items 64

argos vault queue show-bundle \
  --directory /srv/argos-bundle-work/upload-queue --id BUNDLE_ID
```

`enqueue`는 전체 청크·전체 파일 해시와 한도를 검사한 뒤 청크 참조·구성 목록·완료 요청을 하나의 영속 작업으로 원자적으로 등록하며 통신하지 않는다. 같은 해시의 청크는 재사용한다. 검증 실패 시 빈 큐 디렉터리와 DB가 남을 수 있지만 일부 청크나 작업만 등록하지 않는다. 성공 응답은 `bundle_id`, `chunk_items`, `state`, `phase`, `recommended=false`를 포함한 작업 JSON이다. 기본 큐 바이트 상한은 256MiB이므로 큰 백업에는 적절한 `--max-bytes`가 필요하다. 보관 클라이언트의 `max_object_bytes`는 16MiB 청크를 수용해야 한다.

`queue drain`과 선택 설치한 예약 전송은 청크 전송 뒤 구성 목록 등록·완료 검사까지 재시도한다. 한 번의 `--max-items` 또는 시간 예산 안에 끝나지 않으면 다음 실행이 이어간다. `phase`는 `register` → `complete` → `done`, `state`는 `pending` → `complete`로 바뀐다. 완료되기 전에는 복구 가능한 묶음으로 취급하지 않는다. 완료된 작업도 정상 판정은 별개이며 `recommended=false`를 유지한다.

기존 청크만 따로 전송했거나 구성 목록을 수동으로 마무리할 때에는 `bundle publish --manifest PATH`를 사용할 수 있다. 모든 청크와 전체 파일 해시가 확인돼야 성공한다. `queue show-bundle`은 로컬 전송 상태, 원격 `bundle show`는 보관 서버의 완료·정상 판정을 보여 준다. 서버 응답의 `recommended`는 보관 완료와 현재 `good` 판정의 조합이며, 새 호스트에서 DB 시험에 성공했다는 뜻은 아니다.

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

취소는 바이트를 삭제하지 않고 새로운 이력을 추가한다. 이후 일반 복구와 모든 복구 시험은 보류된다. 취소된 묶음은 `--preapproval`로 시험할 수도 없다. 원본 판정 이력 JSON을 수정하거나 예전에 받은 `good` 응답을 재사용하여 현재 판정을 대신할 수 없다.

## 정상본 승인 전 격리 시험

```bash
argos vault --vault-config /etc/argos/vault-admin.toml bundle test \
  --agent-id orders-host --id BUNDLE_ID --preapproval \
  --out /srv/argos-restore/orders-preapproval-42
```

이 경로는 서버의 완료 증명이 있고 현재 판정이 `unknown`인 묶음만 받는다. `good`이면 일반 `test`를 사용하며 `revoked`이면 시험을 거부한다. 시험 전, 재조립 후, 시험 종료 후 원격 자료를 조회하여 같은 구성 목록·완료 증명과 `unknown` 상태를 확인한다. 중간에 승인 또는 취소됐거나 마지막 조회가 실패하면 결과를 승인 전 시험 성공으로 표시하지 않는다. 내장 계획 누락·오류, DB 검사 실패, 격리 불가도 0이 아닌 종료 코드로 끝난다.

승인 전 시험은 Linux 5.11 이상의 `close_range(CLOSE_RANGE_CLOEXEC)` 지원이 필요하다. SQLite 승인 전 시험은 비root GNU/Linux x86_64에서 `/usr/bin/bwrap`와 사용자·네트워크·PID·마운트 네임스페이스를 요구한다. 현재 실행 파일과 root 소유의 고정 GNU 로더·`libc`, `libm`, `libgcc_s`만 읽기 전용으로 연결하며 심볼릭 링크의 실제 대상과 런타임 상위 경로의 소유자·쓰기 권한을 검사한다. 호스트 홈·설정 디렉터리·네트워크는 노출하지 않고 백업 한 파일만 읽기 전용으로 제공한다. 새 전용 작업 공간과 16MiB 임시 메모리 파일시스템을 사용한다. 격리 기능이나 필요한 런타임이 없으면 일반 프로세스로 우회하지 않는다. bubblewrap 자체에 FD 정리를 맡기지 않고, Argos가 실행 직전 `close_range`로 표준입출력 외 열린 FD를 닫히도록 설정한다. 미지원 커널이나 syscall 실패는 시험을 거부한다. 표준입출력 세 개도 감독자가 만든 계획·보고서·오류 pipe만 사용한다. 호스트에서 이미 열려 있던 파일·TCP 소켓도 입력으로 넘기지 않으며, 실제 시험에서는 `FD_CLOEXEC`를 해제한 파일·소켓 FD가 격리 자식에서 닫혀 있는지 확인한다.

PostgreSQL은 동일한 실행 전 FD 정리를 거친 고정 작업자에서 기존 bubblewrap 경로와 고정 PostgreSQL 도구·별도 클러스터를 사용한다. 이 경로는 SQLite의 개별 라이브러리 연결과 달리 필요한 시스템 런타임 디렉터리와 검증된 PostgreSQL 설치 경로를 읽기 전용으로 연결한다. 운영 DB 연결과 임의 명령은 허용하지 않는다. 양쪽 엔진 모두 기존 시간·출력·파일·메모리 제한을 유지한다. Linux 감독자는 종료한 작업자 PID를 `waitid(WNOWAIT)`로 최종 정리까지 유지한다. 작업자가 먼저 종료하고 같은 프로세스 그룹의 자식이 출력 pipe를 계속 보유하면 제한 시간에 해당 그룹을 종료한 뒤 회수한다. PID를 먼저 회수하고 재사용된 번호에 신호를 보내지 않는다. 이 감독 경계는 그룹 안에 남은 자식을 대상으로 하며, 별도 PID 네임스페이스 전체를 정리하는 bubblewrap의 경계와 구분한다. 일반 SQLite 시험에 bubblewrap 격리가 추가된 것은 아니다.

성공하더라도 `trial_passed=true`, `recommended=false`, `operational_restore_authorized=false`이며 서버 검토 이력은 바뀌지 않는다. 운영자는 시험 결과와 내용의 업무적 정상성을 검토한 뒤 별도 `bundle review --decision good` 요청을 해야 한다. 시험은 정상본을 자동 승인하는 기능이 아니다.

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

복구 시험은 기존 고정 작업 프로세스의 시간·출력·파일·메모리 제한과 DB 격리를 사용한다. 시험 성공 후 현재 계획·백업에 대한 보고서 일관성을 재검증하고, 마지막으로 원격 정상 판정과 동일 구성 목록·완료 증명을 다시 확인한다. 이 단계 중 하나라도 실패하면 `trial_passed=false`, `recommended=false` 및 0이 아닌 종료 코드를 반환한다. 일반 시험 성공은 `trial_passed=true`, `recommended=true`, `operational_restore_authorized=true`를 반환한다. 마지막 필드는 현재 원격 정상 판정과 이 시험의 조건이 충족됐음을 뜻하며, 실제 운영 파일 교체나 서비스 시작은 수행하지 않는다.

표준 출력에는 다음 내용을 포함한 단일 JSON이 나온다. 같은 내용을 새 `0600` 파일 `bundle-test.json`에도 저장한다.

| 필드 | 의미 |
|---|---|
| `status`, `failure_code` | 시험 및 최종 현재 판정 결과 |
| `preapproval`, `trial_passed` | 승인 전 모드 여부와 검증·최종 판정 확인을 모두 통과한 로컬 시험 결과 |
| `recommended`, `operational_restore_authorized` | 일반 정상본 시험 성공에서만 `true`. 승인 전 시험은 항상 `false` |
| `drill_report` | 기존 서비스 복구 시험 결과 |
| `verification` | 현재 계획·백업·보고서 일관성 확인 |
| `remote_record_authenticated` | 조회한 원격 구성 목록·완료 자료의 서버 서명 검증 여부 |
| `remote_review_authenticated` | 검증된 원격 검토 이력이 존재하는지 여부. `unknown`은 `false` |
| `report_authenticated` | 항상 `false`: 로컬 시험 보고서는 무서명 |
| `trial_executor_authenticated` | 항상 `false`: 시험 실행자 신원은 인증하지 않음 |
| `original_agent_database_used` | 항상 `false`: 원본 에이전트 DB를 사용하지 않음 |

성공 시 작업 디렉터리에는 `backup.bin`, `plan.toml`, `manifest.json`, `drill/service-recovery.json`, `remote-record.json`, `bundle-test.json`이 남는다. 실패 시에도 생성된 자료를 보존하므로 자동 재시도에는 새 출력 경로를 사용한다. SQLite 승인 전 격리가 중단되면 `.sqlite-preapproval-*` 작업 공간이 시험 출력 디렉터리 안에 남을 수 있다. 출력 경로 자체나 저장 권한이 잘못된 경우에는 요약 파일 생성도 실패할 수 있다.

서명된 보관·판정 이력과 무서명 로컬 시험 결과는 다른 근거다. 최종 `good` 조회 뒤 추가 취소가 발생할 수 있으며, 성공한 DB 검사가 업무 서비스 전체의 복구·데이터의 업무적 정상성·RPO를 증명하지는 않는다. 시험 보고서의 실행자 서명과 중앙 검증은 후속 개발 범위다.

실제 격리 경계 시험은 GNU/Linux x86_64와 비root 사용자·bubblewrap 환경에서 별도로 실행한다.

```bash
cargo test -p argos-cli service_recovery::sqlite_sandbox::tests::sandbox_hides_host_files_network_and_allows_only_private_workspace -- --ignored --exact
```

[묶음 운영 시나리오](../scripts/bundle-operations-scenarios.py)는 예약 전송 중단·재시작과 승인 전 시험/원격 승인 분리를 함께 확인한다. `--pg-root /신뢰된/PostgreSQL18/설치경로`를 추가하면 원본 native backup·계획을 삭제한 뒤 PostgreSQL 승인 전 시험도 수행한다. 이 시험은 열린 호스트 파일·TCP 소켓 FD를 CLI에 명시적으로 상속하고 실제 DB 작업자에게 남지 않는지 확인한다.
