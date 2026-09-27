# 서비스 수준 DB 복구 검증

`argos service-recovery test`는 **로컬 네이티브 DB 백업을 새 작업 디렉터리에 복원하고 고정된 DB 검사를 수행**합니다. 기존 `recovery-status --test`의 파일 해시 확인과 구분됩니다. 운영 DB 접속, 운영 파일 덮어쓰기, 사용자 SQL/셸 명령 실행 옵션은 제공하지 않습니다.

## 지원 범위

- **SQLite**: SQLite Backup API로 만든 독립된 DB 파일. WAL/SHM/journal 파일이 함께 있는 실행 중 DB는 거부합니다. Backup API 복원 후 `integrity_check`, 외래 키, 선택한 `user_version`, 테이블·필수 열·최소 행 수, 쓰기/읽기/롤백을 검사합니다. 가상 테이블과 조회 대상으로 지정한 뷰는 지원하지 않습니다.
- **PostgreSQL**: `pg_dump --format=custom` 아카이브. Linux의 작동하는 `/usr/bin/bwrap`, 신뢰하는 PostgreSQL 도구 설치, 일반 사용자 권한이 필요합니다. 새 클러스터의 Unix socket으로만 복원합니다. TCP 수신과 외부 네트워크를 차단하고 호스트 보고서 디렉터리는 격리 환경에 노출하지 않습니다. `pg_restore --exit-on-error --single-transaction` 및 미검증 FK/CHECK 제약 확인, `public` 스키마의 일반 테이블·필수 열·행 수, 쓰기/읽기/롤백 검사를 수행합니다. RLS가 활성화된 검사 대상 테이블은 거부합니다. PostgreSQL 18.6과 Debian 계열 x86_64 패키지 경로에서 실행 검증하며, 설치 설정은 14–18을 허용하지만 모든 버전/배포판 조합을 검증한 것은 아닙니다.
- MySQL, SQLite SQL 덤프, PostgreSQL plain SQL/tar/directory 형식, 임의 접속 문자열, 운영 애플리케이션 시작/HTTP 헬스 검사는 지원하지 않습니다. PostgreSQL sandbox가 없거나 초기화에 실패하면 호스트 실행으로 대체하지 않습니다.

## SQLite 계획 예

먼저 SQLite Backup API 또는 `sqlite3`의 `.backup`으로 별도 백업을 생성합니다. 직접 실행 중 DB 파일만 복사하면 WAL에 있는 최신 변경을 빠뜨릴 수 있습니다. 다음 TOML에서 경로와 기대값을 실제 서비스에 맞게 지정합니다.

```toml
service_id = "orders-db"
engine = "sqlite"
backup_path = "/srv/argos-drills/input/orders.sqlite3"
timeout_secs = 30
max_backup_bytes = 134217728
max_workspace_bytes = 536870912
expected_user_version = 7
# 다음 시점은 운영자가 확인한 값일 때만 기입합니다(epoch ms).
# declared_recovery_point_ms = 1790000000000
# incident_at_ms = 1790000060000

[[tables]]
check_id = "orders-schema-and-rows"
table = "orders"
required_columns = ["id", "customer_id", "total"]
min_rows = 1
```

```bash
argos service-recovery test --plan /srv/argos-drills/orders.toml \
  --out /srv/argos-drills/results/orders-20260927
```

출력 대상의 부모 디렉터리는 미리 만들되 마지막 디렉터리는 없어야 합니다. 작업 디렉터리는 0700, 백업 사본·보고서는 0600으로 생성합니다. 원본 백업은 읽기만 하며, 작업 디렉터리와 백업에는 실제 업무 데이터가 있으므로 접근을 제한합니다. 보고서에는 행 내용·DB 오류 원문·접속 비밀값을 싣지 않습니다.

## PostgreSQL 계획 예

신뢰하는 로컬 패키지 설치 트리를 지정합니다. 표준 `/usr/lib/postgresql/18/bin` 설치는 `installation_root = "/"`입니다. 임시 추출된 패키지도 동일한 `usr/lib/postgresql/18/{bin,lib}`, `usr/share/postgresql/18`, `usr/lib/x86_64-linux-gnu` 구조를 제공하면 사용할 수 있습니다. 도구 설치 경로의 코드는 운영자가 신뢰해야 합니다. 작업 디렉터리를 도구·런타임의 읽기 바인드 경로 안에 두면 보고서가 별도 경로로 노출될 수 있어 거부합니다.

```toml
service_id = "orders-postgresql"
engine = "postgresql"
backup_path = "/srv/argos-drills/input/orders.dump"
timeout_secs = 60
max_backup_bytes = 134217728
max_workspace_bytes = 536870912

[postgresql]
installation_root = "/"
major_version = 18

[[tables]]
check_id = "orders-schema-and-rows"
table = "orders"
required_columns = ["id", "customer_id", "total"]
min_rows = 1
```

사용 명령은 SQLite와 같습니다. 계획의 테이블·열은 단순 ASCII SQL 식별자만 허용합니다. PostgreSQL의 검사 대상은 `public` 스키마 일반 테이블입니다. 사용자 SQL, 임의 셸 명령, DSN, 확장 프로그램 설치 옵션을 계획에 넣으면 파싱 단계에서 거부합니다. 백업 자체에 포함된 SQL이 코드를 실행할 수 있으므로 PostgreSQL 도구와 서버는 항상 namespace 안에서 실행합니다. 격리 환경에서만 복구용 DB 슈퍼유저를 사용하고, 호스트 운영 DB 자격 증명을 전달하지 않습니다.

## 결과 해석

정상 완료 시 표준 출력과 새 디렉터리의 `service-recovery.json`에 결과를 기록합니다. 실패 시 종료 코드는 0이 아니며 구체적인 `failure_code`를 확인합니다.

| 필드 | 의미 |
|---|---|
| `format = "argos-service-recovery-v2"` | 계획 결합 필드를 포함한 보고서 형식 |
| `plan_hash_version`, `plan_sha256` | 정규화 규칙 버전과 백업 경로를 제외한 계획의 SHA-256 |
| `expectations_sha256`, `required_check_ids` | 검사 기대값의 SHA-256과 필요한 정확한 검사 ID 목록 |
| `status`, `checks` | 네이티브 복원과 계획에 지정한 검사 통과 여부 |
| `backup_sha256`, `backup_bytes` | 실제 검사한 입력 사본의 무결성·크기; 정상 데이터 판정을 의미하지 않음 |
| `restore_duration_ms` | 백업 준비 및 DB 복원에 걸린 실측 시간 |
| `validation_duration_ms` | 고정된 DB 검증에 걸린 실측 시간 |
| `total_duration_ms` | 이번 로컬 드릴 실행 시간 |
| `declared_recovery_point_ms` | 선택적으로 제공한 운영자 주장; DB가 확인한 마지막 커밋 시점이 아님 |
| `rpo_ms = null` | 운영 원본의 마지막 커밋 시점을 알 수 없으므로 RPO 미확인 |
| `service_rto_ms = null` | 애플리케이션 기동과 사용자 업무 정상화까지 시험하지 않았으므로 서비스 RTO 미확인 |

시점 미지정 상태를 파일 수정 시각으로 채우거나 백업 시점과 사고 시점의 차이를 검증된 RPO로 표시하지 않습니다. 행 수가 충분해도 비즈니스 데이터의 의미가 올바름을 증명하지는 않습니다. 이 결과는 서비스별 복구 절차의 DB 단계 근거이며 전체 서비스 복구 완료 판정은 별도입니다.

## 과거 복구 시험 결과가 현재 계획에도 유효한지 확인

새 드릴 보고서에는 계획과 검사 기대값 해시를 기록합니다. 다음 명령은 현재 계획과 백업에 대해 해당 성공 보고서를 재사용할 수 있는 **일관성·최신성 조건**을 확인합니다. DB를 다시 복원하거나 검사를 재실행하는 명령은 아닙니다.

```bash
argos service-recovery verify --plan /srv/argos-drills/orders.toml \
  --report /srv/argos-drills/results/orders-20260927/service-recovery.json \
  --max-age-secs 86400
```

`--max-age-secs`는 반드시 명시한 양의 정수이며 보고서 **완료 시점**부터의 최대 경과 시간입니다. 경계 시점까지 허용하고 그보다 오래됐거나 시작·완료 시점이 미래이면 거부합니다. 성공 결과는 `status = "consistent"`입니다. 계획 읽기·유효성 검사를 통과한 뒤 보고서 검증 실패는 `status = "rejected"`와 `failure_code` JSON 및 비영 종료 코드로 표시합니다. 명령 인수·계획 읽기/파싱/유효성 오류는 JSON 대신 표준 오류와 비영 종료 코드로 표시합니다. 모든 성공 결과에도 `report_authenticated = false`가 표시됩니다. 보고서는 **서명되지 않았으므로 작성자·실제 실행 여부·위조 방지를 증명하지 않습니다.** 보고서를 수정할 수 있는 사람은 해시와 결과도 다시 작성할 수 있습니다.

검증은 다음을 모두 요구합니다.

- 보고서 형식 v2와 계획 해시 버전 1, 성공 상태, 실패 코드 없음, 허용 기간 내의 일관된 시각
- 현재 계획과 `plan_sha256`·`expectations_sha256` 일치
- 계획에서 계산한 검사 ID 목록과 보고서의 실제 검사 목록이 정확히 일치하고, 누락·중복·추가 검사 없음
- 모든 검사 `passed = true`, `code = "ok"`, 테이블별 관측 행 수가 현재 `min_rows` 이상; PostgreSQL 미검증 제약 관측 수는 0
- 현재 백업 파일 **전체**의 SHA-256·크기가 보고서와 일치; 파일 변경·경로 교체·SQLite WAL/SHM/journal 동반 상태 없음

예를 들어 `min_rows`를 1에서 100으로 바꾸거나 필수 열을 추가한 뒤 과거 성공 보고서를 제출하면 거부합니다. v0.3의 v1 보고서와 계획 결합 필드가 없는 보고서도 거부하므로 새 `service-recovery test`를 실행해야 합니다. 실패 보고서의 `status`만 성공으로 고쳐도 다른 검사 결과·필수 목록이 맞지 않으면 거부하지만, 이것이 서명 검증을 대신하지는 않습니다.

### 계획 정규화 규칙

계획 TOML을 파싱해 기본값을 적용한 뒤 JSON 객체 키를 재귀적으로 정렬합니다. 테이블은 `check_id` 순으로, 각 `required_columns`는 정렬·중복 제거해 해시합니다. 따라서 TOML 공백·주석·키 순서, 테이블 검사 순서, 필수 열 순서·중복은 해시를 바꾸지 않습니다. 검사 ID·테이블 이름·필수 열 집합·최소 행 수·`expected_user_version`은 의미 있는 기대값입니다.

`plan_sha256`에는 `service_id`, 엔진, 실행 시간·백업 크기·작업 공간 제한, 선언한 복구·사고 시점, 검사 기대값, PostgreSQL 설정을 포함합니다. **`backup_path`는 제외**합니다. 같은 내용의 백업을 다른 절대 경로로 옮긴 경우 전체 내용 해시·크기가 같으면 허용합니다. PostgreSQL `installation_root`는 포함하되 `.`과 중복 경로 구분자만 정리하며 symlink를 해석하지 않습니다. 다른 설치 루트나 major version, 실행 제한으로 바꾸면 새 시험이 필요합니다. 같은 설치 경로의 실제 도구 바이너리가 바뀌었는지는 이 기능이 확인하지 않습니다.

`expectations_sha256`는 엔진·`expected_user_version`·정규화한 테이블 기대값·정렬된 필수 검사 ID만 결합합니다. 각 해시는 버전별 도메인 문자열(`argos-service-plan-v1` 또는 `argos-service-expectations-v1`), NUL 바이트, 공백 없는 정규화 JSON 바이트를 연결한 SHA-256입니다. 검증 결과의 `report_sha256`는 실제 읽은 보고서 원문 바이트를 식별합니다.

### 읽기 범위와 한계

현재 `verify`는 Linux에서 지원합니다. 계획은 최대 64KiB, 보고서는 최대 256KiB, 백업은 계획의 `max_backup_bytes`까지 스트리밍으로 읽습니다. 보고서와 백업은 같은 descriptor에서 각각 두 번 전체 읽고 해시를 대조하므로 파일 내용의 약 두 배를 읽는 I/O 비용이 듭니다. 두 번째 읽기도 첫 읽기와 같은 제한 시간을 공유합니다. 짧은 간격의 덮어쓰기가 파일시스템 시각 해상도에 가려져도 서로 다른 바이트를 거부합니다. 마지막 경로 요소의 symlink, 일반 파일이 아닌 FIFO·장치, 읽는 동안의 inode·크기·수정 시각·ctime 또는 경로 identity 변경을 거부합니다. 두 번 읽기는 파일시스템 스냅샷이나 배타 쓰기 잠금이 아닙니다. 부모 디렉터리는 운영자가 관리해야 하며 root나 동일 사용자 권한의 악의적인 동시 변경을 완전히 방어하는 격리 경계가 아닙니다. 파일 내용은 변경하지 않으며 OS가 접근 시각을 갱신할 수는 있습니다.

`verify`의 읽기는 계획 `timeout_secs`에 따른 협력적 제한입니다. `test`의 별도 작업 프로세스 감독과 달리 정지된 커널 파일 I/O의 즉시 중단을 보장하지 않습니다. 최신성은 호스트 시계와 보고서의 무서명 완료 시각을 사용합니다. 전체 서비스 복구, 비즈니스 데이터의 정당성, RPO·서비스 RTO를 보장하지 않습니다.

## 실행 한계와 안전 경계

- 제한 시간은 1–300초, 입력 크기 제한은 512바이트–1GiB, 테이블 검사는 1–32개입니다. `service-recovery test` CLI는 고정된 자체 작업 프로세스를 감독해 제한 시간 초과 시 종료합니다. 라이브러리 API 직접 호출은 협력적 타임아웃이며 정지된 커널 I/O나 프로세스 정리 대기까지 강제 중단하지는 못합니다. `test` CLI는 시간 초과 시 SIGKILL 후 정리를 별도 스레드로 넘겨 실패 결과를 반환합니다. 커널의 중단 불가능 I/O 상태에서는 작업 프로세스의 즉시 소멸까지 보장하지 않으며, 해당 I/O가 풀리면 종료 신호가 처리됩니다.
- 타임아웃 또는 작업 프로세스 출력 상한 초과 시 감독 프로세스의 실패 보고서는 표준 출력으로 제공됩니다. 작업 디렉터리에 불완전한 파일이 남을 수 있으며 완료 보고서가 있다는 가정을 해서는 안 됩니다. 같은 경로 재실행은 거부하므로 검토 후 별도로 정리하거나 새 경로를 사용합니다.
- PostgreSQL 출력은 스트림별 64KiB, 보고서는 256KiB로 제한합니다. 전체 작업 파일 크기(기본 512MiB, 최대 8GiB)와 파일/디렉터리 50,000개를 주기적으로 검사합니다. 프로세스별 파일 크기·CPU·주소 공간 제한을 적용하지만 검사 사이 일시적 초과가 가능하며 namespace는 VM이나 파일시스템 용량 할당량을 대신하지 않습니다. 불신 백업 검사는 별도 시험 호스트와 용량 제한된 전용 파일시스템에서 수행하는 것이 적합합니다.
- 백업과 작업 디렉터리의 부모 경로는 운영자가 관리해야 합니다. root 또는 같은 운영 사용자 권한을 가진 다른 프로세스의 변조/삭제를 막는 원격 권한 경계가 아닙니다. PostgreSQL 드릴은 root 실행을 거부합니다.

## 재현 가능한 검증

`service-recovery-scenarios.py`는 임시 디렉터리의 합성 데이터로 실제 CLI를 실행합니다. 기본 실행은 SQLite를 검증하며, `--pg-root`를 주면 PostgreSQL 18 도구로 격리된 fixture와 custom 백업을 만들고 같은 CLI를 검증합니다. 운영 DB를 사용하지 않습니다.

```bash
python3 scripts/service-recovery-scenarios.py --bin-dir target/debug
python3 scripts/service-recovery-scenarios.py --bin-dir target/debug \
  --pg-root /path/to/trusted/postgresql-package-root
python3 scripts/durability-scenarios.py --bin-dir target/debug \
  --report /tmp/argos-durability-new.json
cargo test -p argos-recovery
ARGOS_TEST_POSTGRES_ROOT=/path/to/trusted/postgresql-package-root \
  cargo test -p argos-recovery postgresql_custom_archive -- --ignored
```

SQLite 원본 불변·쓰기 롤백·기대 행 수 실패·기존 작업 경로 거부·WAL 동반 입력 거부·SQL 식별자 주입 거부와 PostgreSQL 복원·제약·서버 종료·시간 초과를 확인합니다. PostgreSQL 시간 초과 fixture에는 고정 2초 지연 트리거를 넣어 빠른 장비에서도 제한 시간 동작을 재현합니다. 이는 검증 스크립트의 고정 합성 SQL이며 제품 계획에서 임의 SQL을 허용하는 기능이 아닙니다. 선택 PostgreSQL 테스트는 쓰기 가능한 경로의 passwd/group를 합성 호스트 마커 파일의 symlink로 바꾼 뒤, 다음 client namespace에도 호스트 마커가 노출되지 않는지 확인합니다. 실제 비밀 파일이나 운영 데이터는 사용하지 않습니다.

## 원격 백업과 연결

v0.6.0의 [복구 묶음 CLI](FEATURE_RECOVERY_BUNDLE_CLI.md)는 현재 정상 판정을 확인한 원격 백업을 새 경로로 받고, 함께 보관한 계획의 백업 경로만 변경해 같은 감독·고정 DB 검사를 실행합니다. 원본 에이전트 DB는 사용하지 않으며 결과 일관성 검사와 최종 원격 판정 재조회까지 수행합니다. 서버의 완료·검토 서명과 별개로 로컬 시험 보고서는 무서명입니다.
