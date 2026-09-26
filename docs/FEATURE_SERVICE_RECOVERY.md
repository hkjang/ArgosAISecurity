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
| `status`, `checks` | 네이티브 복원과 계획에 지정한 검사 통과 여부 |
| `backup_sha256`, `backup_bytes` | 실제 검사한 입력 사본의 무결성·크기; 정상 데이터 판정을 의미하지 않음 |
| `restore_duration_ms` | 백업 준비 및 DB 복원에 걸린 실측 시간 |
| `validation_duration_ms` | 고정된 DB 검증에 걸린 실측 시간 |
| `total_duration_ms` | 이번 로컬 드릴 실행 시간 |
| `declared_recovery_point_ms` | 선택적으로 제공한 운영자 주장; DB가 확인한 마지막 커밋 시점이 아님 |
| `rpo_ms = null` | 운영 원본의 마지막 커밋 시점을 알 수 없으므로 RPO 미확인 |
| `service_rto_ms = null` | 애플리케이션 기동과 사용자 업무 정상화까지 시험하지 않았으므로 서비스 RTO 미확인 |

시점 미지정 상태를 파일 수정 시각으로 채우거나 백업 시점과 사고 시점의 차이를 검증된 RPO로 표시하지 않습니다. 행 수가 충분해도 비즈니스 데이터의 의미가 올바름을 증명하지는 않습니다. 이 결과는 서비스별 복구 절차의 DB 단계 근거이며 전체 서비스 복구 완료 판정은 별도입니다.

## 실행 한계와 안전 경계

- 제한 시간은 1–300초, 입력 크기 제한은 512바이트–1GiB, 테이블 검사는 1–32개입니다. CLI는 고정된 자체 작업 프로세스를 감독해 제한 시간 초과 시 종료합니다. 라이브러리 API 직접 호출은 협력적 타임아웃이며 정지된 커널 I/O나 프로세스 정리 대기까지 강제 중단하지는 못합니다. CLI는 시간 초과 시 SIGKILL 후 정리를 별도 스레드로 넘겨 실패 결과를 반환합니다. 커널의 중단 불가능 I/O 상태에서는 작업 프로세스의 즉시 소멸까지 보장하지 않으며, 해당 I/O가 풀리면 종료 신호가 처리됩니다.
- 타임아웃 또는 작업 프로세스 출력 상한 초과 시 감독 프로세스의 실패 보고서는 표준 출력으로 제공됩니다. 작업 디렉터리에 불완전한 파일이 남을 수 있으며 완료 보고서가 있다는 가정을 해서는 안 됩니다. 같은 경로 재실행은 거부하므로 검토 후 별도로 정리하거나 새 경로를 사용합니다.
- PostgreSQL 출력은 스트림별 64KiB, 보고서는 256KiB로 제한합니다. 전체 작업 파일 크기(기본 512MiB, 최대 8GiB)와 파일/디렉터리 50,000개를 주기적으로 검사합니다. 프로세스별 파일 크기·CPU·주소 공간 제한을 적용하지만 검사 사이 일시적 초과가 가능하며 namespace는 VM이나 파일시스템 용량 할당량을 대신하지 않습니다. 불신 백업 검사는 별도 시험 호스트와 용량 제한된 전용 파일시스템에서 수행하는 것이 적합합니다.
- 백업과 작업 디렉터리의 부모 경로는 운영자가 관리해야 합니다. root 또는 같은 운영 사용자 권한을 가진 다른 프로세스의 변조/삭제를 막는 원격 권한 경계가 아닙니다. PostgreSQL 드릴은 root 실행을 거부합니다.

## 재현 가능한 검증

`service-recovery-scenarios.py`는 임시 디렉터리의 합성 데이터로 실제 CLI를 실행합니다. 기본 실행은 SQLite를 검증하며, `--pg-root`를 주면 PostgreSQL 18 도구로 격리된 fixture와 custom 백업을 만들고 같은 CLI를 검증합니다. 운영 DB를 사용하지 않습니다.

```bash
python3 scripts/service-recovery-scenarios.py --bin-dir target/debug
python3 scripts/service-recovery-scenarios.py --bin-dir target/debug \
  --pg-root /path/to/trusted/postgresql-package-root
cargo test -p argos-recovery
ARGOS_TEST_POSTGRES_ROOT=/path/to/trusted/postgresql-package-root \
  cargo test -p argos-recovery postgresql_custom_archive -- --ignored
```

SQLite 원본 불변·쓰기 롤백·기대 행 수 실패·기존 작업 경로 거부·WAL 동반 입력 거부·SQL 식별자 주입 거부와 PostgreSQL 복원·제약·서버 종료·시간 초과를 확인합니다. PostgreSQL 시간 초과 fixture에는 고정 2초 지연 트리거를 넣어 빠른 장비에서도 제한 시간 동작을 재현합니다. 이는 검증 스크립트의 고정 합성 SQL이며 제품 계획에서 임의 SQL을 허용하는 기능이 아닙니다. 선택 PostgreSQL 테스트는 쓰기 가능한 경로의 passwd/group를 합성 호스트 마커 파일의 symlink로 바꾼 뒤, 다음 client namespace에도 호스트 마커가 노출되지 않는지 확인합니다. 실제 비밀 파일이나 운영 데이터는 사용하지 않습니다.
