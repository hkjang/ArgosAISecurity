# 원격 보존과 서명 수신증명

`argos-vault`는 별도 호스트에서 파일을 받아 보관하는 서버와 검증 클라이언트다. 에이전트별 업로드 토큰, 별도 관리자 조회 토큰, SHA-256 본문 검증, Ed25519 서명 수신증명을 사용한다. API에는 삭제·덮어쓰기 작업이 없으며 동일 에이전트·해시의 재업로드는 저장된 수신증명을 그대로 반환한다.

이 기능의 보존 경계는 **인증된 추가 전용 API와 별도 저장 호스트**다. root·디스크 관리자·서명키 소유자가 저장소를 삭제하거나 과거 상태로 되돌리지 못하게 하는 OS/S3 WORM 저장소는 아니다. 수신증명은 키 소유 서버가 특정 에이전트 토큰으로 받은 바이트·시각·보존 기한을 서명한 기록이며, 이후에도 파일이 존재한다는 실시간 증명이나 내용의 정상 판정은 아니다.

## 서버 설정

전용 서버 계정으로 개인 키와 저장소 디렉터리를 만든다. 다음 경로는 예시이며 해당 계정이 소유해야 한다.

```bash
install -d -m 0700 /var/lib/argos-vault /etc/argos-vault
argos-vault --generate-key /etc/argos-vault/signing.key
```

명령은 새 0600 비밀키 파일을 독점 생성하고 **공개키 hex만** 표준 출력에 쓴다. 공개키를 별도 신뢰 경로로 클라이언트에 전달한다. 기존 키를 덮어쓰지 않는다. `server.toml`도 전용 0700 디렉터리의 계정 소유 0600 일반 파일로 관리한다.

```toml
bind = "127.0.0.1:9080"
dir = "/var/lib/argos-vault"
signing_key_file = "/etc/argos-vault/signing.key"
key_id = "vault-1"
retention_secs = 2592000
max_object_bytes = 67108864
admin_token = "<관리자 조회 전용 무작위 토큰>"

[agent_tokens]
web-01 = "<web-01 수집 전용 무작위 토큰>"
web-02 = "<web-02 수집 전용 다른 무작위 토큰>"
```

```bash
chmod 0600 /etc/argos-vault/server.toml
argos-vault --config /etc/argos-vault/server.toml
```

토큰은 서로 다른 16~4096바이트 ASCII 비공백 값이어야 하며 충분히 긴 무작위 값을 사용한다. 예시 문자열을 그대로 사용하지 않는다. 관리자 토큰과 어떤 에이전트 토큰도 중복될 수 없다. ID·키 ID는 1~128자의 영문·숫자·`-`·`_`만 허용한다. 토큰을 명령행 인자로 넘기거나 로그에 출력하지 않는다.

기본 수신은 loopback 평문 HTTP다. 별도 호스트의 운영 접근에는 인증서 검증이 가능한 HTTPS 역방향 프록시를 구성한다. 비 loopback 평문 수신은 `allow_plain_http=true`를 명시해야 하지만 일반 클라이언트는 원격 HTTP를 거부한다. TLS 프록시·네트워크 경계·디스크 용량 관리는 별도 배포 구성이다.

키·보관 디렉터리는 절대 경로와 현재 계정 소유 0700을 요구한다. 심볼릭 링크가 있는 상위 경로와 신뢰하지 않는 계정이 쓰기 가능한 상위 경로를 거부한다. root 소유 sticky 임시 디렉터리 아래의 전용 디렉터리는 시험용으로 허용한다. 키와 보관 파일은 0600 단일 하드링크 일반 파일이어야 한다. 서명키 교체 후 과거 키의 수신증명을 서버에서 함께 제공하는 다중 키 회전은 현재 구현하지 않았다. 기존 보관소의 키를 임의 교체하지 않는다.

## 클라이언트 설정과 업로드

별도 TOML 설정에 서버 주소와 **미리 신뢰한 공개키·키 ID**를 기록한다. 에이전트에는 업로드 토큰만, 복구 담당자에게는 별도 관리자 조회 토큰을 배포한다. 아래 예시에서 역할에 필요 없는 토큰은 빈 문자열로 두거나 생략한다. 설정 파일은 해당 계정만 읽도록 관리한다.

```toml
endpoint = "https://vault.example.internal"
agent_id = "web-01"
upload_token = "<web-01 수집 토큰>"
admin_token = ""
pinned_pubkey = "<서버에서 별도 신뢰 경로로 전달한 공개키 hex 64자>"
key_id = "vault-1"
max_object_bytes = 67108864
timeout_secs = 30
allow_http_loopback = false
```

```bash
argos vault upload --vault-config /etc/argos/vault-client.toml \
  --file /secure/export/incident-42.json --kind evidence \
  --receipt /secure/receipts/incident-42.json

argos vault verify --file /secure/export/incident-42.json \
  --receipt /secure/receipts/incident-42.json --pubkey PUBLIC_KEY_HEX
```

`kind`는 `evidence`, `backup`, `audit` 중 하나다. 형식·정상 여부를 자동 판정하는 값이 아니라 수신증명에 서명되는 분류다. 일반 파일 업로드는 SHA-256과 크기를 확인한 **동일한 한 번의 읽기 결과**를 전송한다. 심볼릭 링크·특수 파일·크기 초과·읽는 동안 바뀐 크기/시각/파일 신원을 거부한다. 새 수신증명 파일은 0600으로 독점 생성하며 기존 파일을 덮어쓰지 않는다.

클라이언트는 HTTPS를 요구하고 리다이렉트를 따르지 않는다. URL 안의 사용자명·비밀번호·경로·질의·fragment는 거부한다. 시험용 HTTP는 `allow_http_loopback=true`와 숫자 loopback 주소를 함께 지정해야 한다. `localhost` 같은 DNS 이름을 loopback으로 추정하지 않고 시험용 HTTP에서는 환경변수 프록시도 사용하지 않는다. HTTP 요청은 기본 30초, 최대 300초 제한이다.

v0.7.0은 선택적 `tls_ca_pem` 문자열로 사설 CA 목록을 지정한다. 최대 64KiB·16개 인증서이며 지정하면 내장 CA 대신 해당 목록만 신뢰한다. 호스트명·체인 검사는 유지하고 HTTP와의 혼용을 거부한다. 큐는 PEM 원문 SHA-256을 대상에 고정하므로 미완료 전송 중 신뢰 목록을 바꾸면 거부한다. 보관 서버의 서명키 교체와 별개다. [TLS·장애 시험](FEATURE_BUNDLE_OPERATIONS.md)을 참고한다.

응답은 최대 16 KiB로 읽고 고정 공개키의 서명, 요청한 키 ID·에이전트 ID·종류·해시·크기를 검증한다. 서버가 돌려준 공개키를 자동 신뢰하지 않는다. 키 ID는 공개키를 대신하지 않으며 수신증명 파일만으로 신뢰 키를 선정하지 않는다.

## 정상본·증거 패키지 연계

```bash
argos --config argos.toml vault upload-backup /srv/data/report.txt \
  --version 23 --vault-config /etc/argos/vault-client.toml \
  --receipt /secure/receipts/report-v23.json

argos vault upload-evidence --package /secure/export/incident-42 \
  --vault-config /etc/argos/vault-client.toml \
  --receipts /secure/receipts/incident-42
```

정상본 어댑터는 지정 백업 버전의 정상 판정과 별도 미리보기 해시를 확인한 후 업로드한다. 일반 파일 `--kind backup`만 지정하는 동작과 구별한다. 증거 패키지 어댑터는 [패키지 검증](FEATURE_EVIDENCE_PACKAGE.md)을 거친 바이트를 개인 임시 디렉터리의 스냅샷으로 만들어 올리고 manifest는 마지막에 전송한다. 패키지의 여러 객체를 원격에서 한 트랜잭션으로 게시하는 기능은 아니다. 일부 실패 시 이미 보관된 객체가 남을 수 있으며 같은 에이전트·해시·종류로 재전송하면 같은 증명을 받는다. 재시도 시 기존 수신증명 디렉터리를 덮어쓰지 않고 새 디렉터리를 지정한다.

에이전트 이벤트 루프에서 모든 백업을 자동 원격 전송하는 기능은 아니다. 보존 대상을 운영자가 명시적으로 선택한다. 수신 서버가 백업의 정상 판정 근거를 다시 검증하거나 사건 보존 승인 절차를 대신하지 않는다.

## 조회·별도 파일 복원

관리자용 설정에는 `admin_token`을 별도로 넣는다.

```bash
argos vault fetch --vault-config /etc/argos/vault-admin.toml \
  --agent-id web-01 --sha256 OBJECT_SHA256 \
  --out /secure/review/recovered-file \
  --receipt /secure/receipts/fetched-object.json
```

클라이언트는 수신증명을 먼저 받아 고정 키와 요청 에이전트·해시를 확인한 뒤 본문을 받는다. 본문 크기·해시까지 확인한 후 **새 파일**에만 0600으로 기록한다. 원본에 직접 덮어쓰거나 애플리케이션을 재시작하지 않는다. 복원한 바이트가 운영에 안전한지, 애플리케이션 전체가 일관적인지는 별도 복구 검토가 필요하다.

업로드 토큰은 관리자 조회에 사용할 수 없고 관리자 토큰은 업로드에 사용할 수 없다. 다른 에이전트의 토큰으로 받은 수신증명은 클라이언트의 기대 에이전트 ID와 달라 검증에 실패한다. 서버의 에이전트 ID는 토큰에서만 정하며 임의 `X-Argos-Agent-ID` 헤더는 거부한다.

## API·내구성·상한

| API | 인증과 동작 |
| --- | --- |
| `POST /v1/objects/{sha256}` | 에이전트 토큰, raw body와 `X-Argos-Kind`. 본문 해시 검증 후 저장·서명 |
| `GET /v1/objects/{agent}/{sha256}` | 관리자 토큰, 저장된 수신증명과 일치하는 본문만 반환 |
| `GET /v1/receipts/{agent}/{sha256}` | 관리자 토큰, 저장 본문까지 검증한 수신증명 반환 |
| `GET /v1/usage` | 관리자 토큰, 논리 사용량·한도·디스크 여유·차단 이유 조회 |
| DELETE/PUT | 삭제·덮어쓰기 경로 없음 |

수신증명은 다음 필드의 고정 구조 JSON 바이트에 Ed25519 서명을 적용한다. `signature_hex`는 서명 대상 본문 밖에 둔다. 필드·형식이 바뀌면 서명을 다시 검증해야 한다.

```text
receipt: format, key_id, agent_id, kind, sha256, size_bytes,
         received_at_ms, retention_until_ms
signature_hex
```

객체와 수신증명은 에이전트별 디렉터리에서 별도 파일로 저장한다. 완성된 0600 임시 파일을 동기화하고 하드링크로 새 대상에 독점 게시한 뒤 임시 이름을 제거하고 디렉터리를 동기화한다. 객체와 메타데이터의 게시가 완료된 후에만 증명을 응답한다. 동일 에이전트·해시의 다른 종류나 저장된 해시/메타데이터 충돌은 거부한다.

두 파일은 단일 파일시스템 트랜잭션이 아니다. v0.4.0에서는 ACK 전 중단으로 객체만 남는 등 부분 게시가 발견되면 신규 쓰기를 막고 관리자 상태에 표시한다. 자동 수리하지 않는다. ACK 유실·정상 재시작 후에는 기존 증명을 반환해 수신 시각·기한을 바꾸지 않는다. 손상된 객체/증명, 게시 중 남은 비정상 링크 상태 등은 성공으로 복구했다고 표시하지 않고 오류로 거부한다. 전원 차단·파일시스템별 내구성은 별도 환경 시험이 필요하다.

본문은 요청당 최대 64 MiB이며 서버/클라이언트가 더 작은 상한을 설정할 수 있다. 업로드 본문 수집 제한은 30초, 파일 처리 동시 허용은 4건이다. 단일 객체는 제한한 본문을 메모리에 읽는다. v0.6.0의 [복구 묶음](FEATURE_RECOVERY_BUNDLE.md)은 최대 1GiB 백업을 16MiB 청크로 나눠 처리하며 단일 객체 상한은 유지한다. 물리 디스크 예약·전체 자원 자동 제어는 제공하지 않는다. v0.4.0부터 [논리 용량 한도와 최소 디스크 여유](FEATURE_VAULT_CAPACITY.md)를 검사한다. 다운로드 연결 수와 외부 프로세스의 디스크 소비는 별도로 제어해야 한다.

보존 기한은 **서버 설정**의 수신 시각+기간으로 결정한다(1초~10×366일). 클라이언트가 단축할 수 없다. 현재 서버에는 만료 후 자동 정리도 없으므로 기한이 지나도 API를 통한 삭제는 제공하지 않는다. 영구 저장 보장·법적 보존 인증으로 해석하지 않는다. root/디스크 관리자의 삭제 방지는 별도 OS 권한 분리, 외부 감사, S3 Object Lock 같은 저장 계층이 필요하다.

## 개발 API와 검증

라이브러리는 `upload_file`, `fetch_file`, `verify_file`, `verify_receipt`, `read_receipt`, `write_receipt_new`, `generate_signing_key_file`을 공개한다. 서버는 `load_server_config`와 `router`를 사용한다. 설정의 Debug 출력에는 토큰을 넣지 않으며 원격 오류 본문을 클라이언트 오류에 그대로 포함하지 않는다.

```bash
CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/argos-recovery-target \
  cargo test -p argos-vault --offline --locked
```

v0.3.0의 기본 6개 테스트는 실제 loopback HTTP 업로드·재업로드·서버 재시작·원본 삭제 후 관리자 복원, 해시/서명/모든 서명 메타데이터·잘못된 키, 에이전트 사칭·토큰 역할·중복 토큰, DELETE/PUT·본문 충돌 거부, 크기 상한·리다이렉트·HTTP 경계, 키 권한·심볼릭/하드링크·특수 파일·읽기 중 변경·저장소 변조 거부를 확인한다. 외부 서비스 배포나 운영 호스트 방화벽 변경 없이 임시 디렉터리와 로컬 서버로 실행한다. 실제 원격 TLS 배포, 전원 차단 내구성, WORM 저장 장치 연동은 이 시험의 완료 범위가 아니다.

## 중단·용량 초과 처리

`vault queue`는 등록 당시 바이트를 로컬 디스크에 보존하고 명시적 재시도를 제공한다. [전송 대기열](FEATURE_VAULT_QUEUE.md)의 한도·완료 이력·수신증명 확인 절차를 따른다. 서버는 Linux 저장소 작성자 잠금과 시작 시 사용량 재구성, 전체/에이전트별 용량·디스크 여유 검사를 사용한다. 기본값과 업그레이드 영향은 [보관 용량](FEATURE_VAULT_CAPACITY.md)에 정리한다.

원본 에이전트 DB가 없는 복구에는 [번들 CLI](FEATURE_RECOVERY_BUNDLE_CLI.md)의 원격 목록·현재 관리자 판정·새 파일 재조립·내장 계획 시험을 사용한다. 단일 백업과 메타데이터를 보존하는 기능이며, 기존 사건 패키지 3개 파일의 자동 원자적 게시를 제공하지 않는다.
