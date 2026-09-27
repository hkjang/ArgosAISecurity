# 보관 큐 예약 전송

v0.5.0은 `argos-vault-upload.service`와 `.timer` 예제를 제공한다. 이미 큐에 등록한 파일을 일정 간격으로 전송한다. 파일을 찾아 자동 등록하거나 정상본을 자동 판정하는 기능은 아니다. [큐 운영](FEATURE_VAULT_QUEUE.md)의 활성/완료 이력·임대·오류 상태도 함께 확인한다.

## 준비

전용 `argos-upload` 계정, 그 계정 소유의 0700 큐와 0600 설정 파일을 준비한다. 기존 큐를 사용할 때는 기존 소유 계정에 맞게 유닛의 User/Group·경로를 수정한다. 실행 중인 큐의 소유권을 바꾸지 않는다. 다음 예시는 새 전용 큐를 만드는 경우다.

```bash
sudo useradd --system --user-group --home-dir /var/lib/argos-upload --shell /usr/sbin/nologin argos-upload
sudo install -d -o argos-upload -g argos-upload -m 0700 /var/lib/argos-upload
sudo install -d -o root -g argos-upload -m 0750 /etc/argos-upload
sudo install -o argos-upload -g argos-upload -m 0600 vault-client.toml /etc/argos-upload/vault-upload.toml
```

배포 예제도 `/etc/argos-upload/vault-upload.toml`을 사용한다. 다른 경로를 쓰면 서비스의 `ConditionPathExists`와 `ExecStart`를 함께 수정한다. 업로드 토큰만 설정하고 관리자 조회 토큰은 예약 전송 계정에 넣지 않는다.

```bash
sudo -u argos-upload argos vault --vault-config /etc/argos-upload/vault-upload.toml \
  queue enqueue --directory /var/lib/argos-upload/queue \
  --file /srv/argos-export/reviewed.json --kind evidence
```

입력 파일은 전송 계정이 읽을 수 있어야 한다. 등록한 뒤에는 큐의 스냅샷을 사용하므로 원본 경로에 대한 서비스 권한은 필요하지 않다. 토큰·주소를 유닛 파일이나 명령 인수에 직접 쓰지 않는다.

## 설치·조회·중지

설정 경로를 맞춘 서비스와 타이머를 설치한 후 명시적으로 활성화한다. 패키지 설치만으로 자동 시작되지 않는다.

```bash
sudo install -m 0644 packaging/argos-vault-upload.service packaging/argos-vault-upload.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now argos-vault-upload.timer
systemctl list-timers argos-vault-upload.timer
sudo journalctl -u argos-vault-upload.service -n 100 --no-pager
sudo -u argos-upload argos vault queue status --directory /var/lib/argos-upload/queue
# 예약 중지. 이미 실행 중인 전송도 중지하려면 서비스까지 지정한다.
sudo systemctl stop argos-vault-upload.timer argos-vault-upload.service
```

기본 주기는 부팅 후 약 1분, 직전 작업이 끝난 뒤 약 1분이다. 5초 정확도와 최대 10초 무작위 지연이 있어 정확한 벽시계 분 단위 실행은 아니다. 종료 후 다음 작업을 예약하므로 한 서비스 인스턴스가 겹쳐 실행되지는 않는다. 다른 CLI 작업자가 같은 큐를 쓰는 경우에는 항목별 임대로 중복 작업을 조정한다.

한 번에 최대 16건만 처리한다. 서비스 제한 시간은 90분이며 클라이언트 요청 제한은 최대 300초다. 서비스가 종료되면 남은 임대는 `timeout_secs + 30초` 뒤 재처리할 수 있다. 시계 변경과 느린 저장소는 실제 회복 시간에 영향을 준다. 임대가 만료된 오래된 작업자의 ACK는 완료 이력을 덮어쓰거나 다른 작업자의 파일을 지우지 못한다.

설정·큐가 없으면 `ConditionPathExists` 때문에 해당 실행이 생략된다. systemd가 active라고 해서 보관이 완료되었다는 의미는 아니다. `pending_items`, `leased_items`, `failed_items`, `archive_slots_available`, `earliest_retry_ms`, `items[].next_retry_ms`를 확인한다. 실패는 서비스의 비영 종료와 구조화된 큐 결과로 남고, 타이머는 다음 주기에 다시 호출한다. 큐 자체의 backoff가 아직 끝나지 않았으면 전송을 건너뛴다.

## 오류와 운영 범위

인증·용량·호출 제한·서버 오류·연결/시간 초과·수신증명 무결성 오류를 `last_error`로 구분한다. 오류라고 해서 파일을 자동 삭제하지 않는다. 인증은 자격 증명/역할을, 용량은 `vault usage`를, 무결성 오류는 신뢰 키·서버 저장소·로컬 스냅샷을 확인한다. 원격 오류 본문이나 토큰을 큐에 기록하지 않는다.

완료 이력도 디스크를 사용한다. 활성 큐 한도와 별도로 전체 예약 슬롯 상한이 있으므로 남은 슬롯을 감시하고 내보내기·큐 보존/교체 절차를 따른다. 새 큐는 이전 큐와 중복 판정 기록을 공유하지 않는다. 기존 자료의 삭제·정상본 판정 취소는 예약 전송이 수행하지 않는다.

유닛은 전용 사용자, `NoNewPrivileges`, 읽기 전용 시스템 경로와 전용 쓰기 경로를 사용한다. 서버별 프록시·CA·파일시스템·권한 설정은 별도 확인한다. 검증 스크립트는 같은 drain 명령의 반복 실행과 장애·동시 등록을 임시 loopback 환경에서 확인하고 유닛 구문을 검사한다. 운영 호스트의 타이머를 자동 활성화하거나 재부팅·네트워크 연결 준비 순서를 실제 운영에서 검증한 것은 아니다.
