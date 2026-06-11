# Argos 시스템/인프라 운영자(System Operator) 운영 가이드

이 문서는 Argos 에이전트 데몬 서비스를 시스템에 정상 설치 및 기동하고, 시스템 리소스 점유와 백업 디스크 용량을 최적으로 관리하며, 침해 사고 발생 시 무결성이 보장된 백업 파일로 원자 복구를 집행하는 **시스템/인프라 운영자(System / Infrastructure Administrator)**를 위한 상세 운영 매뉴얼입니다.

---

## 1. 역할 정의 및 업무 범위

시스템/인프라 운영자는 Argos 에이전트의 구동 안정성을 책임지며 서비스의 지속적인 가동과 성능 유지, 그리고 물리적인 데이터의 안전 복원을 담당합니다.
- **주요 책임**:
  - 패키지 설치 및 systemd 기반 에이전트 데몬 생명 주기 제어.
  - 에이전트 구동 헬스체크 및 의존 환경 진단 (`doctor`).
  - 디스크 공간 낭비 방지를 위한 백업 CAS 용량 정리 정책 조율 (`prune`).
  - 비정상 파일 암호화 사고 발생 시, 특정 시점으로 원본 데이터 원자 복원 (`restore`).

---

## 2. 에이전트 설치 및 데몬 제어 가이드

### 2.1. 시동 구성 설정 (`argos.toml`) 조율
에이전트가 모니터링할 타겟 시스템 영역과 보존 용량을 조율합니다:
```toml
watch_paths = ["/home", "/var/www/html"]     # 감시할 디렉터리 경로
db_path = "/var/lib/argos/argos.db"          # SQLite 로깅 데이터베이스 위치
sensor = "fanotify"                          # Linux 최적 커널 센서 (root 필요)

[backup]
enabled = true                               # 백업 활성화
dir = "/var/lib/argos/backup"                # 백업 CAS 보존 경로 (감시 대상 밖에 둘 것)
max_file_bytes = 10485760                    # 단일 백업 한계 크기 (10MB 제한)
keep_versions = 5                            # 경로당 최신 이력 보존 수 (5개)
baseline_on_start = true                     # 시동 순간 베이스라인 전수 백업 가동
```

### 2.2. systemd 데몬 관리 (Linux)
1. systemd 서비스 명세(`packaging/argos-agent.service`)를 반영한 상태에서 서비스를 시작하고 상시 활성화합니다:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable argos-agent
   sudo systemctl start argos-agent
   ```
2. 에이전트의 실시간 가동 로그 상태 및 오동작 여부를 추적합니다:
   ```bash
   sudo systemctl status argos-agent
   sudo journalctl -u argos-agent -f -n 100
   ```

---

## 3. 환경 진단 및 장애 헬스체크

시스템 이상 징후나 에이전트 탐지 거부 장애가 의발하는 경우 `doctor` 진단 툴을 구동합니다.
```bash
argos doctor
```
- **주요 자가 진단 항목**:
  - `OS` 타입 및 커널 호환 스펙 체크.
  - `설정 파일` 및 `DB 파일` 경로의 실제 디바이스 상 존재 유무 및 에이전트 접근 권한.
  - `백업 디렉터리` 및 감시 대상 `watch_paths` 경로 유효성.
  - Claude 연동 키(`ANTHROPIC_API_KEY`) 환경 변수 탑재 상태.

---

## 4. 파일 버전 롤백 복구 실행 절차 (`restore`)

랜섬웨어 감염이나 시스템 침입에 의한 파일 오염 사고 발생 시, 무결성이 검증된 백업 저장소(CAS)로부터 원자 복원을 긴급 실행합니다.

### 4.1. 파일 백업 버전 이력 리스트 파악
- 피해를 입은 타겟 파일 경로를 지정해 과거에 적재된 백업 고유 해시와 크기, 적재 시간 목록을 쿼리합니다:
  ```bash
  argos restore /home/user/document.docx --list
  ```

### 4.2. 파일 긴급 복원 단행
- **가장 최근 상태로 복구**:
  ```bash
  argos restore /home/user/document.docx
  ```
- **공격 이전 특정 시점으로 복구** (예: 공격자 침해 스코어 타임스탬프 시각 `1760000000000` 이전 상태):
  ```bash
  argos restore /home/user/document.docx --before-ms 1760000000000
  ```
- **동작 원리 및 안정성 보장**:
  - 복구 엔진은 대상 백업 객체의 SHA-256 해시 검산을 실시해 변조 여부를 1차 필터링합니다.
  - 통과 시 원본의 동일 디렉터리상에 임시 원복 파일(`.argos-restore-tmp`)을 우선 기입한 후 rename 시스콜로 순간 교체하여 복구 시 발생하는 데이터 레이스 및 쓰기 불완전 장애를 완전히 차단합니다.
