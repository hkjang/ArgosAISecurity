# Argos 위협 탐지 및 스코어링 기능 분석서

**Argos 위협 탐지 엔진**은 실시간 파일 시스템 이벤트를 Shannon 엔트로피 수동/자동 실측과 슬라이딩 윈도우 스코어링 수식에 대입하여, 랜섬웨어 등 파일 대량 암호화/변조 공격 행동 양식을 정밀하게 식별하는 시스템의 핵심 탐지 모듈입니다.

---

## 1. 핵심 설계 및 구동 컴포넌트

위협 탐지는 [argos-detect](file:///d:/project/ArgosAISecurity/crates/argos-detect/src) 라이브러리가 전담합니다. 
주요 클래스 및 파일은 다음과 같습니다:
- **`DetectionEngine`** ([lib.rs](file:///d:/project/ArgosAISecurity/crates/argos-detect/src/lib.rs)): 외부 채널에서 들어온 로우 이벤트를 필터링하고 스코어러로 인계하는 외곽 래핑 클래스입니다.
- **`BehaviorScorer`** ([scorer.rs](file:///d:/project/ArgosAISecurity/crates/argos-detect/src/scorer.rs)): PID별로 독립된 타임 이벤트 슬라이딩 윈도우 큐를 소유하여 점수를 계산하고 쿨다운 필터를 처리하는 핵심 스코어러입니다.
- **`entropy`** ([entropy.rs](file:///d:/project/ArgosAISecurity/crates/argos-detect/src/entropy.rs)): 대상 파일 전반부를 읽어 정보이론 기반 Shannon 엔트로피 실측 수치를 연산하는 수학 알고리즘 모듈입니다.

---

## 2. 파일 Shannon 엔트로피 계산 메커니즘

랜섬웨어는 파일을 무단으로 암호화하여 파일 전반의 균일한 바이너리 분산을 야기합니다. 일반 텍스트나 소스 코드 등 구조화된 파일에 비해 높은 엔트로피 수치(최댓값 8.0에 근접하는 7.2 ~ 8.0)가 관측됩니다.

### 2.1.Shannon Entropy 수식
이진 데이터 바이트 $x_i$ ($0 \le i \le 255$)의 정보 엔트로피 $H(X)$는 다음과 같이 연산됩니다:

$$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$

여기서 $P(x_i)$는 전체 바이트 배열 중 바이트값 $x_i$가 점유하는 확률값입니다.

### 2.2. 코드 구현 상세
- `entropy.rs` 내 `shannon_entropy` 함수는 256 크기의 누적 배열(`[u64; 256]`)을 선언하여 전달된 데이터 블록을 한 바퀴 순회하며 바이트 빈도를 취합합니다. 이후 $P(x_i) > 0$인 바이트에 대해 $-\sum P \log_2 P$를 연산합니다.
- `file_entropy` 함수는 I/O 병목 및 CPU 점유를 막기 위해 파일의 전체 바이트를 읽지 않고, 설정된 임계 크기(`entropy_sample_bytes`, 기본값 64KB) 만큼만 버퍼를 잡아 파일 상단에서 읽어들여 연산합니다.

---

## 3. 슬라이딩 윈도우 스코어링 알고리즘

`BehaviorScorer`는 수집된 이벤트를 대상으로 위험 지수 점수(Score)를 동적으로 계산합니다.

### 3.1. 위협 평가 공식

$$Score = MassChangeScore(40) + EntropyScore(35) + ChurnScore(25)$$

1. **Mass Change Score (최대 40점)**:
   - 10초 슬라이딩 윈도우 내에서 변경된 유니크한 파일 경로의 수($N_{path}$)를 대량 파일 변경 기준값($MassThreshold$, 기본값 30개)으로 나누어 가중치를 부여합니다.
   $$MassChangeScore = \min\left(1.0, \frac{N_{path}}{MassThreshold}\right) \times 40$$
2. **Entropy Score (최대 35점)**:
   - 감시 윈도우 내 파일 수정(`Modify`) 이벤트 중 실측 엔트로피 점수가 임계 기준값($EntropyThreshold$, 기본값 7.2)을 돌파한 고엔트로피 파일 개수($N_{high\_entropy}$)의 비율을 산출해 가중합니다.
   $$EntropyScore = \min\left(1.0, \frac{N_{high\_entropy}}{N_{path}}\right) \times 35$$
3. **Churn Score (최대 25점)**:
   - 윈도우 내에 집계된 전체 이벤트 로그 건수($N_{event}$) 대비 파일 이름 변경(`Rename`) 및 파일 강제 삭제(`Delete`) 행동이 유발된 개별 비중을 가산합니다.
   $$ChurnScore = \min\left(1.0, \frac{N_{rename} + N_{delete}}{N_{event}}\right) \times 25$$

---

## 4. 오탐 방지 및 침해 중복 차단 제어 정책

1. **최소 변경 파일 개수 검사 (`min_changed_files`)**:
   - 단일 또는 소수개의 고엔트로피 쓰기 작업이 발생하는 일상적 현상(예: 컴파일 압축 파일 생성 등)으로 인해 오탐이 발생하는 것을 방어하기 위해 변경 파일 개수가 설정 개수(기본값 5개) 미만인 경우 스코어 연산 단계를 생략합니다.
2. **경로 제외 예외 목록 필터 (`exclude_paths`)**:
   - 백업 및 시스템 로그 디렉터리 등 빈번한 갱신이 당연시되는 경로는 탐지 스캔 대상에서 물리 제외합니다.
3. **쿨다운 및 에스컬레이션 메커니즘**:
   - 특정 프로세스에서 탐지가 발생한 순간 윈도우 주기 동안 유사한 알람이 중복 통보되어 시스템 리소스를 낭비하지 않도록 방어하는 쿨다운이 작동합니다.
   - 단, 해당 프로세스의 악성 침해 강도가 증가하여 위험 환산 점수가 직전 탐지값 대비 15점 이상 상승(`ESCALATION_DELTA`)하면, 쿨다운 차단막을 우회해 중앙 관리 서버에 즉시 위험 악화 상태를 통지합니다.
