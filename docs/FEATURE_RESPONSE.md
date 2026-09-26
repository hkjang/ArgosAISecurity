# Argos 대응과 격리 검증

프로세스 대응은 [argos-response](../crates/argos-response/src/lib.rs), 네트워크 격리는 [isolate 모듈](../crates/argos-response/src/isolate.rs)이 담당한다.

## 위험 점수와 프로세스 차단

탐지 엔진은 매 파일 이벤트의 위험 점수와 최소 변경 파일 수 조건을 평가한다. 알림의 중복 억제는 대응 판단에 영향을 주지 않는다. `auto_block=true`, `score >= block_score`, 수집 당시 프로세스 인스턴스 신원과 해당 규칙의 대응 조건을 모두 충족할 때만 자동 대응한다. 일반 행위·인스턴스 시간창에는 최소 변경 파일 수 조건이 있으며, 미끼 변조는 파일 하나로도 대응 조건을 충족할 수 있다. 계정·경로·계보 집계와 Linux 의미 변화 알림만으로는 특정 PID를 종료하지 않는다. 기본값은 `auto_block=false`, `block_score=80`이다.

- 에이전트의 자동 대응은 `KillProcessInstance`를 사용해 신원을 검증한 pidfd에 SIGKILL을 보낸다. 라이브러리의 `KillProcess`·`SuspendProcess`는 각각 SIGKILL·SIGSTOP API이며 수동 CLI 명령으로 제공하지 않는다.
- PID 0은 센서가 프로세스를 식별하지 못했다는 뜻이다. 프로세스 그룹에 잘못 시그널을 보내지 않도록 거부한다.
- fanotify는 수정 이벤트만 제공하므로 대량 변경 40점과 고엔트로피 파일 비율 60점으로 평가한다. notify는 대량 변경 40점, 고엔트로피 파일 비율 35점, 이름 변경·삭제 비율 25점을 사용한다.
- 엔트로피를 읽지 못한 경우 해당 증거 점수를 추가하지 않는다. 센서·샘플링 설정에서 도달할 수 없는 임계치는 시작 시 경고한다.

## 명시적 관리 연결을 통한 격리

`--allow`에는 연결 방향, 숫자 IP 또는 CIDR, TCP 서비스 포트를 지정한다. `in`은 관리자가 이 서버로 접속하는 경우, `out`은 이 서버가 중앙 서버 등으로 접속하는 경우다. 회신은 같은 IP·포트 조건을 만족하는 conntrack REPLY 방향의 ESTABLISHED 연결만 허용한다. 호스트명, 포트 없는 IP, `/0`, 포트 0은 거부한다.

```bash
# 명령과 restore 입력만 출력한다. 권한이나 방화벽 도구가 필요하지 않다.
argos isolate --dry-run \
  --allow in:192.0.2.20:22 \
  --allow out:10.0.0.5:8443 \
  --allow 'out:[2001:db8::5]:8443'

# 관리 경로를 확인한 뒤 실제 적용한다 (Linux, root 필요).
sudo argos isolate \
  --allow in:192.0.2.20:22 \
  --allow out:10.0.0.5:8443

sudo argos isolate --release
```

중앙 서버 주소를 자동으로 모든 포트에 허용하지 않는다. 사용자가 중앙 서버의 실제 IP와 포트를 명시한다. 관리 SSH 연결도 예외에 포함되지 않으면 끊긴다. 일반 ESTABLISHED/RELATED 허용은 제거했으므로 기존 공격자 연결의 후속 패킷도 차단된다. TCP 소켓이나 conntrack 항목 자체를 삭제하는 기능은 아니다.

| 경로 | IPv4 / IPv6 동작 |
| --- | --- |
| INPUT | loopback과 지정 관리 연결·회신을 허용한 뒤 DROP |
| OUTPUT | loopback과 지정 관리 연결·회신을 허용한 뒤 DROP |
| FORWARD | 전체 DROP, 호스트를 통과하는 컨테이너 전달 트래픽 포함 |
| IPv6 링크 제어 | hop limit 255의 이웃 탐색과 제한된 링크 로컬 라우터 탐색 허용 |

독립 네트워크 네임스페이스, 호스트 FORWARD를 거치지 않는 macvlan/직접 장치 경로, eBPF 데이터 경로, 하드웨어 오프로드까지 이 규칙만으로 격리된다고 보장하지 않는다. 실제 배포 환경에서 각 경로의 패킷 차단을 검증해야 한다.

## 적용·해제와 실패 보고

1. `iptables-save`와 `ip6tables-save`로 기존 filter 테이블을 읽는다.
2. 두 주소 계열 모두 `iptables-restore` / `ip6tables-restore`의 `--noflush --test`로 사전 검사한다. 이 단계가 실패하면 변경하지 않는다.
3. 각 주소 계열에서 Argos 체인과 세 진입점의 점프를 하나의 restore 트랜잭션으로 반영한다. 기존 다른 체인·정책은 유지한다. 재적용 시 중복 점프와 구형 `ARGOS_ISOLATE`를 정리한다.
4. 다시 읽어 INPUT/OUTPUT/FORWARD의 최상단 점프, 규칙 수, 마지막 DROP을 확인한다. 각 규칙을 `iptables -C` / `ip6tables -C`로 확인해 IP·포트·연결 방향 조건도 검증한다.

IPv4와 IPv6 사이의 전체 적용은 원자적이지 않다. 두 번째 계열 적용이나 확인에 실패하면 부분 적용 가능성을 포함한 오류를 반환한다. 적용된 격리를 자동으로 풀지는 않는다. 관리자는 반환된 오류와 실제 방화벽 상태를 확인하고 재적용하거나 `--release`로 해제한다.

해제는 현재 존재하는 Argos 점프와 체인만 제거하고 양쪽 주소 계열에 남은 체인이 없는지 확인한다. 권한 부족, 명령 실패, 확인 실패를 성공으로 처리하지 않는다. 재시작이나 다른 방화벽 관리 도구에 의한 이후 변경을 지속적으로 감시하는 기능은 아직 없다.

## 검증 범위

단위 테스트는 두 주소 계열의 명령 계획, 명시적 관리 예외, 전달 차단, 구형 규칙 정리, 사전 검사 실패 시 미변경, 부분 적용 오류, 해제 반복, 적용 후 확인 실패를 검증한다. 가짜 실행기를 사용해 실패 분기도 검사한다.

[격리 네임스페이스 패킷 시험](../scripts/test-isolation-netns.py)은 호스트와 분리된 user/net namespace에서 실행한다. IPv4·IPv6 각각 INPUT/OUTPUT 관리 연결 유지, 기존 의심 연결 차단, 신규 의심 연결 차단, FORWARD 전달 차단, 재적용 시 중복 방지, 반복 해제 후 통신 복구, 무관한 기존 규칙 보존을 실제 TCP 패킷으로 검증한다. iptables-nft 1.8.11 환경에서 이 시험을 통과했다. 물리 장치·특정 컨테이너 런타임·오프로드 경로는 별도 검증 대상이다.

```bash
cargo build -p argos-cli
python3 scripts/test-isolation-netns.py --argos "$PWD/target/debug/argos"
```

Netfilter의 [conntrack match 문서](https://ipset.netfilter.org/iptables-extensions.man.html)와 [iptables-restore 매뉴얼](https://man7.org/linux/man-pages/man8/iptables-restore.8.html)의 `--noflush`, `--test` 동작을 기준으로 작성했다.


## 프로세스 자동 대응 결과 확인

자동 대응은 이벤트에 저장된 PID·시작 ticks·부팅 ID가 있어야 실행한다. Linux에서 pidfd를 연 뒤 현재 시작 신원을 확인하고 그 FD로 SIGKILL을 전송한다. 최대 1초 안에 pidfd가 종료 상태를 나타내는지 확인한다. 미지원 커널·신원 변경·확인 시간 초과는 성공으로 표시하지 않는다. PID 0·1·자기 자신·음수 pid로 변환되는 범위는 거부한다.

감사는 `succeeded`, `failed_or_unconfirmed`, `rejected`, `observed_threshold`를 구분한다. 관찰 모드의 점수 통과는 실제 차단이 아니다. `evidence`/MCP `response_results`와 사건 HTML에서 결과를 조회할 수 있다.
