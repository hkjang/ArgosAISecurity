#!/bin/sh
# E2E 스모크 테스트: 에이전트 기동 → 랜섬웨어 패턴 시뮬레이션 → 탐지·백업·복구 확인.
# 사용: docker run --rm -v <repo>:/src -v argos-target-cache:/src/target -w /src rust:latest sh scripts/smoke-test.sh
set -e

BIN=/src/target/debug
WORK=/tmp/argos-smoke
rm -rf "$WORK"
mkdir -p "$WORK/watched"

cat > "$WORK/argos.toml" <<EOF
watch_paths = ["$WORK/watched"]
db_path = "$WORK/argos.db"

[backup]
enabled = true
dir = "$WORK/backup"
max_file_bytes = 10485760
keep_versions = 5
baseline_on_start = true
EOF

# 공격 전 정상 파일.
echo "important business document" > "$WORK/watched/contract.docx"

echo "=== 에이전트 기동 ==="
"$BIN/argos-agent" --config "$WORK/argos.toml" &
AGENT_PID=$!
sleep 2

echo "=== 랜섬웨어 패턴 시뮬레이션 (고엔트로피 쓰기 + 확장자 변경 x40) ==="
ATTACK_MS=$(($(date +%s%N) / 1000000))
i=1
while [ "$i" -le 40 ]; do
    dd if=/dev/urandom of="$WORK/watched/file$i.docx" bs=4096 count=4 2>/dev/null
    mv "$WORK/watched/file$i.docx" "$WORK/watched/file$i.docx.locked"
    i=$((i + 1))
done
# 기존 문서도 "암호화".
dd if=/dev/urandom of="$WORK/watched/contract.docx" bs=4096 count=1 2>/dev/null
sleep 3

kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true

echo ""
echo "=== argos status ==="
"$BIN/argos" --config "$WORK/argos.toml" status

echo ""
echo "=== argos threats ==="
"$BIN/argos" --config "$WORK/argos.toml" threats -n 3

echo ""
echo "=== 복구: contract.docx 버전 목록 ==="
"$BIN/argos" --config "$WORK/argos.toml" restore "$WORK/watched/contract.docx" --list

echo ""
echo "=== 복구 실행 (공격 시작 시각 $ATTACK_MS 이전 버전) ==="
"$BIN/argos" --config "$WORK/argos.toml" restore "$WORK/watched/contract.docx" --before-ms "$ATTACK_MS"
echo "복구된 내용: $(cat "$WORK/watched/contract.docx")"

# 검증: 탐지가 1건 이상이어야 하고, 복구 내용이 원본과 일치해야 한다.
DETECTIONS=$("$BIN/argos" --config "$WORK/argos.toml" threats -n 1 | grep -c "behavior" || true)
RESTORED=$(cat "$WORK/watched/contract.docx")
if [ "$DETECTIONS" -ge 1 ] && [ "$RESTORED" = "important business document" ]; then
    echo ""
    echo "SMOKE TEST PASSED: 탐지 OK, 복구 OK"
else
    echo ""
    echo "SMOKE TEST FAILED: detections=$DETECTIONS restored='$RESTORED'"
    exit 1
fi
