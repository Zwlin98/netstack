#!/usr/bin/env bash
# Test: TCP under combined adverse conditions.
# Exercises the stack with multiple impairments active simultaneously.
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

dd if=/dev/urandom of="$TMPDIR/1m" bs=1K count=1024 2>/dev/null
dd if=/dev/urandom of="$TMPDIR/256k" bs=1K count=256 2>/dev/null

log "=== TCP 1MB + 3% loss + 25% reorder + 50ms±20ms jitter ==="
tc qdisc add dev $TUN_DEV root netem loss 3% delay 50ms 20ms distribution normal reorder 25% 50%
START=$(date +%s)
nc -w 120 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_combined" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
tc qdisc del dev $TUN_DEV root 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_combined"; then
    pass "1MB echo under loss+reorder+jitter (${ELAPSED}s)"
else
    fail "1MB echo under loss+reorder+jitter"
fi

log "=== TCP 256KB + 5% loss + 10% reorder + 1Mbit/s ==="
tc qdisc add dev $TUN_DEV root handle 1: netem loss 5% delay 10ms reorder 10% 50%
tc qdisc add dev $TUN_DEV parent 1:1 handle 2: tbf rate 1mbit burst 32kbit latency 400ms
START=$(date +%s)
nc -w 60 "$TUN_IP" "$PORT" < "$TMPDIR/256k" > "$TMPDIR/256k_combined" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
tc qdisc del dev $TUN_DEV root 2>/dev/null
if check_md5 "$TMPDIR/256k" "$TMPDIR/256k_combined"; then
    pass "256KB echo under loss+reorder+1Mbit (${ELAPSED}s)"
else
    fail "256KB echo under loss+reorder+1Mbit"
fi
