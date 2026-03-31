#!/usr/bin/env bash
# Test: TCP under bandwidth limiting (tc tbf)
# Exercises congestion control: slow start, congestion avoidance, and flow pacing.
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

dd if=/dev/urandom of="$TMPDIR/256k" bs=1K count=256 2>/dev/null

log "=== TCP 256KB + 1 Mbit/s limit ==="
# tbf: rate=1mbit, burst=32kbit (buffer for token bucket), latency=400ms (max queue delay)
tc qdisc add dev $TUN_DEV root tbf rate 1mbit burst 32kbit latency 400ms
START=$(date +%s)
nc -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/256k" > "$TMPDIR/256k_1m" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
tc qdisc del dev $TUN_DEV root 2>/dev/null
if check_md5 "$TMPDIR/256k" "$TMPDIR/256k_1m"; then
    pass "256KB echo at 1Mbit/s (${ELAPSED}s)"
else
    fail "256KB echo at 1Mbit/s"
fi

log "=== TCP 256KB + 10 Mbit/s limit + 5% loss ==="
# Chain netem (loss) with tbf (rate limit) using a classful qdisc.
tc qdisc add dev $TUN_DEV root handle 1: netem loss 5%
tc qdisc add dev $TUN_DEV parent 1:1 handle 2: tbf rate 10mbit burst 64kbit latency 400ms
START=$(date +%s)
nc -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/256k" > "$TMPDIR/256k_10m_loss" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
tc qdisc del dev $TUN_DEV root 2>/dev/null
if check_md5 "$TMPDIR/256k" "$TMPDIR/256k_10m_loss"; then
    pass "256KB echo at 10Mbit/s + 5% loss (${ELAPSED}s)"
else
    fail "256KB echo at 10Mbit/s + 5% loss"
fi
