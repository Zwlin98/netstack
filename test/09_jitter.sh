#!/usr/bin/env bash
# Test: TCP under jitter / variable latency (netem)
# Exercises RTT estimation (RTTM), RTO accuracy, and timestamp-based recovery.
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

dd if=/dev/urandom of="$TMPDIR/1m" bs=1K count=1024 2>/dev/null

log "=== TCP 1MB + 50ms delay ± 20ms jitter ==="
tc qdisc add dev $TUN_DEV root netem delay 50ms 20ms distribution normal
START=$(date +%s)
nc -N -w 60 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_jitter" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
tc qdisc del dev $TUN_DEV root 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_jitter"; then
    pass "1MB echo under 50ms ± 20ms jitter (${ELAPSED}s)"
else
    fail "1MB echo under 50ms ± 20ms jitter"
fi

log "=== TCP 1MB + 100ms delay ± 50ms jitter + 3% loss ==="
tc qdisc add dev $TUN_DEV root netem delay 100ms 50ms distribution normal loss 3%
START=$(date +%s)
nc -N -w 120 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_jitter_loss" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
tc qdisc del dev $TUN_DEV root 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_jitter_loss"; then
    pass "1MB echo under 100ms ± 50ms jitter + 3% loss (${ELAPSED}s)"
else
    fail "1MB echo under 100ms ± 50ms jitter + 3% loss"
fi
