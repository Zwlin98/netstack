#!/usr/bin/env bash
# Test: TCP large transfer — sustained reliability over 10MB/50MB.
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

dd if=/dev/urandom of="$TMPDIR/10m" bs=1K count=10240 2>/dev/null
dd if=/dev/urandom of="$TMPDIR/50m" bs=1K count=51200 2>/dev/null

log "=== TCP 10MB echo ==="
START=$(date +%s)
nc -N -w 60 "$TUN_IP" "$PORT" < "$TMPDIR/10m" > "$TMPDIR/10m_out" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
if check_md5 "$TMPDIR/10m" "$TMPDIR/10m_out"; then
    pass "10MB echo (${ELAPSED}s)"
else
    fail "10MB echo"
fi

log "=== TCP 50MB echo ==="
START=$(date +%s)
nc -N -w 180 "$TUN_IP" "$PORT" < "$TMPDIR/50m" > "$TMPDIR/50m_out" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
if check_md5 "$TMPDIR/50m" "$TMPDIR/50m_out"; then
    pass "50MB echo (${ELAPSED}s)"
else
    fail "50MB echo"
fi

log "=== TCP 10MB + 3% loss ==="
tc qdisc add dev $TUN_DEV root netem loss 3%
START=$(date +%s)
nc -N -w 120 "$TUN_IP" "$PORT" < "$TMPDIR/10m" > "$TMPDIR/10m_loss3" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
tc qdisc del dev $TUN_DEV root 2>/dev/null
if check_md5 "$TMPDIR/10m" "$TMPDIR/10m_loss3"; then
    pass "10MB echo under 3% loss (${ELAPSED}s)"
else
    fail "10MB echo under 3% loss"
fi
