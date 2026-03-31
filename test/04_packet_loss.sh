#!/usr/bin/env bash
# Test: TCP under packet loss (netem)
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

dd if=/dev/urandom of="$TMPDIR/1m" bs=1K count=1024 2>/dev/null

log "=== TCP 1MB + 5% loss ==="
tc qdisc add dev "$TUN_DEV" root netem loss 5%
nc -N -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_loss5" 2>/dev/null
tc qdisc del dev "$TUN_DEV" root 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_loss5"; then
    pass "1MB echo under 5% loss"
else
    fail "1MB echo under 5% loss"
fi

log "=== TCP 1MB + 10% loss + 50ms delay ==="
tc qdisc add dev "$TUN_DEV" root netem loss 10% delay 50ms
START=$(date +%s)
nc -N -w 120 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_loss10" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
tc qdisc del dev "$TUN_DEV" root 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_loss10"; then
    pass "1MB echo under 10% loss + 50ms delay (${ELAPSED}s)"
else
    fail "1MB echo under 10% loss + 50ms delay"
fi
