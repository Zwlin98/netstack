#!/usr/bin/env bash
# Test: TCP under packet duplication (netem)
# Exercises duplicate segment detection and idempotent delivery.
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

dd if=/dev/urandom of="$TMPDIR/1m" bs=1K count=1024 2>/dev/null

log "=== TCP 1MB + 10% duplicate ==="
tc qdisc add dev $TUN_DEV root netem duplicate 10%
nc -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_dup10" 2>/dev/null
tc qdisc del dev $TUN_DEV root 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_dup10"; then
    pass "1MB echo under 10% duplicate"
else
    fail "1MB echo under 10% duplicate"
fi

log "=== TCP 1MB + 25% duplicate + 5% loss ==="
tc qdisc add dev $TUN_DEV root netem duplicate 25% loss 5%
nc -w 60 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_dup25_loss" 2>/dev/null
tc qdisc del dev $TUN_DEV root 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_dup25_loss"; then
    pass "1MB echo under 25% duplicate + 5% loss"
else
    fail "1MB echo under 25% duplicate + 5% loss"
fi
