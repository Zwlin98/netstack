#!/usr/bin/env bash
# Test: TCP under packet reordering (netem)
# Exercises OOO buffering, SACK blocks, and reassembly.
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

dd if=/dev/urandom of="$TMPDIR/1m" bs=1K count=1024 2>/dev/null

log "=== TCP 1MB + 25% reorder (10ms delay) ==="
tc qdisc add dev "$TUN_DEV" root netem delay 10ms reorder 25% 50%
nc -w 60 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_reorder25" 2>/dev/null
tc qdisc del dev "$TUN_DEV" root 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_reorder25"; then
    pass "1MB echo under 25% reorder"
else
    fail "1MB echo under 25% reorder"
fi

log "=== TCP 1MB + 50% reorder + 5% loss ==="
tc qdisc add dev "$TUN_DEV" root netem delay 10ms reorder 50% 50% loss 5%
nc -w 120 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_reorder50_loss" 2>/dev/null
tc qdisc del dev "$TUN_DEV" root 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_reorder50_loss"; then
    pass "1MB echo under 50% reorder + 5% loss"
else
    fail "1MB echo under 50% reorder + 5% loss"
fi
