#!/usr/bin/env bash
# Test: UDP echo
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

log "=== UDP echo ==="
echo "hello udp" > "$TMPDIR/udp_in"
echo "hello udp" | nc -u -w 1 "$TUN_IP" "$PORT" > "$TMPDIR/udp_out" 2>/dev/null || true
if diff -q "$TMPDIR/udp_in" "$TMPDIR/udp_out" >/dev/null 2>&1; then
    pass "basic echo"
else
    fail "basic echo"
fi
