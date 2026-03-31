#!/usr/bin/env bash
# Test: TCP echo — basic and 1MB integrity
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

log "=== TCP echo: basic ==="
echo "hello tcp" > "$TMPDIR/tcp_in"
if nc -w 3 "$TUN_IP" "$PORT" < "$TMPDIR/tcp_in" > "$TMPDIR/tcp_out" 2>/dev/null \
   && diff -q "$TMPDIR/tcp_in" "$TMPDIR/tcp_out" >/dev/null 2>&1; then
    pass "basic echo"
else
    fail "basic echo"
fi

log "=== TCP echo: 1MB integrity ==="
dd if=/dev/urandom of="$TMPDIR/1m" bs=1K count=1024 2>/dev/null
nc -w 10 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_out" 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_out"; then
    pass "1MB echo (md5 match)"
else
    fail "1MB echo (md5 mismatch)"
fi
