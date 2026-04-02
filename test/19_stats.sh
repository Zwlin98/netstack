#!/usr/bin/env bash
# Test: stats counters are populated after traffic
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

log "=== Stats ==="

# Start a separate echo instance with -stats flag.
ip link del tun9 2>/dev/null || true
sleep 0.3
go build -o "$ECHO_BIN" ./example/
STATS_LOG="$TMPDIR/stats.log"
$ECHO_BIN -tun tun9 -subnet 10.9.0.0/24 -stats "$@" >"$STATS_LOG" 2>&1 &
STATS_PID=$!
sleep 1

STATS_IP=10.9.0.1

# Generate TCP traffic.
echo "hello stats" | nc -N -w 3 "$STATS_IP" "$PORT" >/dev/null 2>&1 || true

# Generate UDP traffic.
echo "hello udp" | nc -u -w 1 "$STATS_IP" "$PORT" >/dev/null 2>&1 || true

# Wait for stats ticker to fire (10s interval + margin).
sleep 12

# Shut down.
kill "$STATS_PID" 2>/dev/null || true
wait "$STATS_PID" 2>/dev/null || true

# Verify stack stats line with non-zero in/out.
if grep -q '\[stats\] stack:' "$STATS_LOG" \
   && grep '\[stats\] stack:' "$STATS_LOG" | grep -qv 'in=0 out=0'; then
    pass "stack stats non-zero"
else
    fail "stack stats missing or all zero"
    cat "$STATS_LOG"
fi

# Verify TCP stats line with at least one accepted connection.
if grep -q '\[stats\] tcp:' "$STATS_LOG" \
   && grep '\[stats\] tcp:' "$STATS_LOG" | grep -qv 'accepted=0'; then
    pass "tcp stats non-zero"
else
    fail "tcp stats missing or accepted=0"
    cat "$STATS_LOG"
fi

# Verify UDP stats line with non-zero datagrams in.
if grep -q '\[stats\] udp:' "$STATS_LOG" \
   && grep '\[stats\] udp:' "$STATS_LOG" | grep -qv 'in=0'; then
    pass "udp stats non-zero"
else
    fail "udp stats missing or in=0"
    cat "$STATS_LOG"
fi
