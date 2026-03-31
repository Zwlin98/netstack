#!/usr/bin/env bash
# Test: abrupt client disconnect — server resilience after kill -9
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

dd if=/dev/urandom of="$TMPDIR/10m" bs=1K count=10240 2>/dev/null
dd if=/dev/urandom of="$TMPDIR/1m" bs=1K count=1024 2>/dev/null
dd if=/dev/urandom of="$TMPDIR/1k" bs=1K count=1 2>/dev/null

# --- Kill client mid-transfer, verify server health ---
log "=== Abrupt disconnect: kill mid-10MB transfer ==="
nc -N -w 60 "$TUN_IP" "$PORT" < "$TMPDIR/10m" > /dev/null 2>/dev/null &
NC_PID=$!
sleep 1
kill -9 $NC_PID 2>/dev/null || true
wait $NC_PID 2>/dev/null || true
sleep 1

nc -N -w 10 "$TUN_IP" "$PORT" < "$TMPDIR/1k" > "$TMPDIR/1k_health1" 2>/dev/null
if check_md5 "$TMPDIR/1k" "$TMPDIR/1k_health1"; then
    pass "server healthy after abrupt 10MB disconnect"
else
    fail "server unhealthy after abrupt 10MB disconnect"
fi

# --- 10 rounds of abrupt disconnect, then health check ---
log "=== 10x abrupt disconnect (1MB each) ==="
for round in $(seq 1 10); do
    nc -N -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > /dev/null 2>/dev/null &
    NC_PID=$!
    sleep 0.5
    kill -9 $NC_PID 2>/dev/null || true
    wait $NC_PID 2>/dev/null || true
done
sleep 1

nc -N -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_health2" 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_health2"; then
    pass "server healthy after 10 abrupt disconnects"
else
    fail "server unhealthy after 10 abrupt disconnects"
fi

# --- 10 rounds with 3% loss, then health check ---
log "=== 10x abrupt disconnect + 3% loss ==="
tc qdisc add dev $TUN_DEV root netem loss 3%
for round in $(seq 1 10); do
    nc -N -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > /dev/null 2>/dev/null &
    NC_PID=$!
    sleep 0.5
    kill -9 $NC_PID 2>/dev/null || true
    wait $NC_PID 2>/dev/null || true
done
tc qdisc del dev $TUN_DEV root 2>/dev/null
sleep 1

nc -N -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_health3" 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_health3"; then
    pass "server healthy after 10 abrupt disconnects + 3% loss"
else
    fail "server unhealthy after 10 abrupt disconnects + 3% loss"
fi
