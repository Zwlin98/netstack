#!/usr/bin/env bash
# Test: TCP zero-window probe and recovery.
# Restarts echo server with -read-delay to simulate slow consumer,
# triggering window=0 → zero-window probe → window update → recovery.
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

# --- Restart echo with slow read ---
_cleanup_zerowin() {
    kill "$ECHO_PID" 2>/dev/null || true
    wait "$ECHO_PID" 2>/dev/null || true
    ip link del $TUN_DEV 2>/dev/null || true
    sleep 0.3
    $ECHO_BIN -tun "$TUN_DEV" -subnet "$TUN_SUBNET" &
    ECHO_PID=$!
    sleep 1
}
trap _cleanup_zerowin RETURN

kill "$ECHO_PID" 2>/dev/null || true
wait "$ECHO_PID" 2>/dev/null || true
ip link del $TUN_DEV 2>/dev/null || true
sleep 0.3
$ECHO_BIN -tun "$TUN_DEV" -subnet "$TUN_SUBNET" -read-delay 50ms &
ECHO_PID=$!
sleep 1

dd if=/dev/urandom of="$TMPDIR/1m" bs=1K count=1024 2>/dev/null
dd if=/dev/urandom of="$TMPDIR/512k" bs=1K count=512 2>/dev/null

log "=== TCP 1MB + read-delay 50ms (zero-window) ==="
START=$(date +%s)
nc -w 120 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_zerowin" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_zerowin"; then
    pass "1MB echo with read-delay 50ms (${ELAPSED}s)"
else
    fail "1MB echo with read-delay 50ms"
fi

log "=== TCP 512KB + read-delay 50ms + 3% loss ==="
tc qdisc add dev $TUN_DEV root netem loss 3%
START=$(date +%s)
nc -w 120 "$TUN_IP" "$PORT" < "$TMPDIR/512k" > "$TMPDIR/512k_zerowin_loss" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
tc qdisc del dev $TUN_DEV root 2>/dev/null
if check_md5 "$TMPDIR/512k" "$TMPDIR/512k_zerowin_loss"; then
    pass "512KB echo with read-delay + 3% loss (${ELAPSED}s)"
else
    fail "512KB echo with read-delay + 3% loss"
fi
