#!/usr/bin/env bash
# Test: half-close — client sends FIN while server still echoing data
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

dd if=/dev/urandom of="$TMPDIR/1m" bs=1K count=1024 2>/dev/null
dd if=/dev/urandom of="$TMPDIR/256k" bs=1K count=256 2>/dev/null

# --- 1MB half-close echo ---
log "=== TCP 1MB half-close echo ==="
START=$(date +%s)
nc -N -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_hc" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_hc"; then
    pass "1MB half-close echo (${ELAPSED}s)"
else
    fail "1MB half-close echo"
fi

# --- 1MB half-close echo + 5% loss ---
log "=== TCP 1MB half-close echo + 5% loss ==="
tc qdisc add dev $TUN_DEV root netem loss 5%
START=$(date +%s)
nc -N -w 60 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_hc_loss" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
tc qdisc del dev $TUN_DEV root 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_hc_loss"; then
    pass "1MB half-close echo + 5% loss (${ELAPSED}s)"
else
    fail "1MB half-close echo + 5% loss"
fi

# --- Half-close with read-delay (restart echo server) ---
_cleanup_halfclose() {
    kill "$ECHO_PID" 2>/dev/null || true
    wait "$ECHO_PID" 2>/dev/null || true
    ip link del $TUN_DEV 2>/dev/null || true
    sleep 0.3
    $ECHO_BIN -tun "$TUN_DEV" -subnet "$TUN_SUBNET" ${ECHO_EXTRA_ARGS:-} &
    ECHO_PID=$!
    sleep 1
}
trap _cleanup_halfclose RETURN

kill "$ECHO_PID" 2>/dev/null || true
wait "$ECHO_PID" 2>/dev/null || true
ip link del $TUN_DEV 2>/dev/null || true
sleep 0.3
$ECHO_BIN -tun "$TUN_DEV" -subnet "$TUN_SUBNET" ${ECHO_EXTRA_ARGS:-} -read-delay 50ms &
ECHO_PID=$!
sleep 1

log "=== TCP 256KB half-close + read-delay 50ms ==="
START=$(date +%s)
nc -N -w 120 "$TUN_IP" "$PORT" < "$TMPDIR/256k" > "$TMPDIR/256k_hc_delay" 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
if check_md5 "$TMPDIR/256k" "$TMPDIR/256k_hc_delay"; then
    pass "256KB half-close with read-delay 50ms (${ELAPSED}s)"
else
    fail "256KB half-close with read-delay 50ms"
fi
