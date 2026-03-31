#!/usr/bin/env bash
# Test: iperf3 throughput through TUN with TCP forwarding.
# Requires: iperf3 on local host, iperf3 on IPERF_HOST.
#
# Usage:
#   IPERF_HOST=<remote-ip> sudo -E ./test/run_all.sh test/06_iperf3.sh
#   IPERF_HOST=<remote-ip> IPERF_SSH=<ssh-host> sudo -E ./test/06_iperf3.sh
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

IPERF_HOST="${IPERF_HOST:-}"
IPERF_SSH="${IPERF_SSH:-}"
IPERF_DURATION="${IPERF_DURATION:-10}"
IPERF_MIN_MBPS="${IPERF_MIN_MBPS:-500}"

if [ -z "$IPERF_HOST" ]; then
    log "=== iperf3 (SKIPPED: set IPERF_HOST) ==="
    return 0 2>/dev/null || exit 0
fi

# --- Start iperf3 server on remote host ---
_iperf_server_started=false
_cleanup_iperf() {
    if [ -n "$IPERF_SSH" ] && $_iperf_server_started; then
        ssh "$IPERF_SSH" "pkill iperf3" 2>/dev/null || true
    fi
    # Restore echo mode (stop forward server, restart echo).
    pkill -f "$ECHO_BIN" 2>/dev/null || true
    ip link del $TUN_DEV 2>/dev/null || true
    sleep 0.3
    $ECHO_BIN &
    ECHO_PID=$!
    sleep 1
}
trap _cleanup_iperf RETURN

if [ -n "$IPERF_SSH" ]; then
    ssh "$IPERF_SSH" "pkill iperf3 2>/dev/null; sleep 0.5; iperf3 -s -D -B $IPERF_HOST" 2>/dev/null
    _iperf_server_started=true
fi

# --- Restart echo server in forward mode ---
pkill -f "$ECHO_BIN" 2>/dev/null || true
ip link del $TUN_DEV 2>/dev/null || true
sleep 0.3
$ECHO_BIN -forward "$IPERF_HOST:5201" &
ECHO_PID=$!
sleep 1

log "=== iperf3 throughput (${IPERF_DURATION}s → $IPERF_HOST) ==="

# Run iperf3 through the TUN.
IPERF_OUT=$(iperf3 -c "$TUN_IP" -t "$IPERF_DURATION" -J 2>&1) || true

# Parse JSON output.
BITS_PER_SEC=$(echo "$IPERF_OUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(int(d['end']['sum_sent']['bits_per_second']))
" 2>/dev/null || echo "0")

RETRANSMITS=$(echo "$IPERF_OUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(int(d['end']['sum_sent'].get('retransmits', 0)))
" 2>/dev/null || echo "-1")

MBPS=$((BITS_PER_SEC / 1000000))

log "  throughput: ${MBPS} Mbits/sec, retransmits: ${RETRANSMITS}"

if [ "$MBPS" -ge "$IPERF_MIN_MBPS" ]; then
    pass "iperf3 throughput ${MBPS} Mbps >= ${IPERF_MIN_MBPS} Mbps threshold"
else
    fail "iperf3 throughput ${MBPS} Mbps < ${IPERF_MIN_MBPS} Mbps threshold"
fi

if [ "$RETRANSMITS" -ge 0 ] && [ "$RETRANSMITS" -le 100 ]; then
    pass "iperf3 retransmits ${RETRANSMITS} <= 100"
else
    fail "iperf3 retransmits ${RETRANSMITS} > 100"
fi
