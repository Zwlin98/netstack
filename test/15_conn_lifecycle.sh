#!/usr/bin/env bash
# Test: connection lifecycle — rapid sequential reconnections, TIME_WAIT handling
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

dd if=/dev/urandom of="$TMPDIR/1k" bs=1K count=1 2>/dev/null
dd if=/dev/urandom of="$TMPDIR/1m" bs=1K count=1024 2>/dev/null
EXPECTED=$(md5sum "$TMPDIR/1k" | awk '{print $1}')

# --- 200 rapid sequential connections, 1KB each ---
N=200
log "=== $N sequential connections, 1KB each ==="
mkdir -p "$TMPDIR/lifecycle1"
START=$(date +%s)
for i in $(seq 1 $N); do
    nc -N -w 5 "$TUN_IP" "$PORT" < "$TMPDIR/1k" > "$TMPDIR/lifecycle1/$i" 2>/dev/null
done
ELAPSED=$(( $(date +%s) - START ))
OK=0
for i in $(seq 1 $N); do
    GOT=$(md5sum "$TMPDIR/lifecycle1/$i" 2>/dev/null | awk '{print $1}')
    [ "$GOT" = "$EXPECTED" ] && OK=$((OK + 1))
done
if [ "$OK" -eq "$N" ]; then
    pass "$OK/$N sequential connections OK (${ELAPSED}s)"
else
    fail "$OK/$N sequential connections OK (${ELAPSED}s)"
fi

# --- 200 rapid sequential connections with 3% loss ---
log "=== $N sequential connections, 1KB each, 3% loss ==="
tc qdisc add dev $TUN_DEV root netem loss 3%
mkdir -p "$TMPDIR/lifecycle2"
START=$(date +%s)
for i in $(seq 1 $N); do
    nc -N -w 10 "$TUN_IP" "$PORT" < "$TMPDIR/1k" > "$TMPDIR/lifecycle2/$i" 2>/dev/null
done
ELAPSED=$(( $(date +%s) - START ))
tc qdisc del dev $TUN_DEV root 2>/dev/null
OK=0
for i in $(seq 1 $N); do
    GOT=$(md5sum "$TMPDIR/lifecycle2/$i" 2>/dev/null | awk '{print $1}')
    [ "$GOT" = "$EXPECTED" ] && OK=$((OK + 1))
done
if [ "$OK" -eq "$N" ]; then
    pass "$OK/$N sequential connections with 3% loss (${ELAPSED}s)"
else
    fail "$OK/$N sequential connections with 3% loss (${ELAPSED}s)"
fi

# --- Post-stress 1MB echo ---
log "=== Post-stress 1MB echo ==="
nc -N -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_post" 2>/dev/null
if check_md5 "$TMPDIR/1m" "$TMPDIR/1m_post"; then
    pass "1MB echo after 400 rapid connections"
else
    fail "1MB echo after 400 rapid connections"
fi
