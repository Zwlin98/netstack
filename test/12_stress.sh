#!/usr/bin/env bash
# Test: TCP stress — high-concurrency connections with data verification.
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

dd if=/dev/urandom of="$TMPDIR/64k" bs=1K count=64 2>/dev/null
dd if=/dev/urandom of="$TMPDIR/16k" bs=1K count=16 2>/dev/null
EXPECTED_64K=$(md5sum "$TMPDIR/64k" | awk '{print $1}')
EXPECTED_16K=$(md5sum "$TMPDIR/16k" | awk '{print $1}')

# --- 50 connections, 64KB each ---
N=50
log "=== $N concurrent connections, 64KB each ==="
mkdir -p "$TMPDIR/stress1"
PIDS=()
for i in $(seq 1 $N); do
    (nc -N -w 10 "$TUN_IP" "$PORT" < "$TMPDIR/64k" > "$TMPDIR/stress1/$i" 2>/dev/null) &
    PIDS+=($!)
done
for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
OK=0
for i in $(seq 1 $N); do
    GOT=$(md5sum "$TMPDIR/stress1/$i" 2>/dev/null | awk '{print $1}')
    [ "$GOT" = "$EXPECTED_64K" ] && OK=$((OK + 1))
done
if [ "$OK" -eq "$N" ]; then
    pass "$OK/$N connections OK (64KB)"
else
    fail "$OK/$N connections OK (64KB)"
fi

# --- 100 connections, 16KB each ---
N=100
log "=== $N concurrent connections, 16KB each ==="
mkdir -p "$TMPDIR/stress2"
PIDS=()
for i in $(seq 1 $N); do
    (nc -N -w 10 "$TUN_IP" "$PORT" < "$TMPDIR/16k" > "$TMPDIR/stress2/$i" 2>/dev/null) &
    PIDS+=($!)
done
for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
OK=0
for i in $(seq 1 $N); do
    GOT=$(md5sum "$TMPDIR/stress2/$i" 2>/dev/null | awk '{print $1}')
    [ "$GOT" = "$EXPECTED_16K" ] && OK=$((OK + 1))
done
if [ "$OK" -eq "$N" ]; then
    pass "$OK/$N connections OK (16KB)"
else
    fail "$OK/$N connections OK (16KB)"
fi

# --- 50 connections, 64KB each, 3% loss ---
N=50
log "=== $N concurrent connections, 64KB each, 3% loss ==="
tc qdisc add dev $TUN_DEV root netem loss 3%
mkdir -p "$TMPDIR/stress3"
PIDS=()
for i in $(seq 1 $N); do
    (nc -N -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/64k" > "$TMPDIR/stress3/$i" 2>/dev/null) &
    PIDS+=($!)
done
for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
tc qdisc del dev $TUN_DEV root 2>/dev/null
OK=0
for i in $(seq 1 $N); do
    GOT=$(md5sum "$TMPDIR/stress3/$i" 2>/dev/null | awk '{print $1}')
    [ "$GOT" = "$EXPECTED_64K" ] && OK=$((OK + 1))
done
if [ "$OK" -eq "$N" ]; then
    pass "$OK/$N connections OK (64KB + 3% loss)"
else
    fail "$OK/$N connections OK (64KB + 3% loss)"
fi
