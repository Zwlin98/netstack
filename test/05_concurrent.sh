#!/usr/bin/env bash
# Test: concurrent TCP connections
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

N=100
log "=== $N concurrent connections ==="

dd if=/dev/urandom of="$TMPDIR/small" bs=1K count=1 2>/dev/null
EXPECTED=$(md5sum "$TMPDIR/small" | awk '{print $1}')
mkdir -p "$TMPDIR/conc"

for i in $(seq 1 $N); do
    (nc -w 5 "$TUN_IP" "$PORT" < "$TMPDIR/small" > "$TMPDIR/conc/$i" 2>/dev/null) &
done
wait

CONC_PASS=0
for i in $(seq 1 $N); do
    GOT=$(md5sum "$TMPDIR/conc/$i" 2>/dev/null | awk '{print $1}')
    [ "$GOT" = "$EXPECTED" ] && CONC_PASS=$((CONC_PASS + 1))
done

if [ "$CONC_PASS" -eq "$N" ]; then
    pass "$CONC_PASS/$N connections OK"
else
    fail "$CONC_PASS/$N connections OK"
fi
