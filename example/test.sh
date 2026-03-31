#!/usr/bin/env bash
# Integration tests for the echo example over TUN.
# Requires root. Starts/stops the echo server automatically.
#
# Usage: sudo ./example/test.sh

set -euo pipefail

ECHO_BIN="./example/echo"
TUN_IP="10.0.0.1"
PORT=7777
PASS=0
FAIL=0
TMPDIR=$(mktemp -d)

cleanup() {
    pkill -f "$ECHO_BIN" 2>/dev/null || true
    rm -rf "$TMPDIR"
    ip link del tun0 2>/dev/null || true
}
trap cleanup EXIT

log()  { printf "\033[1m%s\033[0m\n" "$*"; }
pass() { PASS=$((PASS + 1)); printf "  \033[32mPASS\033[0m %s\n" "$*"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31mFAIL\033[0m %s\n" "$*"; }

# Clean previous runs (without removing TMPDIR).
pkill -f "$ECHO_BIN" 2>/dev/null || true
ip link del tun0 2>/dev/null || true
go build -o "$ECHO_BIN" ./example/
$ECHO_BIN &
sleep 1

# --- ICMP ---
log "=== ICMP ==="
if ping -c 2 -W 1 "$TUN_IP" >/dev/null 2>&1; then
    pass "ping $TUN_IP"
else
    fail "ping $TUN_IP"
fi

# --- TCP echo (basic) ---
log "=== TCP echo ==="
echo "hello tcp" > "$TMPDIR/tcp_in"
if nc -w 3 "$TUN_IP" "$PORT" < "$TMPDIR/tcp_in" > "$TMPDIR/tcp_out" 2>/dev/null; then
    if diff -q "$TMPDIR/tcp_in" "$TMPDIR/tcp_out" >/dev/null 2>&1; then
        pass "basic echo"
    else
        fail "basic echo: data mismatch"
    fi
else
    fail "basic echo: nc failed"
fi

# --- UDP echo ---
log "=== UDP echo ==="
echo "hello udp" > "$TMPDIR/udp_in"
echo "hello udp" | nc -u -w 1 "$TUN_IP" "$PORT" > "$TMPDIR/udp_out" 2>/dev/null || true
if diff -q "$TMPDIR/udp_in" "$TMPDIR/udp_out" >/dev/null 2>&1; then
    pass "basic echo"
else
    fail "basic echo: data mismatch"
fi

# --- TCP: 1MB data integrity ---
log "=== TCP 1MB integrity ==="
dd if=/dev/urandom of="$TMPDIR/1m" bs=1K count=1024 2>/dev/null
SRC_MD5=$(md5sum "$TMPDIR/1m" | awk '{print $1}')
nc -w 10 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_out" 2>/dev/null
DST_MD5=$(md5sum "$TMPDIR/1m_out" | awk '{print $1}')
if [ "$SRC_MD5" = "$DST_MD5" ]; then
    pass "1MB echo (md5 match)"
else
    fail "1MB echo (src=$SRC_MD5 dst=$DST_MD5)"
fi

# --- TCP: 5% packet loss ---
log "=== TCP 1MB + 5% loss ==="
tc qdisc add dev tun0 root netem loss 5%
nc -w 30 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_loss5" 2>/dev/null
DST_MD5=$(md5sum "$TMPDIR/1m_loss5" | awk '{print $1}')
tc qdisc del dev tun0 root 2>/dev/null
if [ "$SRC_MD5" = "$DST_MD5" ]; then
    pass "1MB echo under 5% loss"
else
    fail "1MB echo under 5% loss (src=$SRC_MD5 dst=$DST_MD5)"
fi

# --- TCP: 10% loss + 50ms delay ---
log "=== TCP 1MB + 10% loss + 50ms delay ==="
tc qdisc add dev tun0 root netem loss 10% delay 50ms
START=$(date +%s)
nc -w 120 "$TUN_IP" "$PORT" < "$TMPDIR/1m" > "$TMPDIR/1m_loss10" 2>/dev/null
END=$(date +%s)
DST_MD5=$(md5sum "$TMPDIR/1m_loss10" | awk '{print $1}')
tc qdisc del dev tun0 root 2>/dev/null
if [ "$SRC_MD5" = "$DST_MD5" ]; then
    pass "1MB echo under 10% loss + 50ms delay (${END-START}s)"
else
    fail "1MB echo under 10% loss + 50ms delay (src=$SRC_MD5 dst=$DST_MD5)"
fi

# --- Concurrent connections ---
log "=== 100 concurrent connections ==="
dd if=/dev/urandom of="$TMPDIR/small" bs=1K count=1 2>/dev/null
EXPECTED=$(md5sum "$TMPDIR/small" | awk '{print $1}')
mkdir -p "$TMPDIR/conc"

for i in $(seq 1 100); do
    (nc -w 5 "$TUN_IP" "$PORT" < "$TMPDIR/small" > "$TMPDIR/conc/$i" 2>/dev/null) &
done
wait

CONC_PASS=0
for i in $(seq 1 100); do
    GOT=$(md5sum "$TMPDIR/conc/$i" 2>/dev/null | awk '{print $1}')
    [ "$GOT" = "$EXPECTED" ] && CONC_PASS=$((CONC_PASS + 1))
done

if [ "$CONC_PASS" -eq 100 ]; then
    pass "100/100 connections OK"
else
    fail "$CONC_PASS/100 connections OK"
fi

# --- Summary ---
echo ""
log "=== Summary ==="
printf "  pass: %d, fail: %d\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
