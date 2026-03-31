#!/usr/bin/env bash
# Shared helpers for integration tests.
# Source this file, don't execute it directly.
#
# Each test can set TUN_DEV / TUN_SUBNET / TUN_IP before sourcing to get
# its own isolated TUN device.  Defaults are tun0 / 10.0.0.0/24 / 10.0.0.1.

ECHO_BIN="${ECHO_BIN:-./example/echo}"
TUN_DEV="${TUN_DEV:-tun0}"
TUN_SUBNET="${TUN_SUBNET:-10.0.0.0/24}"
TUN_IP="${TUN_IP:-10.0.0.1}"
PORT=7777
TMPDIR=$(mktemp -d)
_PASS=0
_FAIL=0

log()  { printf "\033[1m%s\033[0m\n" "$*"; }
pass() { _PASS=$((_PASS + 1)); printf "  \033[32mPASS\033[0m %s\n" "$*"; }
fail() { _FAIL=$((_FAIL + 1)); printf "  \033[31mFAIL\033[0m %s\n" "$*"; }

start_echo() {
    ip link del "$TUN_DEV" 2>/dev/null || true
    sleep 0.3
    go build -o "$ECHO_BIN" ./example/
    $ECHO_BIN -tun "$TUN_DEV" -subnet "$TUN_SUBNET" "$@" &
    ECHO_PID=$!
    sleep 1
}

stop_echo() {
    tc qdisc del dev "$TUN_DEV" root 2>/dev/null || true
    kill "$ECHO_PID" 2>/dev/null || true
    wait "$ECHO_PID" 2>/dev/null || true
    rm -rf "$TMPDIR"
}

summary() {
    echo ""
    log "=== Summary ==="
    printf "  pass: %d, fail: %d\n" "$_PASS" "$_FAIL"
    [ "$_FAIL" -eq 0 ]
}

check_md5() {
    local file1="$1" file2="$2"
    local md5_1 md5_2
    md5_1=$(md5sum "$file1" | awk '{print $1}')
    md5_2=$(md5sum "$file2" | awk '{print $1}')
    [ "$md5_1" = "$md5_2" ]
}
