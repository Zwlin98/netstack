#!/usr/bin/env bash
# Shared helpers for integration tests.
# Source this file, don't execute it directly.

ECHO_BIN="./example/echo"
TUN_IP="10.0.0.1"
PORT=7777
TMPDIR=$(mktemp -d)
_PASS=0
_FAIL=0

log()  { printf "\033[1m%s\033[0m\n" "$*"; }
pass() { _PASS=$((_PASS + 1)); printf "  \033[32mPASS\033[0m %s\n" "$*"; }
fail() { _FAIL=$((_FAIL + 1)); printf "  \033[31mFAIL\033[0m %s\n" "$*"; }

start_echo() {
    pkill -f "$ECHO_BIN" 2>/dev/null || true
    ip link del tun0 2>/dev/null || true
    sleep 0.3
    go build -o "$ECHO_BIN" ./example/
    $ECHO_BIN &
    ECHO_PID=$!
    sleep 1
}

stop_echo() {
    tc qdisc del dev tun0 root 2>/dev/null || true
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
