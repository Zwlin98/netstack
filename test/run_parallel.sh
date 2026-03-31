#!/usr/bin/env bash
# Run netem integration tests in parallel, each on its own TUN + subnet.
#
# Usage: sudo ./test/run_parallel.sh [test_file...]
#
# Examples:
#   sudo ./test/run_parallel.sh                                      # run 04-10
#   sudo ./test/run_parallel.sh test/07_reorder.sh test/08_duplicate.sh  # specific tests
set -euo pipefail

cd "$(dirname "$0")/.."

ECHO_BIN="./example/echo"
go build -o "$ECHO_BIN" ./example/

if [ $# -gt 0 ]; then
    TESTS=("$@")
else
    TESTS=(test/04_packet_loss.sh test/07_reorder.sh test/08_duplicate.sh test/09_jitter.sh test/10_bandwidth.sh test/11_large_transfer.sh test/12_stress.sh test/13_combined.sh test/15_conn_lifecycle.sh test/17_abrupt_disconnect.sh)
fi

PIDS=()
LOGS=()
NAMES=()
SLOT=0

for t in "${TESTS[@]}"; do
    SLOT=$((SLOT + 1))
    TNAME=$(basename "$t" .sh)
    DEV="tun${SLOT}"
    SUBNET="10.0.${SLOT}.0/24"
    IP="10.0.${SLOT}.1"
    LOGFILE=$(mktemp)

    printf "\033[1m▶ %-20s\033[0m  dev=%-6s ip=%s\n" "$TNAME" "$DEV" "$IP"

    (
        export TUN_DEV="$DEV" TUN_SUBNET="$SUBNET" TUN_IP="$IP" ECHO_BIN="$ECHO_BIN"

        cd "$(dirname "$0")/.."
        source test/helpers.sh

        start_echo ${ECHO_EXTRA_ARGS:-}
        trap stop_echo EXIT

        source "$t"
        summary
    ) > "$LOGFILE" 2>&1 &

    PIDS+=($!)
    LOGS+=("$LOGFILE")
    NAMES+=("$TNAME")
done

# Wait for all and collect results.
TOTAL_PASS=0
TOTAL_FAIL=0
ALL_OK=true

for i in "${!PIDS[@]}"; do
    pid=${PIDS[$i]}
    log=${LOGS[$i]}
    name=${NAMES[$i]}

    if wait "$pid"; then
        STATUS="\033[32mPASS\033[0m"
    else
        STATUS="\033[31mFAIL\033[0m"
        ALL_OK=false
    fi

    # Extract pass/fail counts from summary line.
    P=$(grep -oP 'pass: \K\d+' "$log" 2>/dev/null | tail -1 || echo 0)
    F=$(grep -oP 'fail: \K\d+' "$log" 2>/dev/null | tail -1 || echo 0)
    TOTAL_PASS=$((TOTAL_PASS + P))
    TOTAL_FAIL=$((TOTAL_FAIL + F))

    printf "  $STATUS  %-20s  pass: %d  fail: %d\n" "$name" "$P" "$F"

    # Show detail on failure.
    if [ "$F" -gt 0 ] || ! wait "$pid" 2>/dev/null; then
        sed 's/^/    │ /' "$log"
    fi

    rm -f "$log"
done

echo ""
printf "\033[1m=== Parallel Summary ===\033[0m\n"
printf "  pass: %d, fail: %d\n" "$TOTAL_PASS" "$TOTAL_FAIL"

$ALL_OK
