#!/usr/bin/env bash
# Run all integration tests.
# Usage: sudo ./test/run_all.sh [test_file...]
#
# Examples:
#   sudo ./test/run_all.sh                  # run all tests
#   sudo ./test/run_all.sh test/01_icmp.sh  # run specific test
set -euo pipefail

cd "$(dirname "$0")/.."
source test/helpers.sh

start_echo ${ECHO_EXTRA_ARGS:-}
trap stop_echo EXIT

if [ $# -gt 0 ]; then
    TESTS=("$@")
else
    TESTS=(test/[0-9]*.sh)
fi

for t in "${TESTS[@]}"; do
    source "$t"
done

summary
