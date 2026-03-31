#!/usr/bin/env bash
# Test: ICMP echo (ping)
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

log "=== ICMP ==="
if ping -c 2 -W 1 "$TUN_IP" >/dev/null 2>&1; then
    pass "ping $TUN_IP"
else
    fail "ping $TUN_IP"
fi
