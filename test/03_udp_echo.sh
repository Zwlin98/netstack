#!/usr/bin/env bash
# Test: UDP echo
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

log "=== UDP echo ==="
echo "hello udp" > "$TMPDIR/udp_in"
echo "hello udp" | nc -u -w 1 "$TUN_IP" "$PORT" > "$TMPDIR/udp_out" 2>/dev/null || true
if diff -q "$TMPDIR/udp_in" "$TMPDIR/udp_out" >/dev/null 2>&1; then
    pass "basic echo"
else
    fail "basic echo"
fi

udp_datagram_echo() {
    local size="$1"
    local input="$2"
    local output="$3"

    python3 - "$TUN_IP" "$PORT" "$size" "$input" "$output" <<'PY'
import socket
import sys

ip = sys.argv[1]
port = int(sys.argv[2])
size = int(sys.argv[3])
input_path = sys.argv[4]
output_path = sys.argv[5]

payload = bytes(((i * 31 + 7) & 0xff) for i in range(size))
with open(input_path, "wb") as f:
    f.write(payload)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(10)

# Let the host kernel fragment large UDP datagrams on the TUN route.
mtu_discover = getattr(socket, "IP_MTU_DISCOVER", 10)
pmtudisc_dont = getattr(socket, "IP_PMTUDISC_DONT", 0)
try:
    sock.setsockopt(socket.IPPROTO_IP, mtu_discover, pmtudisc_dont)
except OSError:
    pass

sock.sendto(payload, (ip, port))
data, _ = sock.recvfrom(65535)
with open(output_path, "wb") as f:
    f.write(data)

if data != payload:
    raise SystemExit(1)
PY
}

log "=== UDP echo: large datagrams ==="
for size in 4096 32768 65507; do
    in_file="$TMPDIR/udp_${size}_in"
    out_file="$TMPDIR/udp_${size}_out"
    if udp_datagram_echo "$size" "$in_file" "$out_file"; then
        pass "${size}B datagram echo"
    else
        fail "${size}B datagram echo"
    fi
done
