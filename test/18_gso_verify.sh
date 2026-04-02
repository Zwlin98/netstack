#!/usr/bin/env bash
# Test: Verify GSO (Generic Segmentation Offload) is working.
# Traces writev syscalls during a large TCP transfer and checks for
# GSO segments (>1500 bytes with non-zero virtio headers).
set -euo pipefail
source "$(dirname "$0")/helpers.sh"

if ! command -v strace &>/dev/null; then
    log "=== GSO verify (SKIPPED: strace not installed) ==="
    return 0 2>/dev/null || exit 0
fi

log "=== GSO verify ==="

dd if=/dev/urandom of="$TMPDIR/gso_10m" bs=1K count=10240 2>/dev/null

# Trace writev calls on the echo server during a 10MB transfer.
strace -p "$ECHO_PID" -f -e writev -o "$TMPDIR/strace_gso.txt" &
STRACE_PID=$!
sleep 1

nc -N -w 60 "$TUN_IP" "$PORT" < "$TMPDIR/gso_10m" > "$TMPDIR/gso_10m_out" 2>/dev/null

sleep 1
kill "$STRACE_PID" 2>/dev/null
wait "$STRACE_PID" 2>/dev/null || true

# Verify data integrity first.
if ! check_md5 "$TMPDIR/gso_10m" "$TMPDIR/gso_10m_out"; then
    fail "GSO 10MB echo data integrity"
    return 0 2>/dev/null || exit 0
fi
pass "GSO 10MB echo data integrity"

# Extract packet sizes from writev calls.
# Each writev has two iovecs: [virtio_header(10B), packet(NB)].
# We want the second iov_len (the actual packet size).
grep -oP 'iov_len=\K\d+' "$TMPDIR/strace_gso.txt" | awk 'NR%2==0' > "$TMPDIR/pkt_sizes.txt"

TOTAL=$(wc -l < "$TMPDIR/pkt_sizes.txt")
ACK_COUNT=$(awk '$1 <= 64' "$TMPDIR/pkt_sizes.txt" | wc -l)
DATA_COUNT=$(awk '$1 > 64 && $1 <= 1500' "$TMPDIR/pkt_sizes.txt" | wc -l)
GSO_COUNT=$(awk '$1 > 1500' "$TMPDIR/pkt_sizes.txt" | wc -l)
GSO_MAX=$(awk 'BEGIN{m=0} $1>m{m=$1} END{print m}' "$TMPDIR/pkt_sizes.txt")

printf "  writev total: %d, ACKs: %d, data: %d, GSO: %d, max GSO: %d bytes\n" \
    "$TOTAL" "$ACK_COUNT" "$DATA_COUNT" "$GSO_COUNT" "${GSO_MAX:-0}"

# Verify GSO segments exist (at least 10 for a 10MB transfer).
if [ "$GSO_COUNT" -ge 10 ]; then
    pass "GSO segments present ($GSO_COUNT segments, max ${GSO_MAX}B)"
else
    fail "GSO segments not detected ($GSO_COUNT < 10)"
fi

# Verify largest GSO segment is significantly larger than MSS.
# With timestamps MSS=1448, GSO segments should be at least 2*MSS.
if [ "${GSO_MAX:-0}" -ge 2896 ]; then
    pass "GSO batching effective (max segment ${GSO_MAX}B >= 2*MSS)"
else
    fail "GSO batching too small (max ${GSO_MAX:-0}B < 2*MSS)"
fi

# Verify non-zero virtio headers exist (NEEDS_CSUM flag = 0x01 as first byte).
GSO_HDRS=$(grep -cP 'iov_base="\\1\\001' "$TMPDIR/strace_gso.txt" || true)
if [ "${GSO_HDRS:-0}" -ge 1 ]; then
    pass "Virtio GSO headers present ($GSO_HDRS packets with NEEDS_CSUM+GSO_TCPV4)"
else
    fail "No virtio GSO headers detected"
fi
