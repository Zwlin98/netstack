# netstack

Pure Go userspace TCP/IP stack, designed as a LAN gateway (TUN device serving internal network clients).

## Build & Test

```bash
go build -o ./example/echo ./example/     # Build example binary
go test ./...                              # Unit tests (MemoryChannel)
sudo ./test/run_all.sh                     # Integration tests (real TUN, requires root)
```

Both must pass after any code change.

## Architecture

```
TUN Device → Channel (packet I/O)
                ↓
             Stack (IPv4 parse + ICMP)
                ↓
          ┌─────┴─────┐
       TCP Handler   UDP Handler
          ↓              ↓
       TCPListener    PacketConn
          ↓
       TCPConn (goroutine-per-connection)
```

- `channel/` — Channel interface (TUN, MemoryChannel for tests, GSO)
- `stack/` — IPv4 dispatch, ICMP echo, outbound queue, stats
- `transport/tcp/` — Full TCP state machine, conn.run() select loop
- `transport/udp/` — Stateless datagram handler
- `header/` — Protocol header encoding/decoding + checksum
- `packet/` — PacketBuffer, RefBuf (pooled, refcounted), GSO buffers
- `tcpip/` — Core types (Address, protocol numbers)
- `example/` — Echo/forward server binary
- `test/` — Integration test shell scripts (19 tests)

## Scope & Constraints

This is a **server-only LAN gateway**. Clients connect to the TUN device over a real network (non-zero RTT).

**Explicitly out of scope — do not propose:**
- TCP active open (Dial/Connect/SYN_SENT) — gateway is passive only
- SYN cookies, urgent data, multi-listener
- ECN, PMTUD, cwnd decay — LAN path has fixed MTU, low latency, minimal congestion
- F-RTO, PRR, RST rate limiting — not useful for LAN
- CUBIC/BBR, TFO — beyond current needs
- PMTUD and advanced fragmentation policy — LAN MTU is fixed; inbound reassembly and basic outbound IPv4 fragmentation exist, while TCP relies on MSS/GSO and UDP uses IPv4 fragmentation for oversized datagrams

## Coding Conventions

- **Commit by feature** — split commits by functional area, not one big commit
- **Nil-guarded stats** — `if st := c.stats; st != nil { st.Counter.Add(1) }` for zero-cost-when-disabled
- **Defensive fixes** — include fixes even for rare edge cases to prevent potential issues
- **Benchmarks** — TCP throughput benchmarks in `transport/tcp/throughput_bench_test.go` for profiling
- **No sensitive info in code** — do not hardcode internal hostnames, IPs, or credentials in source, comments, or commit messages; use generic placeholders like `<remote-ip>`, `<ssh-host>`
