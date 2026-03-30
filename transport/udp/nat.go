package udp

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
)

const (
	DefaultUDPTimeout = 60 * time.Second
	DNSUDPTimeout     = 10 * time.Second
	CleanInterval     = 10 * time.Second
)

// FlowID identifies a unique UDP flow (Symmetric NAT — full 4-tuple).
type FlowID struct {
	SrcAddr tcpip.Address
	SrcPort uint16
	DstAddr tcpip.Address
	DstPort uint16
}

// NATEntry represents one active UDP session.
type NATEntry struct {
	flow       FlowID
	realConn   net.PacketConn
	lastActive atomic.Int64 // unix milliseconds
	timeout    time.Duration
	done       chan struct{}
}

// NATTable manages all active UDP sessions.
type NATTable struct {
	mu      sync.RWMutex
	entries map[FlowID]*NATEntry
	stk     *stack.Stack
	done    chan struct{}
}

// newNATTable creates a new NATTable.
func newNATTable(s *stack.Stack) *NATTable {
	return &NATTable{
		entries: make(map[FlowID]*NATEntry),
		stk:     s,
		done:    make(chan struct{}),
	}
}

// Lookup returns the NATEntry for the given flow, or nil if not found.
func (t *NATTable) Lookup(flow FlowID) *NATEntry {
	t.mu.RLock()
	entry := t.entries[flow]
	t.mu.RUnlock()
	return entry
}

// CreateEntry creates a new NAT entry for the given flow, opens an OS UDP
// socket, and starts the read loop goroutine.
func (t *NATTable) CreateEntry(flow FlowID) (*NATEntry, error) {
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}

	entry := &NATEntry{
		flow:    flow,
		realConn: conn,
		timeout: timeoutForFlow(flow),
		done:    make(chan struct{}),
	}
	entry.lastActive.Store(time.Now().UnixMilli())

	t.mu.Lock()
	t.entries[flow] = entry
	t.mu.Unlock()

	go entry.readLoop(t.stk)

	return entry, nil
}

// DeleteEntry closes and removes the entry for the given flow.
func (t *NATTable) DeleteEntry(flow FlowID) {
	t.mu.Lock()
	entry, ok := t.entries[flow]
	if ok {
		delete(t.entries, flow)
	}
	t.mu.Unlock()

	if ok {
		entry.realConn.Close()
		close(entry.done)
	}
}

// Stop closes all entries and shuts down the cleaner.
func (t *NATTable) Stop() {
	close(t.done)

	t.mu.Lock()
	for flow, entry := range t.entries {
		entry.realConn.Close()
		close(entry.done)
		delete(t.entries, flow)
	}
	t.mu.Unlock()
}

// cleanerLoop periodically scans for expired entries.
func (t *NATTable) cleanerLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.cleanup()
		case <-t.done:
			return
		}
	}
}

// cleanup removes expired entries.
func (t *NATTable) cleanup() {
	now := time.Now().UnixMilli()
	t.mu.Lock()
	defer t.mu.Unlock()
	for flow, entry := range t.entries {
		idle := now - entry.lastActive.Load()
		if idle > entry.timeout.Milliseconds() {
			entry.realConn.Close()
			close(entry.done)
			delete(t.entries, flow)
		}
	}
}

// readLoop reads responses from the OS socket and sends them back through
// the stack as IP/UDP packets with swapped addresses/ports.
func (e *NATEntry) readLoop(s *stack.Stack) {
	buf := make([]byte, 1500)
	for {
		n, _, err := e.realConn.ReadFrom(buf)
		if err != nil {
			return // conn closed by cleaner or Stop
		}

		headroom := header.IPv4MinHeaderSize + header.UDPHeaderSize
		pb := packet.NewPacketBuffer(headroom)

		// Write payload into data region.
		pb.Data = pb.Buf()[:n]
		copy(pb.Data, buf[:n])

		// Prepend UDP header with swapped ports.
		udpTotalLen := uint16(header.UDPHeaderSize + n)
		udpSlice := pb.Prepend(header.UDPHeaderSize)
		udpHdr := header.UDP(udpSlice)
		udpHdr.Encode(&header.UDPFields{
			SrcPort: e.flow.DstPort, // original dst becomes src
			DstPort: e.flow.SrcPort, // original src becomes dst
			Length:  udpTotalLen,
		})

		// Compute UDP checksum with pseudo-header.
		udpHdr.SetChecksum(0)
		fullUDP := pb.AsSlice() // includes UDP header + payload (before IP prepend)
		phc := header.PseudoHeaderChecksum(
			tcpip.UDPProtocolNumber,
			e.flow.DstAddr, e.flow.SrcAddr,
			udpTotalLen,
		)
		udpHdr.SetChecksum(header.Checksum(fullUDP, phc))

		// SendPacket prepends IPv4 header.
		s.SendPacket(pb, e.flow.DstAddr, e.flow.SrcAddr, tcpip.UDPProtocolNumber)

		e.lastActive.Store(time.Now().UnixMilli())
	}
}

func timeoutForFlow(flow FlowID) time.Duration {
	if flow.DstPort == 53 {
		return DNSUDPTimeout
	}
	return DefaultUDPTimeout
}
