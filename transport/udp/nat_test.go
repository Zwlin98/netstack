package udp

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
)

func newTestStack() (*stack.Stack, *channel.MemoryChannel) {
	ch := channel.NewMemory(1500)
	s := stack.New(ch)
	s.Start()
	return s, ch
}

func TestNATTableCreateAndLookup(t *testing.T) {
	s, _ := newTestStack()
	defer s.Stop()

	nat := newNATTable(s)
	defer nat.Stop()

	flow := FlowID{
		SrcAddr: tcpip.From4(10, 0, 0, 1),
		SrcPort: 12345,
		DstAddr: tcpip.From4(8, 8, 8, 8),
		DstPort: 53,
	}

	// Lookup before create returns nil.
	if entry := nat.Lookup(flow); entry != nil {
		t.Fatal("expected nil for unknown flow")
	}

	// Create entry.
	entry, err := nat.CreateEntry(flow)
	if err != nil {
		t.Fatalf("CreateEntry: %v", err)
	}
	if entry == nil {
		t.Fatal("CreateEntry returned nil")
	}

	// Lookup returns same entry.
	got := nat.Lookup(flow)
	if got != entry {
		t.Error("Lookup should return the created entry")
	}

	// Lookup unknown flow still returns nil.
	other := FlowID{
		SrcAddr: tcpip.From4(10, 0, 0, 2),
		SrcPort: 9999,
		DstAddr: tcpip.From4(1, 1, 1, 1),
		DstPort: 53,
	}
	if nat.Lookup(other) != nil {
		t.Error("expected nil for different flow")
	}
}

func TestNATTableDeleteEntry(t *testing.T) {
	s, _ := newTestStack()
	defer s.Stop()

	nat := newNATTable(s)
	defer nat.Stop()

	flow := FlowID{
		SrcAddr: tcpip.From4(10, 0, 0, 1),
		SrcPort: 12345,
		DstAddr: tcpip.From4(8, 8, 8, 8),
		DstPort: 53,
	}

	entry, err := nat.CreateEntry(flow)
	if err != nil {
		t.Fatalf("CreateEntry: %v", err)
	}

	// Delete the entry.
	nat.DeleteEntry(flow)

	// Lookup should return nil.
	if nat.Lookup(flow) != nil {
		t.Error("expected nil after delete")
	}

	// Conn should be closed (ReadFrom should fail).
	buf := make([]byte, 1)
	_, _, err = entry.realConn.ReadFrom(buf)
	if err == nil {
		t.Error("expected error reading from closed conn")
	}
}

func TestNATTableStop(t *testing.T) {
	s, _ := newTestStack()
	defer s.Stop()

	nat := newNATTable(s)

	flow1 := FlowID{SrcAddr: tcpip.From4(10, 0, 0, 1), SrcPort: 1000, DstAddr: tcpip.From4(8, 8, 8, 8), DstPort: 53}
	flow2 := FlowID{SrcAddr: tcpip.From4(10, 0, 0, 1), SrcPort: 2000, DstAddr: tcpip.From4(1, 1, 1, 1), DstPort: 80}

	entry1, _ := nat.CreateEntry(flow1)
	entry2, _ := nat.CreateEntry(flow2)

	nat.Stop()

	// Both entries should be removed.
	if nat.Lookup(flow1) != nil || nat.Lookup(flow2) != nil {
		t.Error("expected nil after Stop")
	}

	// Both conns should be closed.
	buf := make([]byte, 1)
	if _, _, err := entry1.realConn.ReadFrom(buf); err == nil {
		t.Error("entry1 conn should be closed")
	}
	if _, _, err := entry2.realConn.ReadFrom(buf); err == nil {
		t.Error("entry2 conn should be closed")
	}
}

func TestNATTableDNSTimeout(t *testing.T) {
	flow := FlowID{DstPort: 53}
	if timeoutForFlow(flow) != DNSUDPTimeout {
		t.Errorf("DNS timeout = %v, want %v", timeoutForFlow(flow), DNSUDPTimeout)
	}

	flow2 := FlowID{DstPort: 8080}
	if timeoutForFlow(flow2) != DefaultUDPTimeout {
		t.Errorf("default timeout = %v, want %v", timeoutForFlow(flow2), DefaultUDPTimeout)
	}
}

func TestNATTableTimeoutExpiration(t *testing.T) {
	s, _ := newTestStack()
	defer s.Stop()

	nat := newNATTable(s)

	flow := FlowID{
		SrcAddr: tcpip.From4(10, 0, 0, 1),
		SrcPort: 12345,
		DstAddr: tcpip.From4(8, 8, 8, 8),
		DstPort: 9999,
	}

	entry, err := nat.CreateEntry(flow)
	if err != nil {
		t.Fatalf("CreateEntry: %v", err)
	}

	// Override timeout to be very short.
	entry.timeout = 100 * time.Millisecond

	// Start cleaner with short interval.
	go nat.cleanerLoop(50 * time.Millisecond)
	defer nat.Stop()

	// Wait for entry to expire and cleaner to run.
	time.Sleep(300 * time.Millisecond)

	if nat.Lookup(flow) != nil {
		t.Error("expected entry to be expired and removed")
	}

	// Conn should be closed.
	buf := make([]byte, 1)
	if _, _, err := entry.realConn.ReadFrom(buf); err == nil {
		t.Error("expected error from closed conn after expiration")
	}
}
