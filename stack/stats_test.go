package stack

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/tcpip"
)

func TestStats_PacketCounters(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := New(ch)
	stats := s.EnableStats()
	s.Start()
	defer s.Stop()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(10, 0, 0, 2)

	// Inject an ICMP echo — should increment PacketsIn and BytesIn.
	pkt := buildICMPEchoRequest(src, dst, 1, 1)
	ch.Inject(pkt)

	// Wait for readLoop to process.
	time.Sleep(50 * time.Millisecond)

	if got := stats.PacketsIn.Load(); got != 1 {
		t.Errorf("PacketsIn = %d, want 1", got)
	}
	if got := stats.BytesIn.Load(); got != uint64(len(pkt)) {
		t.Errorf("BytesIn = %d, want %d", got, len(pkt))
	}

	// ICMP echo reply should have been sent — check PacketsOut/BytesOut.
	resp := ch.Read(time.Second)
	if resp == nil {
		t.Fatal("expected ICMP echo reply")
	}
	if got := stats.PacketsOut.Load(); got != 1 {
		t.Errorf("PacketsOut = %d, want 1", got)
	}
	if got := stats.BytesOut.Load(); got == 0 {
		t.Error("BytesOut = 0, want > 0")
	}

	// Inject a packet with unknown protocol — should increment UnknownProtocol.
	unknownPkt := buildIPv4Packet(src, dst, 253, []byte{0, 0, 0, 0})
	ch.Inject(unknownPkt)
	time.Sleep(50 * time.Millisecond)

	if got := stats.UnknownProtocol.Load(); got != 1 {
		t.Errorf("UnknownProtocol = %d, want 1", got)
	}
}

func TestStats_OutboundQueueLen(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := New(ch)

	if got := s.OutboundQueueLen(); got != 0 {
		t.Errorf("OutboundQueueLen = %d, want 0", got)
	}
}

func TestStats_Nil(t *testing.T) {
	// Without EnableStats, nothing should panic.
	ch := channel.NewMemory(1500)
	s := New(ch)
	s.Start()
	defer s.Stop()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(10, 0, 0, 2)
	pkt := buildICMPEchoRequest(src, dst, 1, 1)
	ch.Inject(pkt)
	ch.Read(time.Second)

	// Also inject unknown protocol.
	unknownPkt := buildIPv4Packet(src, dst, 253, []byte{0, 0, 0, 0})
	ch.Inject(unknownPkt)
	time.Sleep(50 * time.Millisecond)
}

