package udp

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
)

// buildUDPPacket constructs a valid IPv4+UDP packet.
func buildUDPPacket(src, dst tcpip.Address, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := uint16(header.UDPHeaderSize + len(payload))
	totalLen := header.IPv4MinHeaderSize + int(udpLen)
	buf := make([]byte, totalLen)

	// IPv4 header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    tcpip.UDPProtocolNumber,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(header.Checksum(buf[:header.IPv4MinHeaderSize], 0))

	// UDP header.
	udpBuf := buf[header.IPv4MinHeaderSize:]
	udpHdr := header.UDP(udpBuf)
	udpHdr.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  udpLen,
	})
	copy(udpBuf[header.UDPHeaderSize:], payload)

	// UDP checksum.
	udpHdr.SetChecksum(0)
	phc := header.PseudoHeaderChecksum(tcpip.UDPProtocolNumber, src, dst, udpLen)
	udpHdr.SetChecksum(header.Checksum(udpBuf[:udpLen], phc))

	return buf
}

func TestHandlerCreatesNATEntry(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := stack.New(ch)

	h := NewUDPHandler(s, WithCleanInterval(time.Second))
	defer h.Close()

	var mu sync.Mutex
	var receivedFlow FlowID
	callbackCalled := false

	h.SetNewSessionCallback(func(flow FlowID) bool {
		mu.Lock()
		receivedFlow = flow
		callbackCalled = true
		mu.Unlock()
		return true
	})

	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()
	defer s.Stop()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)
	pkt := buildUDPPacket(src, dst, 12345, 53, []byte("dns query"))
	ch.Inject(pkt)

	// Wait for processing.
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if !callbackCalled {
		t.Fatal("onNewSession callback was not called")
	}

	if receivedFlow.SrcAddr != src {
		t.Errorf("flow SrcAddr = %s, want %s", receivedFlow.SrcAddr, src)
	}
	if receivedFlow.SrcPort != 12345 {
		t.Errorf("flow SrcPort = %d, want 12345", receivedFlow.SrcPort)
	}
	if receivedFlow.DstAddr != dst {
		t.Errorf("flow DstAddr = %s, want %s", receivedFlow.DstAddr, dst)
	}
	if receivedFlow.DstPort != 53 {
		t.Errorf("flow DstPort = %d, want 53", receivedFlow.DstPort)
	}

	// Verify NAT entry was created.
	entry := h.nat.Lookup(receivedFlow)
	if entry == nil {
		t.Error("NAT entry should have been created")
	}
}

func TestHandlerRejectsFlow(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := stack.New(ch)

	h := NewUDPHandler(s, WithCleanInterval(time.Second))
	defer h.Close()

	h.SetNewSessionCallback(func(flow FlowID) bool {
		return false // reject all
	})

	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()
	defer s.Stop()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)
	pkt := buildUDPPacket(src, dst, 12345, 53, []byte("rejected"))
	ch.Inject(pkt)

	time.Sleep(100 * time.Millisecond)

	flow := FlowID{SrcAddr: src, SrcPort: 12345, DstAddr: dst, DstPort: 53}
	if h.nat.Lookup(flow) != nil {
		t.Error("NAT entry should NOT be created when callback rejects")
	}
}

func TestHandlerReusesExistingEntry(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := stack.New(ch)

	h := NewUDPHandler(s, WithCleanInterval(time.Second))
	defer h.Close()

	callCount := 0
	h.SetNewSessionCallback(func(flow FlowID) bool {
		callCount++
		return true
	})

	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()
	defer s.Stop()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)

	// Send same flow twice.
	pkt1 := buildUDPPacket(src, dst, 12345, 53, []byte("query1"))
	pkt2 := buildUDPPacket(src, dst, 12345, 53, []byte("query2"))
	ch.Inject(pkt1)
	time.Sleep(50 * time.Millisecond)
	ch.Inject(pkt2)
	time.Sleep(100 * time.Millisecond)

	if callCount != 1 {
		t.Errorf("callback called %d times, want 1 (should reuse entry)", callCount)
	}
}

func TestHandlerGoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	ch := channel.NewMemory(1500)
	s := stack.New(ch)

	h := NewUDPHandler(s, WithCleanInterval(50*time.Millisecond))

	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()

	// Create a NAT entry by injecting a packet.
	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)
	pkt := buildUDPPacket(src, dst, 12345, 53, []byte("test"))
	ch.Inject(pkt)
	time.Sleep(100 * time.Millisecond)

	// Verify goroutines were spawned.
	during := runtime.NumGoroutine()
	if during <= before {
		t.Error("expected goroutines to be spawned")
	}

	// Shut down.
	h.Close()
	s.Stop()

	// Wait for goroutines to exit.
	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	after := runtime.NumGoroutine()
	if after > before+1 {
		t.Errorf("goroutine leak: before=%d, after=%d", before, after)
	}
}
