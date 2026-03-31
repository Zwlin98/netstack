package udp

import (
	"bytes"
	"runtime"
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

func setupStack() (*stack.Stack, *channel.MemoryChannel, *UDPHandler) {
	ch := channel.NewMemory(1500)
	s := stack.New(ch)
	h := NewUDPHandler(s)
	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()
	return s, ch, h
}

func TestReadFrom(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)
	payload := []byte("hello udp")
	pkt := buildUDPPacket(src, dst, 12345, 53, payload)
	ch.Inject(pkt)

	buf := make([]byte, 1500)
	n, gotSrc, gotDst, err := h.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}

	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("payload = %q, want %q", buf[:n], payload)
	}
	if gotSrc.Addr != src || gotSrc.Port != 12345 {
		t.Errorf("src = %s:%d, want %s:12345", gotSrc.Addr, gotSrc.Port, src)
	}
	if gotDst.Addr != dst || gotDst.Port != 53 {
		t.Errorf("dst = %s:%d, want %s:53", gotDst.Addr, gotDst.Port, dst)
	}
}

func TestWriteTo(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.FullAddress{Addr: tcpip.From4(8, 8, 8, 8), Port: 53}
	dst := tcpip.FullAddress{Addr: tcpip.From4(10, 0, 0, 1), Port: 12345}
	payload := []byte("dns response")

	n, err := h.WriteTo(payload, src, dst)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo returned %d, want %d", n, len(payload))
	}

	// Read the packet from channel.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected packet on channel")
	}

	// Validate IPv4 header.
	ip := header.IPv4(raw)
	if ip.SourceAddress() != src.Addr {
		t.Errorf("IP src = %s, want %s", ip.SourceAddress(), src.Addr)
	}
	if ip.DestinationAddress() != dst.Addr {
		t.Errorf("IP dst = %s, want %s", ip.DestinationAddress(), dst.Addr)
	}

	// Validate UDP header.
	udpHdr := header.UDP(raw[ip.HeaderLength():])
	if udpHdr.SourcePort() != src.Port {
		t.Errorf("UDP src port = %d, want %d", udpHdr.SourcePort(), src.Port)
	}
	if udpHdr.DestinationPort() != dst.Port {
		t.Errorf("UDP dst port = %d, want %d", udpHdr.DestinationPort(), dst.Port)
	}

	// Validate payload.
	got := udpHdr.Payload()
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

func TestReadFromBlocksUntilPacket(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	done := make(chan struct{})
	var n int
	var err error
	buf := make([]byte, 1500)

	go func() {
		n, _, _, err = h.ReadFrom(buf)
		close(done)
	}()

	// Ensure ReadFrom is blocking.
	select {
	case <-done:
		t.Fatal("ReadFrom should block when no data")
	case <-time.After(50 * time.Millisecond):
	}

	// Inject a packet to unblock.
	payload := []byte("wake up")
	pkt := buildUDPPacket(tcpip.From4(10, 0, 0, 1), tcpip.From4(8, 8, 8, 8), 1000, 53, payload)
	ch.Inject(pkt)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ReadFrom did not unblock after packet injection")
	}

	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("payload = %q, want %q", buf[:n], payload)
	}
}

func TestReadFromUnblocksOnClose(t *testing.T) {
	s, ch, _ := setupStack()
	_ = ch
	defer s.Stop()

	h := NewUDPHandler(s)
	errCh := make(chan error, 1)

	go func() {
		buf := make([]byte, 1500)
		_, _, _, err := h.ReadFrom(buf)
		errCh <- err
	}()

	// Let ReadFrom block.
	time.Sleep(50 * time.Millisecond)
	h.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReadFrom should return error after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFrom did not unblock after Close")
	}
}

func TestQueueBackpressure(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)

	// Fill the queue beyond capacity.
	for i := 0; i < inboundQueueSize+10; i++ {
		pkt := buildUDPPacket(src, dst, uint16(1000+i), 53, []byte("x"))
		ch.Inject(pkt)
	}

	// Wait for processing.
	time.Sleep(200 * time.Millisecond)

	// Should be able to drain exactly inboundQueueSize items.
	count := 0
	for {
		buf := make([]byte, 1500)
		done := make(chan struct{})
		var err error
		go func() {
			_, _, _, err = h.ReadFrom(buf)
			close(done)
		}()

		select {
		case <-done:
			if err != nil {
				break
			}
			count++
		case <-time.After(100 * time.Millisecond):
			goto out
		}
	}
out:
	if count != inboundQueueSize {
		t.Errorf("drained %d datagrams, want %d", count, inboundQueueSize)
	}
}

func TestWriteToAfterClose(t *testing.T) {
	s, _, h := setupStack()
	defer s.Stop()

	h.Close()

	_, err := h.WriteTo([]byte("data"), tcpip.FullAddress{}, tcpip.FullAddress{})
	if err == nil {
		t.Fatal("WriteTo should return error after Close")
	}
}

func TestNoGoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	ch := channel.NewMemory(1500)
	s := stack.New(ch)
	h := NewUDPHandler(s)
	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()

	// Inject a packet and read it.
	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)
	pkt := buildUDPPacket(src, dst, 12345, 53, []byte("test"))
	ch.Inject(pkt)

	buf := make([]byte, 1500)
	h.ReadFrom(buf)

	// Shut down.
	h.Close()
	s.Stop()

	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	after := runtime.NumGoroutine()
	if after > before+1 {
		t.Errorf("goroutine leak: before=%d, after=%d", before, after)
	}
}

func TestMultipleDatagrams(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)

	payloads := []string{"first", "second", "third"}
	for _, p := range payloads {
		pkt := buildUDPPacket(src, dst, 12345, 53, []byte(p))
		ch.Inject(pkt)
	}

	// Wait for all packets to be processed.
	time.Sleep(100 * time.Millisecond)

	for _, want := range payloads {
		buf := make([]byte, 1500)
		n, _, _, err := h.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		if string(buf[:n]) != want {
			t.Errorf("payload = %q, want %q", string(buf[:n]), want)
		}
	}
}
