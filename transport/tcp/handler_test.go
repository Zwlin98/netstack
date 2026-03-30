package tcp_test

import (
	"encoding/binary"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// buildTCPPacket constructs a complete IPv4+TCP packet ready for injection.
func buildTCPPacket(src, dst tcpip.Address, srcPort, dstPort uint16, flags header.TCPFlags, seqNum, ackNum uint32) []byte {
	tcpLen := header.TCPMinHeaderSize
	totalLen := header.IPv4MinHeaderSize + tcpLen
	buf := make([]byte, totalLen)

	// IPv4 header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    tcpip.TCPProtocolNumber,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(header.Checksum(buf[:header.IPv4MinHeaderSize], 0))

	// TCP header.
	tcpBuf := buf[header.IPv4MinHeaderSize:]
	tcpHdr := header.TCP(tcpBuf)
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seqNum,
		AckNum:     ackNum,
		DataOffset: header.TCPMinHeaderSize / 4,
		Flags:      flags,
		WindowSize: 65535,
	})
	tcpHdr.SetChecksum(0)
	partial := header.PseudoHeaderChecksum(tcpip.TCPProtocolNumber, src, dst, uint16(tcpLen))
	tcpHdr.SetChecksum(header.Checksum(tcpBuf, partial))

	return buf
}

// parseTCPResponse parses a raw packet into IPv4 and TCP header views.
// Returns the headers and validates checksums.
func parseTCPResponse(t *testing.T, raw []byte) (header.IPv4, header.TCP) {
	t.Helper()

	if len(raw) < header.IPv4MinHeaderSize {
		t.Fatalf("response too short: %d bytes", len(raw))
	}

	ip := header.IPv4(raw)
	hdrLen := ip.HeaderLength()

	// Validate IP checksum.
	if header.Checksum(raw[:hdrLen], 0) != 0 {
		t.Error("response IP checksum invalid")
	}

	tcpData := raw[hdrLen:]
	if len(tcpData) < header.TCPMinHeaderSize {
		t.Fatalf("TCP segment too short: %d bytes", len(tcpData))
	}

	tcpHdr := header.TCP(tcpData)

	// Validate TCP checksum.
	tcpLen := uint16(len(tcpData))
	partial := header.PseudoHeaderChecksum(tcpip.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), tcpLen)
	if header.Checksum(tcpData, partial) != 0 {
		t.Error("response TCP checksum invalid")
	}

	return ip, tcpHdr
}

// setupStack creates a MemoryChannel, Stack, and TCPHandler wired together.
func setupStack(t *testing.T) (*channel.MemoryChannel, *stack.Stack, *tcp.TCPHandler) {
	t.Helper()
	ch := channel.NewMemory(1500)
	s := stack.New(ch)
	h := tcp.NewTCPHandler(s)
	s.RegisterHandler(tcpip.TCPProtocolNumber, h)
	s.Start()
	return ch, s, h
}

func TestThreeWayHandshake(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(12345)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	// Step 1: Send SYN.
	syn := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagSYN, clientISN, 0)
	ch.Inject(syn)

	// Step 2: Read SYN+ACK.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK, got nil")
	}

	ip, tcpHdr := parseTCPResponse(t, raw)

	// Verify addresses are swapped.
	if ip.SourceAddress() != serverAddr {
		t.Errorf("SYN+ACK src = %s, want %s", ip.SourceAddress(), serverAddr)
	}
	if ip.DestinationAddress() != clientAddr {
		t.Errorf("SYN+ACK dst = %s, want %s", ip.DestinationAddress(), clientAddr)
	}

	// Verify ports are swapped.
	if tcpHdr.SourcePort() != serverPort {
		t.Errorf("SYN+ACK src port = %d, want %d", tcpHdr.SourcePort(), serverPort)
	}
	if tcpHdr.DestinationPort() != clientPort {
		t.Errorf("SYN+ACK dst port = %d, want %d", tcpHdr.DestinationPort(), clientPort)
	}

	// Verify flags.
	flags := tcpHdr.Flags()
	if !flags.Has(header.TCPFlagSYN | header.TCPFlagACK) {
		t.Errorf("SYN+ACK flags = %s, want SYN|ACK", flags)
	}

	// Verify AckNum == client ISN + 1.
	if tcpHdr.AckNumber() != clientISN+1 {
		t.Errorf("SYN+ACK AckNum = %d, want %d", tcpHdr.AckNumber(), clientISN+1)
	}

	serverISN := tcpHdr.SequenceNumber()

	// Step 3: Send ACK to complete handshake.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagACK, clientISN+1, serverISN+1)
	ch.Inject(ack)

	// Step 4: Accept should return the connection.
	done := make(chan struct{})
	var conn *tcp.TCPConn
	var acceptAddr tcpip.FullAddress
	var acceptErr error

	go func() {
		conn, acceptAddr, acceptErr = h.Listener().Accept()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Accept() timed out")
	}

	if acceptErr != nil {
		t.Fatalf("Accept() error: %v", acceptErr)
	}
	if conn == nil {
		t.Fatal("Accept() returned nil connection")
	}

	// Verify OriginalDst.
	origDst := conn.OriginalDst()
	if origDst.Addr != serverAddr {
		t.Errorf("OriginalDst addr = %s, want %s", origDst.Addr, serverAddr)
	}
	if origDst.Port != serverPort {
		t.Errorf("OriginalDst port = %d, want %d", origDst.Port, serverPort)
	}

	// Verify Accept returned client address.
	if acceptAddr.Addr != clientAddr {
		t.Errorf("Accept addr = %s, want %s", acceptAddr.Addr, clientAddr)
	}
	if acceptAddr.Port != clientPort {
		t.Errorf("Accept port = %d, want %d", acceptAddr.Port, clientPort)
	}
}

func TestRSTForUnknownFlow(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientISN := uint32(5000)

	// Send a SYN+ACK (not a SYN — simulates a segment to unknown flow with ACK).
	// Actually, let's send a plain ACK to a non-existent connection.
	pkt := buildTCPPacket(clientAddr, serverAddr, 9999, 8080, header.TCPFlagACK, clientISN, 1)
	ch.Inject(pkt)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected RST, got nil")
	}

	ip, tcpHdr := parseTCPResponse(t, raw)

	// Verify addresses.
	if ip.SourceAddress() != serverAddr {
		t.Errorf("RST src = %s, want %s", ip.SourceAddress(), serverAddr)
	}
	if ip.DestinationAddress() != clientAddr {
		t.Errorf("RST dst = %s, want %s", ip.DestinationAddress(), clientAddr)
	}

	// Verify RST flag.
	if !tcpHdr.Flags().Has(header.TCPFlagRST) {
		t.Errorf("expected RST flag, got %s", tcpHdr.Flags())
	}

	// When inbound has ACK, RST SeqNum should equal inbound AckNum.
	if tcpHdr.SequenceNumber() != 1 {
		t.Errorf("RST SeqNum = %d, want 1 (from inbound AckNum)", tcpHdr.SequenceNumber())
	}

	// Also test RST for a SYN to unknown flow: this triggers handleSYN, so
	// a SYN+ACK comes back. But a non-SYN non-existing flow gets RST.
	// Let's test with a data segment (no SYN, no ACK).
	pkt2 := buildTCPPacket(clientAddr, serverAddr, 7777, 8080, 0, 100, 0)
	ch.Inject(pkt2)

	raw2 := ch.Read(time.Second)
	if raw2 == nil {
		t.Fatal("expected RST for non-SYN segment, got nil")
	}

	_, tcpHdr2 := parseTCPResponse(t, raw2)
	if !tcpHdr2.Flags().Has(header.TCPFlagRST | header.TCPFlagACK) {
		t.Errorf("expected RST|ACK flags, got %s", tcpHdr2.Flags())
	}

	// When inbound has no ACK, AckNum = SeqNum + segLen. Segment has no payload and no SYN, so segLen=0.
	if tcpHdr2.AckNumber() != 100 {
		t.Errorf("RST AckNum = %d, want 100", tcpHdr2.AckNumber())
	}
}

func TestMultipleConcurrentHandshakes(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	type connInfo struct {
		clientPort uint16
		serverPort uint16
		clientISN  uint32
	}

	flows := []connInfo{
		{10001, 80, 1000},
		{10002, 443, 2000},
		{10003, 8080, 3000},
	}

	// Start Accept() in background.
	var mu sync.Mutex
	accepted := make([]*tcp.TCPConn, 0, 3)
	acceptAddrs := make([]tcpip.FullAddress, 0, 3)
	var wg sync.WaitGroup
	wg.Add(len(flows))

	go func() {
		for range flows {
			conn, addr, err := h.Listener().Accept()
			if err != nil {
				t.Errorf("Accept() error: %v", err)
				wg.Done()
				continue
			}
			mu.Lock()
			accepted = append(accepted, conn)
			acceptAddrs = append(acceptAddrs, addr)
			mu.Unlock()
			wg.Done()
		}
	}()

	// Perform handshakes for all flows.
	serverISNs := make(map[uint16]uint32) // keyed by client port

	for _, f := range flows {
		syn := buildTCPPacket(clientAddr, serverAddr, f.clientPort, f.serverPort, header.TCPFlagSYN, f.clientISN, 0)
		ch.Inject(syn)

		raw := ch.Read(time.Second)
		if raw == nil {
			t.Fatalf("expected SYN+ACK for port %d, got nil", f.clientPort)
		}

		_, tcpHdr := parseTCPResponse(t, raw)
		serverISNs[f.clientPort] = tcpHdr.SequenceNumber()
	}

	// Send ACKs to complete all handshakes.
	for _, f := range flows {
		serverISN := serverISNs[f.clientPort]
		ack := buildTCPPacket(clientAddr, serverAddr, f.clientPort, f.serverPort, header.TCPFlagACK, f.clientISN+1, serverISN+1)
		ch.Inject(ack)
	}

	// Wait for all Accept() calls.
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for all Accept() calls")
	}

	mu.Lock()
	defer mu.Unlock()

	if len(accepted) != 3 {
		t.Fatalf("expected 3 connections, got %d", len(accepted))
	}

	// Verify each connection has a unique OriginalDst.
	dstPorts := make(map[uint16]bool)
	for _, conn := range accepted {
		dst := conn.OriginalDst()
		if dstPorts[dst.Port] {
			t.Errorf("duplicate OriginalDst port: %d", dst.Port)
		}
		dstPorts[dst.Port] = true
	}

	// Verify all expected ports are present.
	for _, f := range flows {
		if !dstPorts[f.serverPort] {
			t.Errorf("missing connection for server port %d", f.serverPort)
		}
	}
}

func TestNoGoroutineLeaksOnClose(t *testing.T) {
	// Stabilize goroutine count.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	ch := channel.NewMemory(1500)
	s := stack.New(ch)
	h := tcp.NewTCPHandler(s)
	s.RegisterHandler(tcpip.TCPProtocolNumber, h)
	s.Start()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	// Complete a handshake.
	syn := buildTCPPacket(clientAddr, serverAddr, 55555, 80, header.TCPFlagSYN, 1, 0)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK")
	}

	ip := header.IPv4(raw)
	tcpHdr := header.TCP(raw[ip.HeaderLength():])
	serverISN := tcpHdr.SequenceNumber()

	ack := buildTCPPacket(clientAddr, serverAddr, 55555, 80, header.TCPFlagACK, 2, serverISN+1)
	ch.Inject(ack)

	// Accept the connection.
	done := make(chan struct{})
	go func() {
		h.Listener().Accept()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Accept() timed out")
	}

	// Shut down.
	h.Close()
	s.Stop()

	// Wait for goroutines to exit.
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()

	if after > before+1 {
		t.Errorf("goroutine leak: before=%d, after=%d", before, after)
	}
}

// Ensure binary import is used (needed for buildTCPPacket checksum).
var _ = binary.BigEndian
