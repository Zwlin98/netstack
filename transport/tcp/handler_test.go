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

// TestDuplicateSYNRetransmitsSYNACK is superseded by TestSYNRetransmit
// (ported from gVisor) which tests 5 rapid retransmissions.

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

func TestRSTAbortsSynRcvd(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientISN := uint32(1000)

	// SYN → SYN+ACK.
	syn := buildTCPPacket(clientAddr, serverAddr, 12345, 80, header.TCPFlagSYN, clientISN, 0)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK")
	}
	_, sa := parseTCPResponse(t, raw)
	serverISN := sa.SequenceNumber()

	// Send RST instead of ACK — abort the handshake.
	rst := buildTCPPacket(clientAddr, serverAddr, 12345, 80, header.TCPFlagRST, clientISN+1, serverISN+1)
	ch.Inject(rst)

	// Allow conn goroutine to process.
	time.Sleep(50 * time.Millisecond)

	// Accept() should NOT return this connection. Close listener to unblock.
	acceptDone := make(chan error, 1)
	go func() {
		_, _, err := h.Listener().Accept()
		acceptDone <- err
	}()

	// Give Accept a brief window — it should NOT fire.
	select {
	case <-acceptDone:
		t.Fatal("Accept() should not return a connection aborted by RST")
	case <-time.After(200 * time.Millisecond):
		// Expected — no connection was delivered.
	}

	// No extra packets should be emitted.
	extra := ch.Read(100 * time.Millisecond)
	if extra != nil {
		t.Error("unexpected packet after RST during handshake")
	}
}

// TestInvalidACKInSynRcvd is superseded by TestAcceptableAckInSynRcvd
// (ported from gVisor) which tests offset=0/1/2 in a table-driven style.

func TestSYNInEstablishedSendsChallengeACK(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientISN := uint32(1000)

	// Complete handshake.
	syn := buildTCPPacket(clientAddr, serverAddr, 12345, 80, header.TCPFlagSYN, clientISN, 0)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK")
	}
	_, sa := parseTCPResponse(t, raw)
	serverISN := sa.SequenceNumber()

	ack := buildTCPPacket(clientAddr, serverAddr, 12345, 80, header.TCPFlagACK, clientISN+1, serverISN+1)
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

	// Send a SYN to the ESTABLISHED connection — should get challenge ACK.
	dupSyn := buildTCPPacket(clientAddr, serverAddr, 12345, 80, header.TCPFlagSYN, 9999, 0)
	ch.Inject(dupSyn)

	ackRaw := ch.Read(time.Second)
	if ackRaw == nil {
		t.Fatal("expected challenge ACK")
	}

	_, ackHdr := parseTCPResponse(t, ackRaw)

	// Should be a pure ACK (not SYN+ACK, not RST).
	if ackHdr.Flags() != header.TCPFlagACK {
		t.Errorf("challenge ACK flags = %s, want ACK only", ackHdr.Flags())
	}

	// SeqNum and AckNum should reflect current connection state.
	if ackHdr.SequenceNumber() != serverISN+1 {
		t.Errorf("challenge ACK SeqNum = %d, want %d", ackHdr.SequenceNumber(), serverISN+1)
	}
	if ackHdr.AckNumber() != clientISN+1 {
		t.Errorf("challenge ACK AckNum = %d, want %d", ackHdr.AckNumber(), clientISN+1)
	}
}

func TestRSTToUnknownFlowSilentlyDropped(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	// Send RST to a non-existent flow — should be silently dropped (RFC 793).
	rst := buildTCPPacket(clientAddr, serverAddr, 9999, 8080, header.TCPFlagRST, 1, 0)
	ch.Inject(rst)

	// No response expected.
	raw := ch.Read(200 * time.Millisecond)
	if raw != nil {
		_, tcpHdr := parseTCPResponse(t, raw)
		t.Errorf("expected no response to RST, got packet with flags %s", tcpHdr.Flags())
	}
}

func TestConnCloseIdempotent(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientISN := uint32(1000)

	// Complete handshake.
	syn := buildTCPPacket(clientAddr, serverAddr, 12345, 80, header.TCPFlagSYN, clientISN, 0)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK")
	}
	_, sa := parseTCPResponse(t, raw)
	serverISN := sa.SequenceNumber()

	ack := buildTCPPacket(clientAddr, serverAddr, 12345, 80, header.TCPFlagACK, clientISN+1, serverISN+1)
	ch.Inject(ack)

	done := make(chan *tcp.TCPConn, 1)
	go func() {
		conn, _, _ := h.Listener().Accept()
		done <- conn
	}()

	var conn *tcp.TCPConn
	select {
	case conn = <-done:
	case <-time.After(time.Second):
		t.Fatal("Accept() timed out")
	}

	// Close multiple times — should not panic.
	conn.Close()
	conn.Close()
	conn.Close()
}

// completeHandshake performs a full 3-way handshake and returns the server ISN
// and the accepted TCPConn.
func completeHandshake(t *testing.T, ch *channel.MemoryChannel, h *tcp.TCPHandler,
	clientAddr, serverAddr tcpip.Address, clientPort, serverPort uint16, clientISN uint32,
) (serverISN uint32, conn *tcp.TCPConn) {
	t.Helper()

	syn := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagSYN, clientISN, 0)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK, got nil")
	}
	_, sa := parseTCPResponse(t, raw)
	serverISN = sa.SequenceNumber()

	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagACK, clientISN+1, serverISN+1)
	ch.Inject(ack)

	done := make(chan struct{})
	var acceptErr error
	go func() {
		conn, _, acceptErr = h.Listener().Accept()
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
	return serverISN, conn
}

// Ported from gvisor: test/packetimpact/tests/tcp_acceptable_ack_syn_rcvd_test.go:TestAcceptableAckInSynRcvd
//
// Tests that SYN-RCVD state correctly validates the ACK number.
// Only ACK = ISS+1 (offset=1) should be accepted; other offsets should
// produce a RST with SeqNum equal to the bad AckNum.
func TestAcceptableAckInSynRcvd(t *testing.T) {
	for _, tt := range []struct {
		name      string
		offset    uint32
		expectRST bool
	}{
		{"offset=0 (acks ISS, not ISS+1)", 0, true},
		{"offset=1 (correct)", 1, false},
		{"offset=2 (too high)", 2, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ch, s, h := setupStack(t)
			defer s.Stop()
			defer h.Close()

			clientAddr := tcpip.From4(10, 0, 0, 1)
			serverAddr := tcpip.From4(10, 0, 0, 2)
			clientPort := uint16(12345)
			serverPort := uint16(80)
			clientISN := uint32(1000)

			// SYN → SYN+ACK.
			syn := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagSYN, clientISN, 0)
			ch.Inject(syn)

			raw := ch.Read(time.Second)
			if raw == nil {
				t.Fatal("expected SYN+ACK, got nil")
			}
			_, sa := parseTCPResponse(t, raw)
			serverISN := sa.SequenceNumber()

			// Send ACK with ackNum = serverISN + offset.
			ackNum := serverISN + tt.offset
			ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagACK, clientISN+1, ackNum)
			ch.Inject(ack)

			if tt.expectRST {
				rstRaw := ch.Read(time.Second)
				if rstRaw == nil {
					t.Fatal("expected RST, got nil")
				}
				_, rstHdr := parseTCPResponse(t, rstRaw)
				if !rstHdr.Flags().Has(header.TCPFlagRST) {
					t.Errorf("expected RST flag, got %s", rstHdr.Flags())
				}
				if rstHdr.SequenceNumber() != ackNum {
					t.Errorf("RST SeqNum = %d, want %d", rstHdr.SequenceNumber(), ackNum)
				}
			} else {
				// Should be accepted — Accept() returns connection.
				done := make(chan struct{})
				go func() {
					conn, _, err := h.Listener().Accept()
					if err != nil {
						t.Errorf("Accept() error: %v", err)
					}
					if conn == nil {
						t.Error("Accept() returned nil")
					}
					close(done)
				}()

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("Accept() timed out")
				}
			}
		})
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestSendRstOnListenerRxSynAckV4 (line 1197)
//
// A listener receiving a SYN+ACK (not a pure SYN) for an unknown flow
// should respond with RST, not create a new connection.
func TestSendRstOnListenerRxSynAck(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	// Send SYN+ACK to listener — this is not a valid connection initiation.
	pkt := buildTCPPacket(clientAddr, serverAddr, 4096, 1234,
		header.TCPFlagSYN|header.TCPFlagACK, 100, 200)
	ch.Inject(pkt)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected RST, got nil")
	}

	_, tcpHdr := parseTCPResponse(t, raw)

	if !tcpHdr.Flags().Has(header.TCPFlagRST) {
		t.Errorf("expected RST flag, got %s", tcpHdr.Flags())
	}

	// RST SeqNum should equal the incoming AckNum (RFC 793).
	if tcpHdr.SequenceNumber() != 200 {
		t.Errorf("RST SeqNum = %d, want 200 (from inbound AckNum)", tcpHdr.SequenceNumber())
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestSendRstOnListenerRxAckV4 (line 1477)
//
// A listener receiving a FIN+ACK for an unknown flow should respond with RST.
func TestSendRstOnListenerRxFinAck(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	pkt := buildTCPPacket(clientAddr, serverAddr, 4096, 1234,
		header.TCPFlagFIN|header.TCPFlagACK, 100, 200)
	ch.Inject(pkt)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected RST, got nil")
	}

	_, tcpHdr := parseTCPResponse(t, raw)

	if !tcpHdr.Flags().Has(header.TCPFlagRST) {
		t.Errorf("expected RST flag, got %s", tcpHdr.Flags())
	}
	if tcpHdr.SequenceNumber() != 200 {
		t.Errorf("RST SeqNum = %d, want 200 (from inbound AckNum)", tcpHdr.SequenceNumber())
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestSYNRetransmit (line 6718)
//
// Sending the same SYN multiple times should produce valid SYN-ACK replies
// with the same server ISS, without corrupting connection state.
func TestSYNRetransmit(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	syn := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagSYN, clientISN, 0)

	// Send same SYN 5 times.
	for i := 0; i < 5; i++ {
		ch.Inject(syn)
	}

	// Collect all SYN-ACK replies.
	var serverISN uint32
	for i := 0; i < 5; i++ {
		raw := ch.Read(time.Second)
		if raw == nil {
			t.Fatalf("expected SYN+ACK #%d, got nil", i+1)
		}
		_, sa := parseTCPResponse(t, raw)

		if !sa.Flags().Has(header.TCPFlagSYN | header.TCPFlagACK) {
			t.Errorf("reply #%d flags = %s, want SYN|ACK", i+1, sa.Flags())
		}
		if sa.AckNumber() != clientISN+1 {
			t.Errorf("reply #%d AckNum = %d, want %d", i+1, sa.AckNumber(), clientISN+1)
		}
		if i == 0 {
			serverISN = sa.SequenceNumber()
		} else if sa.SequenceNumber() != serverISN {
			t.Errorf("reply #%d SeqNum = %d, want %d (same ISS)", i+1, sa.SequenceNumber(), serverISN)
		}
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestSynRcvdBadSeqNumber (line 6764)
//
// In SYN_RCVD, an ACK with correct AckNum but out-of-window sequence number
// should be answered with an ACK (not transition to ESTABLISHED).
// A subsequent ACK with correct sequence should still complete the handshake.
func TestSynRcvdBadSeqNumber(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	// SYN → SYN+ACK.
	syn := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagSYN, clientISN, 0)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK, got nil")
	}
	_, sa := parseTCPResponse(t, raw)
	serverISN := sa.SequenceNumber()

	// Send ACK with out-of-window sequence number but correct AckNum.
	largeSeqNum := clientISN + uint32(sa.WindowSize()) + 1
	badSeq := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, largeSeqNum, serverISN+1)
	ch.Inject(badSeq)

	// Should receive an ACK (not RST) with correct SeqNum and AckNum.
	ackRaw := ch.Read(time.Second)
	if ackRaw == nil {
		t.Fatal("expected ACK for out-of-window seq, got nil")
	}
	_, ackHdr := parseTCPResponse(t, ackRaw)
	if ackHdr.Flags() != header.TCPFlagACK {
		t.Errorf("expected pure ACK, got %s", ackHdr.Flags())
	}
	if ackHdr.AckNumber() != clientISN+1 {
		t.Errorf("ACK AckNum = %d, want %d", ackHdr.AckNumber(), clientISN+1)
	}
	if ackHdr.SequenceNumber() != serverISN+1 {
		t.Errorf("ACK SeqNum = %d, want %d", ackHdr.SequenceNumber(), serverISN+1)
	}

	// Now send correct ACK — handshake should still complete.
	goodACK := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1)
	ch.Inject(goodACK)

	done := make(chan struct{})
	go func() {
		conn, _, err := h.Listener().Accept()
		if err != nil {
			t.Errorf("Accept() error: %v", err)
		}
		if conn == nil {
			t.Error("Accept() returned nil")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Accept() timed out — bad seq may have incorrectly transitioned state")
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestTCPResetsDoNotGenerateResets (line 587)
//
// An RST received on an ESTABLISHED connection must not generate another RST
// (RFC 793 Section 3.4).
func TestResetsDoNotGenerateResets(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, _ := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send RST to ESTABLISHED connection.
	rst := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagRST, clientISN+1, serverISN+1)
	ch.Inject(rst)

	// No response should be generated.
	extra := ch.Read(200 * time.Millisecond)
	if extra != nil {
		_, tcpHdr := parseTCPResponse(t, extra)
		t.Errorf("expected no response to RST, got packet with flags %s", tcpHdr.Flags())
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestListenCloseWhileConnect (line 1667)
//
// Closing the handler after a connection is established should send RST
// to the remote peer.
func TestListenCloseWhileConnect(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Close the handler — should trigger RST to remote.
	h.Close()

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected RST after handler close, got nil")
	}

	_, tcpHdr := parseTCPResponse(t, raw)
	if !tcpHdr.Flags().Has(header.TCPFlagRST) {
		t.Errorf("expected RST flag, got %s", tcpHdr.Flags())
	}
}

// Ensure binary import is used (needed for buildTCPPacket checksum).
var _ = binary.BigEndian
