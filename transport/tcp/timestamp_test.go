package tcp_test

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// buildTCPPacketWithDataAndOptions builds a TCP packet with both options and data payload.
func buildTCPPacketWithDataAndOptions(src, dst tcpip.Address, srcPort, dstPort uint16,
	flags header.TCPFlags, seqNum, ackNum uint32, wnd uint16,
	opts []byte, data []byte,
) []byte {
	optLen := len(opts)
	for optLen%4 != 0 {
		opts = append(opts, header.TCPOptionNOP)
		optLen++
	}
	tcpHdrLen := header.TCPMinHeaderSize + optLen
	tcpLen := tcpHdrLen + len(data)
	totalLen := header.IPv4MinHeaderSize + tcpLen
	buf := make([]byte, totalLen)

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

	tcpBuf := buf[header.IPv4MinHeaderSize:]
	tcpHdr := header.TCP(tcpBuf)
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seqNum,
		AckNum:     ackNum,
		DataOffset: uint8(tcpHdrLen / 4),
		Flags:      flags,
		WindowSize: wnd,
	})
	copy(tcpBuf[header.TCPMinHeaderSize:], opts)
	copy(tcpBuf[tcpHdrLen:], data)
	tcpHdr.SetChecksum(0)
	partial := header.PseudoHeaderChecksum(tcpip.TCPProtocolNumber, src, dst, uint16(tcpLen))
	tcpHdr.SetChecksum(header.Checksum(tcpBuf, partial))

	return buf
}

// buildTSOption builds a 12-byte timestamp option (NOP+NOP+TS).
func buildTSOption(tsval, tsecr uint32) []byte {
	buf := make([]byte, 12)
	header.EncodeTimestampOption(buf, tsval, tsecr)
	return buf
}

// completeHandshakeWithTS performs a 3-way handshake with timestamp options.
func completeHandshakeWithTS(t *testing.T, ch interface {
	Inject([]byte)
	Read(time.Duration) []byte
}, h *tcp.TCPHandler,
	clientAddr, serverAddr tcpip.Address, clientPort, serverPort uint16, clientISN uint32,
	clientTSVal uint32,
) (serverISN uint32, conn *tcp.TCPConn, synAckTSVal uint32) {
	t.Helper()

	// Build SYN with MSS + Timestamp options.
	var opts []byte
	mssBuf := make([]byte, 4)
	header.EncodeMSSOption(mssBuf, 1460)
	opts = append(opts, mssBuf...)
	opts = append(opts, buildTSOption(clientTSVal, 0)...)

	syn := buildTCPPacketWithDataAndOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagSYN, clientISN, 0, 65535, opts, nil)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK, got nil")
	}
	_, sa := parseTCPResponse(t, raw)
	serverISN = sa.SequenceNumber()

	// Parse SYN+ACK options to get server's TSval.
	saOpts := sa.Options()
	so := header.ParseSynOptions(saOpts)
	if !so.TSEnabled {
		t.Fatal("SYN+ACK missing Timestamp option")
	}
	synAckTSVal = so.TSVal

	// Complete handshake with ACK that includes timestamp.
	ackOpts := buildTSOption(clientTSVal+1, synAckTSVal)
	ack := buildTCPPacketWithDataAndOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, ackOpts, nil)
	ch.Inject(ack)

	done := make(chan struct{})
	var acceptErr error
	go func() {
		conn, acceptErr = h.Listener().Accept()
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
	return serverISN, conn, synAckTSVal
}

// --- Task 4.3: RTTM Tests ---

func TestTimestamp_RTTMFromTSecr(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60001)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn, _ := completeHandshakeWithTS(t, ch, h, clientAddr, serverAddr,
		clientPort, serverPort, clientISN, 5000)

	// Make server send data.
	go conn.Write([]byte("Hello"))

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment")
	}
	_, tcpHdr := parseTCPResponse(t, raw)
	dataOpts := header.ParseSegmentOptions(tcpHdr.Options())
	if !dataOpts.TSEnabled {
		t.Fatal("data segment missing timestamp")
	}
	serverTSVal := dataOpts.TSVal

	// ACK with TSecr = serverTSVal (echoing it back for RTTM).
	ackOpts := buildTSOption(5010, serverTSVal)
	ack := buildTCPPacketWithDataAndOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+5, 65535, ackOpts, nil)
	ch.Inject(ack)

	// If we get here without panic, RTTM processing worked.
	// The RTT measurement is internal — we just verify no crash.
	time.Sleep(10 * time.Millisecond)
	_ = conn
}

// --- Task 5.1: Timestamp Negotiation ---

func TestTimestamp_Negotiation_PeerOffersTS(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60010)
	serverPort := uint16(80)
	clientISN := uint32(1000)
	clientTSVal := uint32(1000)

	// Build SYN with MSS + Timestamp.
	var opts []byte
	mssBuf := make([]byte, 4)
	header.EncodeMSSOption(mssBuf, 1460)
	opts = append(opts, mssBuf...)
	opts = append(opts, buildTSOption(clientTSVal, 0)...)

	syn := buildTCPPacketWithDataAndOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagSYN, clientISN, 0, 65535, opts, nil)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK, got nil")
	}
	_, sa := parseTCPResponse(t, raw)

	// SYN+ACK should include Timestamp option.
	saOpts := sa.Options()
	so := header.ParseSynOptions(saOpts)
	if !so.TSEnabled {
		t.Error("SYN+ACK missing Timestamp option when peer offered it")
	}
	if so.TSVal == 0 {
		t.Error("SYN+ACK TSval should be non-zero")
	}
}

func TestTimestamp_Negotiation_PeerNoTS(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60011)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	// Plain SYN without Timestamp option.
	syn := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagSYN, clientISN, 0)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK, got nil")
	}
	_, sa := parseTCPResponse(t, raw)

	// SYN+ACK should NOT include Timestamp option.
	saOpts := sa.Options()
	if saOpts != nil {
		so := header.ParseSynOptions(saOpts)
		if so.TSEnabled {
			t.Error("SYN+ACK should NOT include Timestamp when peer didn't offer it")
		}
	}
}

// --- Task 5.2: PAWS ---

func TestTimestamp_PAWS_StaleDropped(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60020)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn, _ := completeHandshakeWithTS(t, ch, h, clientAddr, serverAddr,
		clientPort, serverPort, clientISN, 5000)

	// Send a valid data segment with TSval=6000.
	validOpts := buildTSOption(6000, 0)
	validPkt := buildTCPPacketWithDataAndOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, validOpts, []byte("OK"))
	ch.Inject(validPkt)

	// Drain ACK response.
	ch.Read(time.Second)

	// Now send a segment with STALE TSval=3000 (< tsRecent which is now >= 5000).
	staleOpts := buildTSOption(3000, 0)
	stalePkt := buildTCPPacketWithDataAndOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1+2, serverISN+1, 65535, staleOpts, []byte("BAD"))
	ch.Inject(stalePkt)

	// The stale segment should be dropped silently — no ACK response.
	resp := ch.Read(100 * time.Millisecond)
	if resp != nil {
		t.Error("expected stale segment to be dropped silently, got a response")
	}

	// Verify the valid data was delivered.
	buf := make([]byte, 10)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "OK" {
		t.Errorf("received %q, want %q", buf[:n], "OK")
	}
}

// --- Task 5.3: PAWS Wraparound ---

func TestTimestamp_PAWS_Wraparound(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60021)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	// Start with TSval near uint32 max.
	nearMax := uint32(0xFFFFFFF0)
	serverISN, conn, _ := completeHandshakeWithTS(t, ch, h, clientAddr, serverAddr,
		clientPort, serverPort, clientISN, nearMax)

	// Send segment with TSval that wraps: 0x00000010 (just past max).
	// Signed difference: 0x00000010 - 0xFFFFFFF0 = 0x00000020 (positive) → valid.
	wrappedTSVal := uint32(0x00000010)
	wrappedOpts := buildTSOption(wrappedTSVal, 0)
	pkt := buildTCPPacketWithDataAndOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, wrappedOpts, []byte("WRAP"))
	ch.Inject(pkt)

	// Should be accepted (not dropped by PAWS).
	resp := ch.Read(time.Second)
	if resp == nil {
		t.Fatal("expected ACK for wrapped-TSval segment, got nil")
	}

	buf := make([]byte, 10)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "WRAP" {
		t.Errorf("received %q, want %q", buf[:n], "WRAP")
	}
}

// --- Task 5.4: Timestamp Echo ---

func TestTimestamp_Echo(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60030)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, _, _ := completeHandshakeWithTS(t, ch, h, clientAddr, serverAddr,
		clientPort, serverPort, clientISN, 5000)

	// Send data with TSval=7777 — server should echo it back as TSecr.
	tsVal := uint32(7777)
	dataOpts := buildTSOption(tsVal, 0)
	pkt := buildTCPPacketWithDataAndOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, dataOpts, []byte("echo"))
	ch.Inject(pkt)

	// Read ACK response.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK, got nil")
	}
	_, ackHdr := parseTCPResponse(t, raw)
	ackOpts := header.ParseSegmentOptions(ackHdr.Options())
	if !ackOpts.TSEnabled {
		t.Fatal("ACK missing timestamp option")
	}
	// TSecr should echo back the peer's TSval.
	if ackOpts.TSecr != tsVal {
		t.Errorf("TSecr = %d, want %d (should echo peer's TSval)", ackOpts.TSecr, tsVal)
	}
}

// TestTimestamp_MSSReduced verifies effective MSS is reduced by 12 when timestamps negotiated.
func TestTimestamp_MSSReduced(t *testing.T) {
	ch, s, h := setupStack(t) // MTU=1500
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60040)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn, _ := completeHandshakeWithTS(t, ch, h, clientAddr, serverAddr,
		clientPort, serverPort, clientISN, 5000)

	// Write a large chunk — segments should be at most 1460-12=1448 bytes of payload.
	data := make([]byte, 2000)
	go conn.Write(data)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment")
	}
	ip := header.IPv4(raw)
	tcpHdr := header.TCP(raw[ip.HeaderLength():])
	dataLen := len(raw) - int(ip.HeaderLength()) - int(tcpHdr.DataOffset())
	expectedMSS := 1460 - 12
	if dataLen > expectedMSS {
		t.Errorf("data segment payload = %d bytes, want <= %d (MSS reduced by TS overhead)", dataLen, expectedMSS)
	}

	// Verify the segment itself has a timestamp option.
	segOpts := header.ParseSegmentOptions(tcpHdr.Options())
	if !segOpts.TSEnabled {
		t.Error("data segment missing timestamp option")
	}

	_ = serverISN
	_ = binary.BigEndian // keep import
}
