package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// TestDSACK_InOrderDuplicate verifies that a fully duplicate in-order segment
// generates a DSACK block in the next ACK.
func TestDSACK_InOrderDuplicate(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(40001)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, _ := completeHandshakeWithSACK(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send in-order data first.
	data := []byte("hello")
	pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, data)
	ch.Inject(pkt)

	// Wait for delayed ACK.
	drainACKs(ch, 300*time.Millisecond)

	// Now send the exact same segment again — fully duplicate.
	ch.Inject(buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, data))

	// The duplicate should trigger an immediate ACK with DSACK.
	// Since it's a "data" segment, delayed ACK logic runs, but we need to trigger it.
	// Send a second segment to trigger the every-2-segment rule.
	ch.Inject(buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, data))

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK with DSACK, got nil")
	}
	_, ackHdr := parseTCPResponse(t, raw)

	// ACK number should be clientISN+1+5 (original 5 bytes delivered).
	expectedACK := clientISN + 1 + uint32(len(data))
	if ackHdr.AckNumber() != expectedACK {
		t.Errorf("ACK number = %d, want %d", ackHdr.AckNumber(), expectedACK)
	}

	// Parse SACK blocks — should have DSACK block as first.
	opts := ackHdr.Options()
	if opts == nil {
		t.Fatal("ACK has no options")
	}
	so := header.ParseSegmentOptions(opts)
	if len(so.SACKBlocks) == 0 {
		t.Fatal("ACK has no SACK blocks, expected DSACK")
	}

	dsack := so.SACKBlocks[0]
	// DSACK should cover the duplicate range: [clientISN+1, clientISN+1+5).
	if dsack.Start != clientISN+1 {
		t.Errorf("DSACK start = %d, want %d", dsack.Start, clientISN+1)
	}
	if dsack.End != clientISN+1+uint32(len(data)) {
		t.Errorf("DSACK end = %d, want %d", dsack.End, clientISN+1+uint32(len(data)))
	}
}

// TestDSACK_OOODuplicate verifies that a duplicate of a buffered OOO segment
// generates a DSACK block.
func TestDSACK_OOODuplicate(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(40002)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	serverISN, _ := completeHandshakeWithSACK(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send OOO segment at clientISN+1+100.
	oooData := []byte("world")
	oooSeq := clientISN + 1 + 100
	pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, oooSeq, serverISN+1, 65535, oooData)
	ch.Inject(pkt)

	// Read the ACK with SACK block for the OOO data.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK with SACK block")
	}

	// Now send the same OOO segment again — should generate DSACK.
	ch.Inject(buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, oooSeq, serverISN+1, 65535, oooData))

	raw = ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK with DSACK, got nil")
	}
	_, ackHdr := parseTCPResponse(t, raw)

	opts := ackHdr.Options()
	if opts == nil {
		t.Fatal("ACK has no options")
	}
	so := header.ParseSegmentOptions(opts)
	if len(so.SACKBlocks) == 0 {
		t.Fatal("ACK has no SACK blocks")
	}

	// First block should be the DSACK.
	dsack := so.SACKBlocks[0]
	if dsack.Start != oooSeq {
		t.Errorf("DSACK start = %d, want %d", dsack.Start, oooSeq)
	}
	if dsack.End != oooSeq+uint32(len(oooData)) {
		t.Errorf("DSACK end = %d, want %d", dsack.End, oooSeq+uint32(len(oooData)))
	}

	// Should also have the regular SACK block for the OOO segment.
	if len(so.SACKBlocks) < 2 {
		t.Fatal("expected DSACK + regular SACK block")
	}
	regular := so.SACKBlocks[1]
	if regular.Start != oooSeq {
		t.Errorf("regular SACK start = %d, want %d", regular.Start, oooSeq)
	}
}

// TestDSACK_ClearedAfterSending verifies that the DSACK block is a one-shot
// notification — it is not repeated in subsequent ACKs.
func TestDSACK_ClearedAfterSending(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(40003)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	serverISN, _ := completeHandshakeWithSACK(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send in-order data.
	data := []byte("abc")
	pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, data)
	ch.Inject(pkt)
	drainACKs(ch, 300*time.Millisecond)

	// Send duplicate to trigger DSACK.
	dup := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, data)
	ch.Inject(dup)
	ch.Inject(dup) // second to trigger immediate ACK
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK with DSACK")
	}

	// Now drain any remaining ACKs.
	drainACKs(ch, 300*time.Millisecond)

	// Send new in-order data to trigger another ACK.
	newData := []byte("def")
	nextSeq := clientISN + 1 + uint32(len(data))
	pkt1 := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, nextSeq, serverISN+1, 65535, newData)
	pkt2 := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, nextSeq+uint32(len(newData)), serverISN+1, 65535, []byte("g"))
	ch.Inject(pkt1)
	ch.Inject(pkt2)

	raw = ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK for new data")
	}
	_, ackHdr := parseTCPResponse(t, raw)

	// This ACK should NOT contain DSACK blocks (no OOO data either).
	opts := ackHdr.Options()
	if opts != nil {
		so := header.ParseSegmentOptions(opts)
		for _, b := range so.SACKBlocks {
			// Any block below the ACK number would be a stale DSACK.
			if !seqGreaterThan(b.End, ackHdr.AckNumber()) {
				t.Errorf("stale DSACK block found: [%d, %d)", b.Start, b.End)
			}
		}
	}
}

// TestDSACK_CoexistsWithRegularSACK verifies DSACK block + regular SACK blocks
// can coexist in the same ACK.
func TestDSACK_CoexistsWithRegularSACK(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(40004)
	serverPort := uint16(80)
	clientISN := uint32(4000)

	serverISN, _ := completeHandshakeWithSACK(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send in-order data.
	data := []byte("hello")
	pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, data)
	ch.Inject(pkt)
	drainACKs(ch, 300*time.Millisecond)

	// Send OOO data to create a gap.
	oooSeq := clientISN + 1 + uint32(len(data)) + 100
	oooData := []byte("world")
	oooPkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, oooSeq, serverISN+1, 65535, oooData)
	ch.Inject(oooPkt)

	// Read ACK for OOO (immediate ACK for OOO).
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK for OOO")
	}

	// Now send a duplicate of the in-order data — should generate DSACK + regular SACK.
	dupPkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, data)
	ch.Inject(dupPkt)
	ch.Inject(dupPkt) // trigger immediate ACK

	raw = ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK with DSACK + SACK")
	}
	_, ackHdr := parseTCPResponse(t, raw)

	opts := ackHdr.Options()
	if opts == nil {
		t.Fatal("ACK has no options")
	}
	so := header.ParseSegmentOptions(opts)
	if len(so.SACKBlocks) < 2 {
		t.Fatalf("expected at least 2 SACK blocks (DSACK + regular), got %d", len(so.SACKBlocks))
	}

	// First block should be DSACK (below cumulative ACK).
	dsack := so.SACKBlocks[0]
	ackNum := ackHdr.AckNumber()
	if seqGreaterThan(dsack.End, ackNum) {
		t.Errorf("first block [%d, %d) should be DSACK (below ACK %d)", dsack.Start, dsack.End, ackNum)
	}

	// Second block should be regular SACK for OOO data.
	regular := so.SACKBlocks[1]
	if regular.Start != oooSeq {
		t.Errorf("regular SACK start = %d, want %d", regular.Start, oooSeq)
	}
}

// TestDSACK_SenderDetection verifies that the sender correctly identifies
// DSACK blocks (block range < cumulative ACK) as spurious retransmission signals.
func TestDSACK_SenderDetection(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(40005)
	serverPort := uint16(80)
	clientISN := uint32(5000)

	_, conn := completeHandshakeWithSACK(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server sends data.
	writeData := make([]byte, 100)
	for i := range writeData {
		writeData[i] = byte(i)
	}
	go func() { conn.Write(writeData) }()

	// Read the data segment.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	dataSeq := dataHdr.SequenceNumber()

	// ACK all the data.
	ackNum := dataSeq + uint32(len(writeData))

	// Now send an ACK with DSACK: block below cumulative ACK.
	// This simulates the peer telling us they received a duplicate.
	dsackBlock := header.SACKBlock{Start: dataSeq, End: dataSeq + 50}
	var optBuf [34]byte
	optLen := header.EncodeSACKBlocks(optBuf[:], []header.SACKBlock{dsackBlock})
	for optLen%4 != 0 {
		optBuf[optLen] = header.TCPOptionNOP
		optLen++
	}

	ackPkt := buildTCPPacketWithOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, ackNum, optBuf[:optLen])
	ch.Inject(ackPkt)

	// Give the conn time to process.
	time.Sleep(50 * time.Millisecond)

	if !tcp.SenderDSACKSeen(conn) {
		t.Error("sender should have detected DSACK")
	}
}

// TestDSACK_SenderNormalSACKNotConfused verifies that a normal SACK block
// (above cumulative ACK) is NOT treated as DSACK.
func TestDSACK_SenderNormalSACKNotConfused(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(40006)
	serverPort := uint16(80)
	clientISN := uint32(6000)

	_, conn := completeHandshakeWithSACK(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server sends data.
	writeData := make([]byte, 200)
	go func() { conn.Write(writeData) }()

	// Read data segments.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	dataSeq := dataHdr.SequenceNumber()

	// Send ACK for first 50 bytes with a SACK block for bytes 100-150.
	// The SACK block is above the cumulative ACK — NOT a DSACK.
	partialAck := dataSeq + 50
	sackBlock := header.SACKBlock{Start: dataSeq + 100, End: dataSeq + 150}
	var optBuf [34]byte
	optLen := header.EncodeSACKBlocks(optBuf[:], []header.SACKBlock{sackBlock})
	for optLen%4 != 0 {
		optBuf[optLen] = header.TCPOptionNOP
		optLen++
	}

	ackPkt := buildTCPPacketWithOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, partialAck, optBuf[:optLen])
	ch.Inject(ackPkt)

	time.Sleep(50 * time.Millisecond)

	if tcp.SenderDSACKSeen(conn) {
		t.Error("sender should NOT detect DSACK for normal SACK block above cumulative ACK")
	}
}

// drainACKs reads and discards any pending packets within the timeout.
func drainACKs(ch interface {
	Read(time.Duration) []byte
}, timeout time.Duration) {
	for {
		raw := ch.Read(timeout)
		if raw == nil {
			return
		}
	}
}

// seqGreaterThan for test use (same as the one in rcv.go).
func seqGreaterThan(a, b uint32) bool {
	return int32(a-b) > 0
}
