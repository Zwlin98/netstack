package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
)

// TestSACK_NegotiatedInHandshake verifies SACK is negotiated during handshake.
func TestSACK_NegotiatedInHandshake(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	// SYN with SACK-Permitted.
	var synOpts []byte
	buf := make([]byte, 10)
	n := 0
	n += header.EncodeMSSOption(buf[n:], 1460)
	buf[n] = header.TCPOptionNOP
	n++
	n += header.EncodeWSOption(buf[n:], 7)
	n += header.EncodeSACKPermittedOption(buf[n:])
	synOpts = buf[:n]

	syn := buildTCPPacketWithOptions(clientAddr, serverAddr, 12345, 80, header.TCPFlagSYN, 1000, 0, synOpts)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK, got nil")
	}
	_, tcpHdr := parseTCPResponse(t, raw)

	opts := tcpHdr.Options()
	if opts == nil {
		t.Fatal("SYN+ACK has no options")
	}
	so := header.ParseSynOptions(opts)
	if !so.SACKPermit {
		t.Error("SYN+ACK should include SACK-Permitted when peer offered it")
	}
}

// TestSACK_OOOGeneratesSACKBlocks verifies that receiving out-of-order data
// causes ACKs to include SACK blocks.
func TestSACK_OOOGeneratesSACKBlocks(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(12345)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	// SYN with SACK-Permitted.
	var synOpts []byte
	optBuf := make([]byte, 10)
	n := 0
	n += header.EncodeMSSOption(optBuf[n:], 1460)
	optBuf[n] = header.TCPOptionNOP
	n++
	n += header.EncodeWSOption(optBuf[n:], 0) // WS=0 for simplicity
	n += header.EncodeSACKPermittedOption(optBuf[n:])
	synOpts = optBuf[:n]

	syn := buildTCPPacketWithOptions(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagSYN, clientISN, 0, synOpts)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK, got nil")
	}
	_, sa := parseTCPResponse(t, raw)
	serverISN := sa.SequenceNumber()

	// Complete handshake.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagACK, clientISN+1, serverISN+1)
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
		t.Fatal("Accept timed out")
	}

	// Now send out-of-order data: skip segment at clientISN+1, send at clientISN+1+100.
	oooData := make([]byte, 50)
	for i := range oooData {
		oooData[i] = byte(i)
	}
	oooSeq := clientISN + 1 + 100
	oooPkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, oooSeq, serverISN+1, 65535, oooData)
	ch.Inject(oooPkt)

	// Read the ACK response.
	raw = ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK with SACK blocks, got nil")
	}
	_, ackHdr := parseTCPResponse(t, raw)

	// The ACK should still be for clientISN+1 (the gap).
	if ackHdr.AckNumber() != clientISN+1 {
		t.Errorf("ACK number = %d, want %d", ackHdr.AckNumber(), clientISN+1)
	}

	// Parse SACK blocks from the response.
	ackOpts := ackHdr.Options()
	if ackOpts == nil {
		t.Fatal("ACK has no options (expected SACK blocks)")
	}
	segOpts := header.ParseSegmentOptions(ackOpts)
	if len(segOpts.SACKBlocks) == 0 {
		t.Fatal("ACK has no SACK blocks")
	}

	// Verify the SACK block covers the OOO data.
	block := segOpts.SACKBlocks[0]
	if block.Start != oooSeq {
		t.Errorf("SACK block start = %d, want %d", block.Start, oooSeq)
	}
	if block.End != oooSeq+uint32(len(oooData)) {
		t.Errorf("SACK block end = %d, want %d", block.End, oooSeq+uint32(len(oooData)))
	}
	t.Logf("SACK block: [%d, %d)", block.Start, block.End)
}
