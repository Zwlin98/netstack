package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
)

// TestSegmentTrimming_PartialOverlap verifies that when a retransmitted segment
// partially overlaps with already-received data, the new bytes are still delivered.
func TestSegmentTrimming_PartialOverlap(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50000)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)
	clientSeq := clientISN + 1

	// Send first segment: bytes 0-9.
	data1 := []byte("AAAAAAAAAA") // 10 bytes
	pkt := buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535,
		data1,
	)
	ch.Inject(pkt)
	time.Sleep(50 * time.Millisecond)
	drainPackets(ch, 200*time.Millisecond)

	// Send overlapping retransmit: seq=clientSeq+5, data covers bytes 5-14.
	// Bytes 5-9 are duplicate, bytes 10-14 are new.
	data2 := []byte("aaaaaBBBBB") // 10 bytes: 5 dup + 5 new
	pkt = buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq+5, serverISN+1, 65535,
		data2,
	)
	ch.Inject(pkt)
	time.Sleep(50 * time.Millisecond)

	// Drain ACKs and check the final ACK covers bytes 0-14 (clientSeq+15).
	var lastAck uint32
	for {
		resp := ch.Read(200 * time.Millisecond)
		if resp == nil {
			break
		}
		_, ackHdr := parseTCPResponse(t, resp)
		if ackHdr.Flags().Has(header.TCPFlagACK) {
			lastAck = ackHdr.AckNumber()
		}
	}

	expectedAck := clientSeq + 15
	if lastAck != expectedAck {
		t.Fatalf("expected ACK %d, got %d — segment trimming may have failed", expectedAck, lastAck)
	}

	// Read and verify data.
	buf := make([]byte, 20)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	got := string(buf[:n])
	want := "AAAAAAAAAABBBBB" // 10 original + 5 new
	if got != want {
		t.Fatalf("read data = %q, want %q", got, want)
	}
}

// TestSegmentTrimming_FullDuplicate verifies that a fully duplicate segment is ignored.
func TestSegmentTrimming_FullDuplicate(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50001)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)
	clientSeq := clientISN + 1

	// Send original segment.
	data := []byte("HELLO")
	pkt := buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535,
		data,
	)
	ch.Inject(pkt)
	time.Sleep(50 * time.Millisecond)
	drainPackets(ch, 200*time.Millisecond)

	// Send exact duplicate.
	ch.Inject(buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535,
		data,
	))
	time.Sleep(50 * time.Millisecond)
	drainPackets(ch, 200*time.Millisecond)

	// Read should return exactly "HELLO", not "HELLOHELLO".
	buf := make([]byte, 20)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if string(buf[:n]) != "HELLO" {
		t.Fatalf("read data = %q, want %q — duplicate was not suppressed", string(buf[:n]), "HELLO")
	}
}

// TestSegmentTrimming_LeadingOverlapAtNxt verifies trimming when seq < nxt
// but the segment extends past nxt.
func TestSegmentTrimming_LeadingOverlapAtNxt(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50002)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)
	clientSeq := clientISN + 1

	// Send 10 bytes.
	pkt := buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535,
		[]byte("0123456789"),
	)
	ch.Inject(pkt)
	time.Sleep(50 * time.Millisecond)
	drainPackets(ch, 200*time.Millisecond)

	// Now send with seq = clientSeq (before nxt), but data covers clientSeq..clientSeq+20.
	// First 10 are dup, next 10 are new.
	pkt = buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535,
		[]byte("0123456789ABCDEFGHIJ"),
	)
	ch.Inject(pkt)
	time.Sleep(50 * time.Millisecond)
	drainPackets(ch, 200*time.Millisecond)

	// Read all data.
	buf := make([]byte, 30)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	want := "0123456789ABCDEFGHIJ"
	if string(buf[:n]) != want {
		t.Fatalf("read data = %q, want %q", string(buf[:n]), want)
	}
}

// TestReceiveWindowValidation_BeyondWindow verifies that a segment entirely
// beyond the receive window is discarded.
func TestReceiveWindowValidation_BeyondWindow(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50003)
	serverPort := uint16(80)
	clientISN := uint32(4000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)
	clientSeq := clientISN + 1

	// Send a segment way beyond the window (e.g., seq = clientSeq + 1MB).
	farSeq := clientSeq + 1024*1024
	pkt := buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, farSeq, serverISN+1, 65535,
		[]byte("FAR_AWAY"),
	)
	ch.Inject(pkt)
	time.Sleep(50 * time.Millisecond)
	drainPackets(ch, 200*time.Millisecond)

	// Send in-order segment.
	pkt = buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535,
		[]byte("VALID"),
	)
	ch.Inject(pkt)
	time.Sleep(50 * time.Millisecond)
	drainPackets(ch, 200*time.Millisecond)

	// Read should only return "VALID", not "FAR_AWAY".
	buf := make([]byte, 20)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if string(buf[:n]) != "VALID" {
		t.Fatalf("read data = %q, want %q — beyond-window segment was not discarded", string(buf[:n]), "VALID")
	}
	_ = conn
}

// drainPackets reads and discards all packets from the channel until timeout.
func drainPackets(ch interface{ Read(time.Duration) []byte }, timeout time.Duration) {
	for {
		if ch.Read(timeout) == nil {
			return
		}
	}
}
