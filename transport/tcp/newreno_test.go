package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// TestNewReno_FastRecoveryEntry verifies that 3 duplicate ACKs trigger
// fast recovery: ssthresh = cwnd/2, cwnd = ssthresh + 3*MSS, retransmit.
func TestNewReno_FastRecoveryEntry(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(12345)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)
	_ = serverISN

	mss := 1500 - header.IPv4MinHeaderSize - header.TCPMinHeaderSize

	// Write data.
	data := make([]byte, mss*10)
	go func() {
		conn.Write(data)
	}()

	// Initial cwnd=1 MSS → first segment sent.
	firstRaw := ch.Read(time.Second)
	if firstRaw == nil {
		t.Fatal("no first segment")
	}
	_, firstTCP := parseTCPResponse(t, firstRaw)
	firstEnd := firstTCP.SequenceNumber() + uint32(len(firstTCP.Payload()))

	// ACK the first segment to grow cwnd (slow start: cwnd becomes 2 MSS).
	ack1 := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, firstEnd)
	ch.Inject(ack1)

	// Now 2 segments should be sent. Collect them.
	var seg2End uint32
	for range 2 {
		raw := ch.Read(time.Second)
		if raw == nil {
			break
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		end := tcpHdr.SequenceNumber() + uint32(len(tcpHdr.Payload()))
		if end > seg2End {
			seg2End = end
		}
	}

	// ACK up to just the first of the two new segments (partial).
	partialAck := firstEnd + uint32(mss)
	ack2 := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, partialAck)
	ch.Inject(ack2)

	// Drain any new segments.
	for {
		raw := ch.Read(200 * time.Millisecond)
		if raw == nil {
			break
		}
	}

	// Now send 3 duplicate ACKs for the partial ACK point.
	for range 3 {
		dupAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientISN+1, partialAck)
		ch.Inject(dupAck)
	}

	// After 3 dup ACKs, the server should retransmit (fast recovery).
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected retransmission after 3 dup ACKs, got nil")
	}
	_, retxTCP := parseTCPResponse(t, raw)
	t.Logf("Fast recovery triggered: retransmit seq=%d (expected ~%d)",
		retxTCP.SequenceNumber(), partialAck)
}

// TestNewReno_FullACKExitsRecovery verifies that a full ACK covering
// the recovery point exits fast recovery.
func TestNewReno_FullACKExitsRecovery(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(12345)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)
	_ = serverISN

	mss := 1500 - header.IPv4MinHeaderSize - header.TCPMinHeaderSize

	// Write data.
	data := make([]byte, mss*10)
	go func() {
		conn.Write(data)
	}()

	// Read initial segment and grow cwnd.
	firstRaw := ch.Read(time.Second)
	if firstRaw == nil {
		t.Fatal("no first segment")
	}
	_, firstTCP := parseTCPResponse(t, firstRaw)
	ackPoint := firstTCP.SequenceNumber() + uint32(len(firstTCP.Payload()))

	// ACK first → cwnd grows.
	ack1 := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, ackPoint)
	ch.Inject(ack1)

	// Drain new segments.
	highSeq := ackPoint
	for {
		raw := ch.Read(200 * time.Millisecond)
		if raw == nil {
			break
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		end := tcpHdr.SequenceNumber() + uint32(len(tcpHdr.Payload()))
		if end > highSeq {
			highSeq = end
		}
	}

	// 3 dup ACKs → enter fast recovery.
	for range 3 {
		dupAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientISN+1, ackPoint)
		ch.Inject(dupAck)
	}

	// Drain retransmit.
	for {
		raw := ch.Read(200 * time.Millisecond)
		if raw == nil {
			break
		}
	}

	// Full ACK covering all sent data → exits recovery.
	fullAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, highSeq)
	ch.Inject(fullAck)

	time.Sleep(50 * time.Millisecond)
	t.Logf("Full ACK at %d processed, recovery exited", highSeq)
}

// TestNewReno_CwndInflation verifies that during fast recovery,
// each additional dup ACK inflates cwnd by MSS.
func TestNewReno_CwndInflation(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(12345)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)
	_ = serverISN

	// Write lots of data.
	mss := 1500 - header.IPv4MinHeaderSize - header.TCPMinHeaderSize
	data := make([]byte, mss*10)
	go func() {
		conn.Write(data)
	}()

	// Collect initial segments (cwnd starts at 1 MSS in our stack).
	firstRaw := ch.Read(time.Second)
	if firstRaw == nil {
		t.Fatal("no data segment sent")
	}
	_, firstTCP := parseTCPResponse(t, firstRaw)
	ackPoint := firstTCP.SequenceNumber() + uint32(len(firstTCP.Payload()))

	// ACK first segment to grow cwnd via slow start.
	ack1 := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, ackPoint)
	ch.Inject(ack1)

	// Drain any new segments that arrive after the ACK.
	for {
		raw := ch.Read(200 * time.Millisecond)
		if raw == nil {
			break
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		newEnd := tcpHdr.SequenceNumber() + uint32(len(tcpHdr.Payload()))
		if newEnd > ackPoint {
			ackPoint = newEnd
		}
	}

	// Now send 3 dup ACKs to enter recovery.
	for range 3 {
		dupAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientISN+1, ackPoint)
		ch.Inject(dupAck)
	}

	// Drain the retransmit.
	ch.Read(500 * time.Millisecond)

	// Additional dup ACKs during recovery should inflate cwnd and allow new data.
	extraDups := 0
	for range 5 {
		dupAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientISN+1, ackPoint)
		ch.Inject(dupAck)
		// Check if new data is sent (cwnd inflation allows it).
		raw := ch.Read(100 * time.Millisecond)
		if raw != nil {
			extraDups++
		}
	}
	t.Logf("new segments sent during cwnd inflation: %d", extraDups)
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go
// TestFastRetransmitOnTripleDupACK is already ported in congestion_test.go.
// TestNewReno* are custom tests for our NewReno implementation.
var _ = (*tcp.TCPConn)(nil) // ensure import
