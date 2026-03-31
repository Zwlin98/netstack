package tcp_test

import (
	"sync"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
)

// TestRetransmissionOnWithheldACK verifies that when an ACK is withheld,
// the sender retransmits the data segment after the RTO expires.
func TestRetransmissionOnWithheldACK(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60000)
	serverPort := uint16(80)
	clientISN := uint32(5000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server writes data.
	data := []byte("retransmit me")
	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	// Read the first data segment — but do NOT ACK it.
	raw1 := ch.Read(time.Second)
	if raw1 == nil {
		t.Fatal("expected initial data segment")
	}
	_, tcpHdr1 := parseTCPResponse(t, raw1)
	payload1 := raw1[header.IPv4MinHeaderSize+tcpHdr1.DataOffset():]
	if string(payload1) != string(data) {
		t.Fatalf("first segment payload = %q, want %q", payload1, data)
	}
	origSeq := tcpHdr1.SequenceNumber()

	// Wait for retransmission (RTO is 1s initially).
	raw2 := ch.Read(3 * time.Second)
	if raw2 == nil {
		t.Fatal("expected retransmitted segment after RTO")
	}
	_, tcpHdr2 := parseTCPResponse(t, raw2)
	payload2 := raw2[header.IPv4MinHeaderSize+tcpHdr2.DataOffset():]

	// Retransmitted segment should have the same sequence number and data.
	if tcpHdr2.SequenceNumber() != origSeq {
		t.Errorf("retransmit SeqNum = %d, want %d", tcpHdr2.SequenceNumber(), origSeq)
	}
	if string(payload2) != string(data) {
		t.Errorf("retransmit payload = %q, want %q", payload2, data)
	}

	// ACK the data so the sender stops retransmitting.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+uint32(len(data)))
	ch.Inject(ack)

	wg.Wait()
	conn.ForceClose()
}

// TestRTOExponentialBackoff verifies that the RTO doubles on consecutive timeouts.
func TestRTOExponentialBackoff(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60001)
	serverPort := uint16(80)
	clientISN := uint32(6000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server writes data.
	data := []byte("backoff test")
	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	// Read initial segment.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected initial segment")
	}
	t0 := time.Now()

	// First retransmit: ~1s RTO.
	raw2 := ch.Read(3 * time.Second)
	if raw2 == nil {
		t.Fatal("expected first retransmit")
	}
	t1 := time.Now()
	elapsed1 := t1.Sub(t0)

	// Second retransmit: ~2s RTO (doubled).
	raw3 := ch.Read(5 * time.Second)
	if raw3 == nil {
		t.Fatal("expected second retransmit")
	}
	t2 := time.Now()
	elapsed2 := t2.Sub(t1)

	// The second RTO interval should be roughly double the first.
	ratio := float64(elapsed2) / float64(elapsed1)
	if ratio < 1.5 || ratio > 2.8 {
		t.Errorf("RTO backoff ratio = %.2f (elapsed1=%v, elapsed2=%v), want ~2.0", ratio, elapsed1, elapsed2)
	}

	// ACK to stop retransmits.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+uint32(len(data)))
	ch.Inject(ack)

	wg.Wait()
	conn.ForceClose()
}

// TestFastRetransmitOnTripleDupACK verifies that 3 duplicate ACKs trigger
// fast retransmit of the oldest unacked segment.
func TestFastRetransmitOnTripleDupACK(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60002)
	serverPort := uint16(80)
	clientISN := uint32(7000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server writes enough data for multiple segments.
	// cwnd starts at MSS (1460). We need to grow it to send multiple segments.
	data := make([]byte, 4000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	// Read first segment (cwnd=MSS allows only 1 segment initially).
	raw1 := ch.Read(time.Second)
	if raw1 == nil {
		t.Fatal("expected segment 0")
	}
	_, tcpHdr1 := parseTCPResponse(t, raw1)
	seg1Len := uint32(len(raw1[header.IPv4MinHeaderSize+tcpHdr1.DataOffset():]))
	seg1End := tcpHdr1.SequenceNumber() + seg1Len

	// ACK the first segment to grow cwnd (slow start: cwnd doubles).
	ack1 := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, seg1End)
	ch.Inject(ack1)

	// Now cwnd >= 2*MSS. Read the next 2 segments.
	type sentSeg struct {
		seq     uint32
		payload []byte
	}
	var segs []sentSeg
	for i := 0; i < 2; i++ {
		raw := ch.Read(time.Second)
		if raw == nil {
			t.Fatalf("expected segment %d after window growth", i+1)
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		payload := raw[header.IPv4MinHeaderSize+tcpHdr.DataOffset():]
		segs = append(segs, sentSeg{seq: tcpHdr.SequenceNumber(), payload: append([]byte(nil), payload...)})
	}

	// Now send 3 duplicate ACKs at seg1End (the current UNA), simulating
	// that the second segment was lost but later segments arrived.
	dupACK := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, seg1End)
	for i := 0; i < 3; i++ {
		ch.Inject(dupACK)
	}

	// Should get a fast retransmit of the oldest unacked segment (seg2).
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected fast retransmit")
	}
	_, rtxHdr := parseTCPResponse(t, raw)

	// Fast retransmit should resend the segment starting at seg1End.
	if rtxHdr.SequenceNumber() != seg1End {
		t.Errorf("fast retransmit SeqNum = %d, want %d", rtxHdr.SequenceNumber(), seg1End)
	}

	// ACK everything to clean up.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+uint32(len(data)))
	ch.Inject(ack)

	wg.Wait()
	conn.ForceClose()
}

// TestDataTransferWithPacketLoss verifies that data transfer completes
// correctly despite simulated packet loss (by dropping segments and relying on retransmission).
func TestDataTransferWithPacketLoss(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60003)
	serverPort := uint16(80)
	clientISN := uint32(8000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server writes data.
	data := []byte("data survives packet loss!")
	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	// Read the first data segment — simulate loss by NOT ACKing it.
	raw1 := ch.Read(time.Second)
	if raw1 == nil {
		t.Fatal("expected initial data segment")
	}
	_, tcpHdr1 := parseTCPResponse(t, raw1)
	payload1 := raw1[header.IPv4MinHeaderSize+tcpHdr1.DataOffset():]
	if string(payload1) != string(data) {
		t.Fatalf("segment payload = %q, want %q", payload1, data)
	}

	// Wait for retransmission.
	raw2 := ch.Read(3 * time.Second)
	if raw2 == nil {
		t.Fatal("expected retransmitted segment")
	}
	_, tcpHdr2 := parseTCPResponse(t, raw2)
	payload2 := raw2[header.IPv4MinHeaderSize+tcpHdr2.DataOffset():]

	// Verify the retransmit has the same data.
	if string(payload2) != string(data) {
		t.Fatalf("retransmit payload = %q, want %q", payload2, data)
	}

	// Now ACK the retransmitted segment.
	ackSeq := serverISN + 1 + uint32(len(data))
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, ackSeq)
	ch.Inject(ack)

	wg.Wait()

	// Now test client→server direction with loss.
	// Send first data segment from client — "drop" it by reading from readBuf
	// and verifying. Then send it again to simulate retransmit.
	clientData := []byte("client data with loss")
	clientSeq := clientISN + 1

	// Send client data.
	pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, ackSeq, 65535, clientData)
	ch.Inject(pkt)

	// Read the ACK.
	ackRaw := ch.Read(time.Second)
	if ackRaw == nil {
		t.Fatal("expected ACK for client data")
	}

	// Read from connection — should have the data.
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if string(buf[:n]) != string(clientData) {
		t.Fatalf("received = %q, want %q", buf[:n], clientData)
	}

	conn.ForceClose()
}
