package tcp_test

import (
	"sync"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// receiveAndCheckSegment reads one segment from the channel, verifies it carries
// maxPayload bytes from data starting at offset, and returns the raw packet.
func receiveAndCheckSegment(t *testing.T, ch interface{ Read(time.Duration) []byte }, data []byte, offset, maxPayload int) []byte {
	t.Helper()
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatalf("expected data segment at offset %d, got nil", offset)
	}
	_, tcpHdr := parseTCPResponse(t, raw)
	payload := raw[header.IPv4MinHeaderSize+tcpHdr.DataOffset():]

	want := maxPayload
	remaining := len(data) - offset
	if remaining < want {
		want = remaining
	}
	if len(payload) != want {
		t.Fatalf("segment at offset %d: payload length = %d, want %d", offset, len(payload), want)
	}
	for i := range payload {
		if payload[i] != data[offset+i] {
			t.Fatalf("segment at offset %d: byte %d = %d, want %d", offset, i, payload[i], data[offset+i])
		}
	}
	return raw
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_noracedetector_test.go:TestExponentialIncreaseDuringSlowStart (line 205)
//
// Tests that cwnd doubles during slow start: each RTT, the sender transmits
// twice as many segments as the previous RTT. Our implementation starts with
// cwnd=1*MSS (vs gVisor's InitialCwnd=10), so the sequence is 1, 2, 4, 8, ...
func TestExponentialIncreaseDuringSlowStart(t *testing.T) {
	const maxPayload = 32
	mtu := header.IPv4MinHeaderSize + header.TCPMinHeaderSize + maxPayload
	ch, s, h := setupStackWithMTU(t, mtu)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	const initialCwnd = 1
	const iterations = 4
	data := make([]byte, maxPayload*(initialCwnd<<(iterations+1)))
	for i := range data {
		data[i] = byte(i)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	expected := initialCwnd
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		// Read all segments expected in this cwnd window.
		for j := 0; j < expected; j++ {
			receiveAndCheckSegment(t, ch, data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Verify no more segments arrive (cwnd is exhausted).
		extra := ch.Read(100 * time.Millisecond)
		if extra != nil {
			t.Fatalf("iteration %d: received more segments than expected cwnd=%d", i, expected)
		}

		// ACK all data received so far → cwnd doubles in slow start.
		ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientISN+1, serverISN+1+uint32(bytesRead))
		ch.Inject(ack)

		expected *= 2
	}

	// ACK everything remaining to let writer finish.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+uint32(len(data)))
	ch.Inject(ack)
	// Drain any remaining segments.
	for {
		raw := ch.Read(200 * time.Millisecond)
		if raw == nil {
			break
		}
	}

	wg.Wait()
	conn.ForceClose()
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_noracedetector_test.go:TestCongestionAvoidance (line 249)
//
// Tests that after an RTO timeout resets cwnd, the sender goes through
// slow start up to ssthresh, then switches to congestion avoidance where
// cwnd increases by ~1 MSS per RTT.
func TestCongestionAvoidance(t *testing.T) {
	const maxPayload = 32
	mtu := header.IPv4MinHeaderSize + header.TCPMinHeaderSize + maxPayload
	ch, s, h := setupStackWithMTU(t, mtu)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	const initialCwnd = 1
	const iterations = 3
	data := make([]byte, 2*maxPayload*(initialCwnd<<(iterations+1)))
	for i := range data {
		data[i] = byte(i)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	// Phase 1: Slow start to build up cwnd.
	expected := initialCwnd
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		if i > 0 {
			// ACK all data received so far.
			ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
				header.TCPFlagACK, clientISN+1, serverISN+1+uint32(bytesRead))
			ch.Inject(ack)
			expected = initialCwnd << uint(i)
		}

		for j := 0; j < expected; j++ {
			receiveAndCheckSegment(t, ch, data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		extra := ch.Read(100 * time.Millisecond)
		if extra != nil {
			t.Fatalf("slow start iteration %d: extra segment beyond cwnd=%d", i, expected)
		}
	}

	// Phase 2: Don't ACK → let RTO fire. This resets cwnd=MSS, ssthresh=cwnd/2.
	// Wait for the retransmitted oldest unacked segment.
	retransmit := ch.Read(3 * time.Second)
	if retransmit == nil {
		t.Fatal("expected retransmitted segment after RTO")
	}
	_, rtxHdr := parseTCPResponse(t, retransmit)
	rtxPayload := retransmit[header.IPv4MinHeaderSize+rtxHdr.DataOffset():]
	if len(rtxPayload) != maxPayload {
		t.Fatalf("retransmit payload = %d bytes, want %d", len(rtxPayload), maxPayload)
	}

	// ACK all data received so far (the full slow-start train).
	// This will cause the sender to go through slow start again up to ssthresh,
	// then enter congestion avoidance.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+uint32(bytesRead))
	ch.Inject(ack)

	// After RTO: ssthresh = old_cwnd/2 = (expected*maxPayload)/2 bytes.
	// That's expected/2 segments. cwnd resets to 1 segment (MSS bytes).
	// The cumulative ACK of 'expected' segments makes cwnd grow via slow start
	// up to ssthresh (capped), then enters congestion avoidance.
	//
	// In congestion avoidance, cwnd grows by ~1 segment per RTT.
	// After recovery, cwnd = ssthresh = expected/2 segments.
	expectedCA := expected / 2

	// Phase 3: Congestion avoidance — cwnd grows by 1 per RTT.
	for i := 0; i < iterations; i++ {
		for j := 0; j < expectedCA; j++ {
			receiveAndCheckSegment(t, ch, data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		extra := ch.Read(100 * time.Millisecond)
		if extra != nil {
			t.Fatalf("congestion avoidance iteration %d: extra segment beyond cwnd=%d", i, expectedCA)
		}

		// ACK all data → cwnd grows by 1 in congestion avoidance.
		ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientISN+1, serverISN+1+uint32(bytesRead))
		ch.Inject(ack)

		expectedCA++
	}

	// Clean up: ACK everything.
	finalAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+uint32(len(data)))
	ch.Inject(finalAck)
	for {
		raw := ch.Read(200 * time.Millisecond)
		if raw == nil {
			break
		}
	}

	wg.Wait()
	conn.ForceClose()
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_noracedetector_test.go:TestRetransmit (line 466)
//
// Tests that the sender retransmits the oldest unacked segment after an RTO
// timeout, and resumes sending remaining data after a partial ACK.
func TestRetransmit(t *testing.T) {
	const maxPayload = 32
	mtu := header.IPv4MinHeaderSize + header.TCPMinHeaderSize + maxPayload
	ch, s, h := setupStackWithMTU(t, mtu)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	const initialCwnd = 1
	const iterations = 3
	data := make([]byte, maxPayload*(initialCwnd<<(iterations+1)))
	for i := range data {
		data[i] = byte(i)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	// Phase 1: Slow start.
	expected := initialCwnd
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		expected = initialCwnd << uint(i)
		if i > 0 {
			ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
				header.TCPFlagACK, clientISN+1, serverISN+1+uint32(bytesRead))
			ch.Inject(ack)
		}

		for j := 0; j < expected; j++ {
			receiveAndCheckSegment(t, ch, data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		extra := ch.Read(100 * time.Millisecond)
		if extra != nil {
			t.Fatalf("slow start iteration %d: extra segment", i)
		}
	}

	// Phase 2: Wait for RTO and verify retransmission.
	rtxOffset := bytesRead - maxPayload*expected
	retransmit := ch.Read(3 * time.Second)
	if retransmit == nil {
		t.Fatal("expected retransmitted segment")
	}
	_, rtxHdr := parseTCPResponse(t, retransmit)
	rtxSeq := rtxHdr.SequenceNumber()
	expectedRtxSeq := serverISN + 1 + uint32(rtxOffset)
	if rtxSeq != expectedRtxSeq {
		t.Fatalf("retransmit SeqNum = %d, want %d", rtxSeq, expectedRtxSeq)
	}

	// Phase 3: ACK all data sent so far. This advances UNA and allows
	// the sender to resume sending remaining data from the write buffer.
	fullAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+uint32(bytesRead))
	ch.Inject(fullAck)

	// Phase 4: Receive remaining data (from write buffer), ACKing each segment.
	for bytesRead < len(data) {
		raw := ch.Read(3 * time.Second)
		if raw == nil {
			t.Fatalf("expected more data, %d/%d bytes received", bytesRead, len(data))
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		payload := raw[header.IPv4MinHeaderSize+tcpHdr.DataOffset():]
		bytesRead += len(payload)

		ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientISN+1, serverISN+1+uint32(bytesRead))
		ch.Inject(ack)
	}

	if bytesRead != len(data) {
		t.Fatalf("total received = %d, want %d", bytesRead, len(data))
	}

	wg.Wait()
	conn.ForceClose()
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestMaxRetransmitsTimeout (line 4074)
//
// Tests that a connection aborts (sends RST) after exceeding the maximum
// number of retransmission attempts.
func TestMaxRetransmitsTimeout(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Override maxRetries to a small value for faster testing.
	tcp.SetMaxRetries(conn, 2)

	// Server writes data.
	data := []byte("abort test")
	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	// Expect the initial transmit + 2 retransmits = 3 total segments.
	for i := 0; i < 3; i++ {
		raw := ch.Read(5 * time.Second)
		if raw == nil {
			t.Fatalf("expected segment %d (initial + retransmit), got nil", i)
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		if !tcpHdr.Flags().Has(header.TCPFlagACK) {
			t.Fatalf("segment %d: expected ACK flag, got %s", i, tcpHdr.Flags())
		}
	}

	// After max retries, the connection should abort with RST.
	// The next segment should be a RST.
	raw := ch.Read(10 * time.Second)
	if raw == nil {
		t.Fatal("expected RST after max retransmits")
	}
	_, rstHdr := parseTCPResponse(t, raw)
	if !rstHdr.Flags().Has(header.TCPFlagRST) {
		t.Fatalf("expected RST flag after max retransmits, got %s", rstHdr.Flags())
	}

	wg.Wait()
}
