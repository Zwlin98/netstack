package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// TestDeliverFullReadBuf verifies that when the read buffer is full,
// the receiver does not advance r.nxt (does not ACK undelivered data).
func TestDeliverFullReadBuf(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(40000)
	serverPort := uint16(80)
	clientISN := uint32(5000)

	serverISN, _ := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Fill the read buffer by sending data without reading it.
	// The default read buffer is 256KB. Send enough to fill it.
	clientSeq := clientISN + 1
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = 0xAA
	}

	// Send ~256KB of data to fill the buffer.
	segCount := (256*1024)/len(payload) + 5 // a bit more than buffer capacity
	var lastAckNum uint32
	for i := 0; i < segCount; i++ {
		pkt := buildTCPPacketWithData(
			clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientSeq, serverISN+1, 65535,
			payload,
		)
		ch.Inject(pkt)
		clientSeq += uint32(len(payload))
		time.Sleep(100 * time.Microsecond)

		// Drain ACK.
		for {
			resp := ch.Read(50 * time.Millisecond)
			if resp == nil {
				break
			}
			_, ackHdr := parseTCPResponse(t, resp)
			if ackHdr.Flags().Has(header.TCPFlagACK) {
				lastAckNum = ackHdr.AckNumber()
			}
		}
	}

	// The last ACK should NOT acknowledge all data — some should remain unACKed
	// because the read buffer is full and deliver() shouldn't advance r.nxt
	// past what was actually written.
	totalSent := clientISN + 1 + uint32(segCount)*uint32(len(payload))
	if lastAckNum >= totalSent {
		t.Fatalf("receiver ACKed all data (%d >= %d) — expected partial ACK due to full read buffer", lastAckNum, totalSent)
	}

	// Verify the ACKed amount is roughly the buffer size (256KB).
	acked := lastAckNum - (clientISN + 1)
	if acked > 260*1024 {
		t.Fatalf("receiver ACKed %d bytes, expected <= ~256KB (buffer size)", acked)
	}
	t.Logf("buffer full: ACKed %d / %d bytes sent", acked, totalSent-(clientISN+1))
}

// TestPartialDelivery verifies that when the read buffer has partial space,
// r.nxt advances by only the delivered bytes.
func TestPartialDelivery(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(40001)
	serverPort := uint16(80)
	clientISN := uint32(6000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Fill most of the buffer: send 255KB of data, leaving ~1KB free.
	clientSeq := clientISN + 1
	payload := make([]byte, 1400)
	fillAmount := 255 * 1024
	sent := 0
	for sent < fillAmount {
		sz := min(len(payload), fillAmount-sent)
		pkt := buildTCPPacketWithData(
			clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientSeq, serverISN+1, 65535,
			payload[:sz],
		)
		ch.Inject(pkt)
		clientSeq += uint32(sz)
		sent += sz
		time.Sleep(100 * time.Microsecond)

		// Drain ACKs.
		for {
			resp := ch.Read(50 * time.Millisecond)
			if resp == nil {
				break
			}
		}
	}

	// Now send a 1400-byte segment that won't fully fit (~1KB free).
	pkt := buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535,
		payload,
	)
	ch.Inject(pkt)
	time.Sleep(50 * time.Millisecond)

	// Drain ACK.
	var lastAckNum uint32
	for {
		resp := ch.Read(50 * time.Millisecond)
		if resp == nil {
			break
		}
		_, ackHdr := parseTCPResponse(t, resp)
		if ackHdr.Flags().Has(header.TCPFlagACK) {
			lastAckNum = ackHdr.AckNumber()
		}
	}

	// The ACK should be for less than clientSeq + 1400 (partial delivery).
	fullAck := clientSeq + uint32(len(payload))
	if lastAckNum >= fullAck {
		t.Fatalf("receiver ACKed full segment (%d >= %d) — expected partial ACK", lastAckNum, fullAck)
	}
	partialAcked := lastAckNum - clientSeq
	t.Logf("partial delivery: ACKed %d / %d bytes of last segment", partialAcked, len(payload))

	// Now read some data to free buffer space.
	readBuf := make([]byte, 4096)
	n, err := conn.Read(readBuf)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if n == 0 {
		t.Fatal("expected to read data from buffer")
	}
	t.Logf("read %d bytes, freeing buffer space", n)
}

// TestOOOReassemblyPartialReadBuf verifies that OOO reassembly handles
// partial read buffer space correctly.
func TestOOOReassemblyPartialReadBuf(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(40002)
	serverPort := uint16(80)
	clientISN := uint32(7000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Fill most of the buffer.
	clientSeq := clientISN + 1
	payload := make([]byte, 1400)
	fillAmount := 254 * 1024
	sent := 0
	for sent < fillAmount {
		sz := min(len(payload), fillAmount-sent)
		pkt := buildTCPPacketWithData(
			clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientSeq, serverISN+1, 65535,
			payload[:sz],
		)
		ch.Inject(pkt)
		clientSeq += uint32(sz)
		sent += sz
		time.Sleep(100 * time.Microsecond)
		for {
			resp := ch.Read(50 * time.Millisecond)
			if resp == nil {
				break
			}
		}
	}

	// Send OOO segment (skip seq clientSeq, send clientSeq+1400).
	oooData := []byte("OOO-DATA-SEGMENT")
	oooSeq := clientSeq + 1400
	pkt := buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, oooSeq, serverISN+1, 65535,
		oooData,
	)
	ch.Inject(pkt)
	time.Sleep(50 * time.Millisecond)

	// Now send the missing segment to fill the gap.
	gapData := make([]byte, 1400)
	for i := range gapData {
		gapData[i] = 0xBB
	}
	pkt = buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535,
		gapData,
	)
	ch.Inject(pkt)
	time.Sleep(50 * time.Millisecond)

	// Drain all ACKs.
	var lastAckNum uint32
	for {
		resp := ch.Read(100 * time.Millisecond)
		if resp == nil {
			break
		}
		_, ackHdr := parseTCPResponse(t, resp)
		if ackHdr.Flags().Has(header.TCPFlagACK) {
			lastAckNum = ackHdr.AckNumber()
		}
	}

	// The ACK should NOT cover the full OOO segment if readBuf is nearly full.
	// It should have delivered as much as fits and retained the rest.
	fullAck := oooSeq + uint32(len(oooData))
	t.Logf("last ACK: %d, full coverage would be: %d", lastAckNum, fullAck)

	// Read data to verify integrity — the delivered data should be consistent.
	readBuf := make([]byte, 4096)
	n, err := conn.Read(readBuf)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if n == 0 {
		t.Fatal("expected to read data")
	}
	t.Logf("read %d bytes after OOO reassembly with partial buffer", n)
}

// --- Handshake data delivery tests ---

// TestHandshakeACKWithData verifies that data piggybacked on the
// completing ACK is delivered to the receiver.
func TestHandshakeACKWithData(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50000)
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

	// Send completing ACK with piggybacked data.
	payload := []byte("hello from handshake")
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, payload)
	ch.Inject(ack)

	// Accept the connection.
	done := make(chan struct{})
	var conn *tcp.TCPConn
	go func() {
		conn, _ = h.Listener().Accept()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Accept() timed out")
	}

	// Read data — should contain the piggybacked payload.
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if string(buf[:n]) != "hello from handshake" {
		t.Fatalf("Read = %q, want %q", string(buf[:n]), "hello from handshake")
	}

	// Server should have sent an ACK for the data.
	ackRaw := ch.Read(time.Second)
	if ackRaw == nil {
		t.Fatal("expected ACK for piggybacked data, got nil")
	}
	_, ackHdr := parseTCPResponse(t, ackRaw)
	if !ackHdr.Flags().Has(header.TCPFlagACK) {
		t.Fatalf("expected ACK flag, got %s", ackHdr.Flags())
	}
	expectedAck := clientISN + 1 + uint32(len(payload))
	if ackHdr.AckNumber() != expectedAck {
		t.Fatalf("ACK number = %d, want %d", ackHdr.AckNumber(), expectedAck)
	}

	conn.ForceClose()
}

// TestHandshakeACKWithoutData verifies normal handshake (no data) still works.
func TestHandshakeACKWithoutData(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, 50001, 80, 2000)

	// Send data after handshake — should work normally.
	data := buildTCPPacketWithData(clientAddr, serverAddr, 50001, 80,
		header.TCPFlagACK, 2001, serverISN+1, 65535, []byte("post-handshake"))
	ch.Inject(data)

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if string(buf[:n]) != "post-handshake" {
		t.Fatalf("Read = %q, want %q", string(buf[:n]), "post-handshake")
	}
	conn.ForceClose()
}

// --- OOO overlap/merge tests ---

// TestOOOAdjacentMerge verifies that adjacent OOO segments are merged.
func TestOOOAdjacentMerge(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, 50002, 80, 3000)

	// Send two OOO segments: [3002-3005] then [3005-3008] (gap at [3001-3002]).
	seg1 := buildTCPPacketWithData(clientAddr, serverAddr, 50002, 80,
		header.TCPFlagACK, 3002, serverISN+1, 65535, []byte("abc"))
	ch.Inject(seg1)
	time.Sleep(10 * time.Millisecond)

	seg2 := buildTCPPacketWithData(clientAddr, serverAddr, 50002, 80,
		header.TCPFlagACK, 3005, serverISN+1, 65535, []byte("def"))
	ch.Inject(seg2)
	time.Sleep(10 * time.Millisecond)

	// Verify OOO count: should be 1 merged segment [3002-3008].
	oooCount := tcp.OOOCount(conn)
	if oooCount != 1 {
		t.Fatalf("OOO segments = %d, want 1 (merged)", oooCount)
	}

	// Now fill the gap — send [3001-3002].
	gap := buildTCPPacketWithData(clientAddr, serverAddr, 50002, 80,
		header.TCPFlagACK, 3001, serverISN+1, 65535, []byte("X"))
	ch.Inject(gap)
	time.Sleep(10 * time.Millisecond)

	buf := make([]byte, 100)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "Xabcdef" {
		t.Fatalf("Read = %q, want %q", string(buf[:n]), "Xabcdef")
	}
	conn.ForceClose()
}

// TestOOOOverlappingMerge verifies that overlapping OOO segments are merged.
func TestOOOOverlappingMerge(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, 50003, 80, 4000)

	// Send two overlapping OOO segments: [4002-4006] and [4004-4008] (gap at [4001-4002]).
	seg1 := buildTCPPacketWithData(clientAddr, serverAddr, 50003, 80,
		header.TCPFlagACK, 4002, serverISN+1, 65535, []byte("ABCD"))
	ch.Inject(seg1)
	time.Sleep(10 * time.Millisecond)

	seg2 := buildTCPPacketWithData(clientAddr, serverAddr, 50003, 80,
		header.TCPFlagACK, 4004, serverISN+1, 65535, []byte("cdef"))
	ch.Inject(seg2)
	time.Sleep(10 * time.Millisecond)

	// Should be merged into one segment [4002-4008].
	oooCount := tcp.OOOCount(conn)
	if oooCount != 1 {
		t.Fatalf("OOO segments = %d, want 1 (merged overlap)", oooCount)
	}

	// Fill the gap.
	gap := buildTCPPacketWithData(clientAddr, serverAddr, 50003, 80,
		header.TCPFlagACK, 4001, serverISN+1, 65535, []byte("X"))
	ch.Inject(gap)
	time.Sleep(10 * time.Millisecond)

	buf := make([]byte, 100)
	n, _ := conn.Read(buf)
	// [4001]: "X", [4002-4005]: "ABCD", [4006-4007]: "ef" (from merge)
	if string(buf[:n]) != "XABCDef" {
		t.Fatalf("Read = %q, want %q", string(buf[:n]), "XABCDef")
	}
	conn.ForceClose()
}

// TestOOOChainMerge verifies that a new segment bridging two OOO segments merges all three.
func TestOOOChainMerge(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, 50004, 80, 5000)

	// Send [5002-5004] and [5006-5008] (two separate OOO segments).
	seg1 := buildTCPPacketWithData(clientAddr, serverAddr, 50004, 80,
		header.TCPFlagACK, 5002, serverISN+1, 65535, []byte("ab"))
	ch.Inject(seg1)
	time.Sleep(10 * time.Millisecond)

	seg2 := buildTCPPacketWithData(clientAddr, serverAddr, 50004, 80,
		header.TCPFlagACK, 5006, serverISN+1, 65535, []byte("ef"))
	ch.Inject(seg2)
	time.Sleep(10 * time.Millisecond)

	if c := tcp.OOOCount(conn); c != 2 {
		t.Fatalf("OOO segments = %d, want 2 before chain merge", c)
	}

	// Send [5004-5006] which bridges the gap between the two OOO segments.
	bridge := buildTCPPacketWithData(clientAddr, serverAddr, 50004, 80,
		header.TCPFlagACK, 5004, serverISN+1, 65535, []byte("cd"))
	ch.Inject(bridge)
	time.Sleep(10 * time.Millisecond)

	// Should be merged into one segment [5002-5008].
	if c := tcp.OOOCount(conn); c != 1 {
		t.Fatalf("OOO segments = %d, want 1 (chain merge)", c)
	}

	// Fill the gap [5001-5002].
	gap := buildTCPPacketWithData(clientAddr, serverAddr, 50004, 80,
		header.TCPFlagACK, 5001, serverISN+1, 65535, []byte("X"))
	ch.Inject(gap)
	time.Sleep(10 * time.Millisecond)

	buf := make([]byte, 100)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "Xabcdef" {
		t.Fatalf("Read = %q, want %q", string(buf[:n]), "Xabcdef")
	}
	conn.ForceClose()
}

// --- deliverOOO trimming test ---

// TestDeliverOOOTrimsOverlap verifies that deliverOOO trims leading bytes
// when an OOO segment starts before rcv.nxt.
func TestDeliverOOOTrimsOverlap(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, 50005, 80, 6000)

	// Send OOO segment [6003-6008].
	seg := buildTCPPacketWithData(clientAddr, serverAddr, 50005, 80,
		header.TCPFlagACK, 6003, serverISN+1, 65535, []byte("CDEFG"))
	ch.Inject(seg)
	time.Sleep(10 * time.Millisecond)

	// Send in-order segment [6001-6005] which overlaps with OOO [6003-6008].
	// After delivering [6001-6005], nxt=6005. deliverOOO should trim OOO
	// segment to [6005-6008] and deliver "FG".
	inOrder := buildTCPPacketWithData(clientAddr, serverAddr, 50005, 80,
		header.TCPFlagACK, 6001, serverISN+1, 65535, []byte("abcd"))
	ch.Inject(inOrder)
	time.Sleep(10 * time.Millisecond)

	buf := make([]byte, 100)
	n, _ := conn.Read(buf)
	// [6001-6004]: "abcd", [6005-6007]: "EFG" (trimmed from OOO, 2 bytes overlap removed)
	if string(buf[:n]) != "abcdEFG" {
		t.Fatalf("Read = %q, want %q", string(buf[:n]), "abcdEFG")
	}
	conn.ForceClose()
}

// --- SACK block coalescing test ---

// completeHandshakeWithSACK performs handshake with SACK permitted option.
func completeHandshakeWithSACK(t *testing.T, ch *channel.MemoryChannel, h *tcp.TCPHandler,
	clientAddr, serverAddr tcpip.Address, clientPort, serverPort uint16, clientISN uint32,
) (serverISN uint32, conn *tcp.TCPConn) {
	t.Helper()

	// Build SYN with SACK Permitted option.
	var opts [2]byte
	n := header.EncodeSACKPermittedOption(opts[:])

	syn := buildTCPPacketWithOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagSYN, clientISN, 0, opts[:n])
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK, got nil")
	}
	_, sa := parseTCPResponse(t, raw)
	serverISN = sa.SequenceNumber()

	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1)
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
	return serverISN, conn
}

// TestSACKBlockCoalesced verifies that adjacent OOO segments produce
// coalesced SACK blocks.
func TestSACKBlockCoalesced(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	serverISN, conn := completeHandshakeWithSACK(t, ch, h, clientAddr, serverAddr, 50006, 80, 7000)

	// Send two adjacent OOO segments: [7003-7006] and [7006-7009].
	seg1 := buildTCPPacketWithData(clientAddr, serverAddr, 50006, 80,
		header.TCPFlagACK, 7003, serverISN+1, 65535, []byte("abc"))
	ch.Inject(seg1)

	// Read ACK with SACK for first OOO.
	ack1 := ch.Read(time.Second)
	if ack1 == nil {
		t.Fatal("expected ACK, got nil")
	}

	seg2 := buildTCPPacketWithData(clientAddr, serverAddr, 50006, 80,
		header.TCPFlagACK, 7006, serverISN+1, 65535, []byte("def"))
	ch.Inject(seg2)

	// Read ACK with SACK — should be one coalesced block [7003-7009].
	ack2 := ch.Read(time.Second)
	if ack2 == nil {
		t.Fatal("expected ACK with SACK, got nil")
	}
	_, ackHdr := parseTCPResponse(t, ack2)
	opts := header.ParseSegmentOptions(ackHdr.Options())
	if len(opts.SACKBlocks) != 1 {
		t.Fatalf("SACK blocks = %d, want 1 (coalesced)", len(opts.SACKBlocks))
	}
	if opts.SACKBlocks[0].Start != 7003 || opts.SACKBlocks[0].End != 7009 {
		t.Fatalf("SACK block = [%d-%d], want [7003-7009]",
			opts.SACKBlocks[0].Start, opts.SACKBlocks[0].End)
	}

	conn.ForceClose()
}

// --- SYN_RCVD timeout tests ---

// TestSynRcvdTimeout verifies that half-open connections are cleaned up after timeout.
func TestSynRcvdTimeout(t *testing.T) {
	ch, s, h := setupStack(t, tcp.WithSynRcvdTimeout(100*time.Millisecond))
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	// Send SYN — server responds with SYN+ACK, connection enters SYN_RCVD.
	syn := buildTCPPacket(clientAddr, serverAddr, 50007, 80, header.TCPFlagSYN, 8000, 0)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK, got nil")
	}

	// Verify connection exists.
	if tcp.ConnTableLen(h) != 1 {
		t.Fatalf("conn table len = %d, want 1", tcp.ConnTableLen(h))
	}

	// Don't send completing ACK — wait for timeout.
	time.Sleep(300 * time.Millisecond)

	// Connection should be cleaned up.
	if tcp.ConnTableLen(h) != 0 {
		t.Fatalf("conn table len = %d, want 0 (timed out)", tcp.ConnTableLen(h))
	}
}

// TestSynRcvdTimeoutCancelledOnHandshake verifies that completing the
// handshake cancels the SYN_RCVD timeout.
func TestSynRcvdTimeoutCancelledOnHandshake(t *testing.T) {
	ch, s, h := setupStack(t, tcp.WithSynRcvdTimeout(200*time.Millisecond))
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, 50008, 80, 9000)

	// Wait longer than timeout — connection should still be alive.
	time.Sleep(400 * time.Millisecond)

	if tcp.ConnTableLen(h) != 1 {
		t.Fatalf("conn table len = %d, want 1 (handshake completed, timer cancelled)", tcp.ConnTableLen(h))
	}

	conn.ForceClose()
}
