package tcp_test

import (
	"io"
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

// TestGracefulClose_FullLifecycle tests the complete lifecycle:
// handshake → data transfer → graceful 4-way close.
func TestGracefulClose_FullLifecycle(t *testing.T) {
	ch, s, h := setupStack(t, tcp.WithTimeWaitDuration(100*time.Millisecond))
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50100)
	serverPort := uint16(80)
	clientISN := uint32(5000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Client sends data.
	clientSeq := clientISN + 1
	data := []byte("hello graceful close")
	pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535, data)
	ch.Inject(pkt)
	clientSeq += uint32(len(data))

	// Drain the ACK.
	ackRaw := ch.Read(time.Second)
	if ackRaw == nil {
		t.Fatal("expected ACK for data")
	}

	// Read the data from the connection.
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if string(buf[:n]) != string(data) {
		t.Fatalf("Read = %q; want %q", buf[:n], data)
	}

	// Server initiates close.
	conn.Close()

	// Should receive FIN+ACK from server.
	finRaw := ch.Read(time.Second)
	if finRaw == nil {
		t.Fatal("expected FIN from server")
	}
	_, finHdr := parseTCPResponse(t, finRaw)
	if !finHdr.Flags().Has(header.TCPFlagFIN) {
		t.Fatalf("expected FIN flag, got %s", finHdr.Flags())
	}
	serverFINSeq := finHdr.SequenceNumber()

	// Client ACKs the FIN.
	finAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverFINSeq+1)
	ch.Inject(finAck)

	// Server should now be in FIN_WAIT_2.
	// Give the segment time to be processed.
	time.Sleep(50 * time.Millisecond)

	// Client sends FIN.
	clientFIN := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagFIN|header.TCPFlagACK, clientSeq, serverFINSeq+1)
	ch.Inject(clientFIN)

	// Server ACKs the client's FIN.
	ackRaw2 := ch.Read(time.Second)
	if ackRaw2 == nil {
		t.Fatal("expected ACK for client FIN")
	}
	_, ackHdr2 := parseTCPResponse(t, ackRaw2)
	if !ackHdr2.Flags().Has(header.TCPFlagACK) {
		t.Fatalf("expected ACK flag, got %s", ackHdr2.Flags())
	}
	if ackHdr2.AckNumber() != clientSeq+1 {
		t.Errorf("ACK for FIN: AckNum = %d, want %d", ackHdr2.AckNumber(), clientSeq+1)
	}

	// Server is now in TIME_WAIT. Wait for it to expire.
	time.Sleep(200 * time.Millisecond)

	// Connection should be removed from table.
	if n := tcp.ConnTableLen(h); n != 0 {
		t.Errorf("connTable has %d entries, want 0 after TIME_WAIT", n)
	}
}

func TestForceClosePreventsWritesAfterReturn(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50199)
	serverPort := uint16(80)
	clientISN := uint32(5500)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	if err := conn.ForceClose(); err != nil {
		t.Fatalf("ForceClose error: %v", err)
	}
	n, err := conn.Write([]byte("after close"))
	if err == nil {
		t.Fatalf("Write after ForceClose returned n=%d, err=nil", n)
	}
}

// TestGracefulClose_PeerInitiated tests peer-initiated close:
// peer sends FIN → Read returns EOF → app calls Close() → LAST_ACK → CLOSED.
func TestGracefulClose_PeerInitiated(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50101)
	serverPort := uint16(80)
	clientISN := uint32(6000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	clientSeq := clientISN + 1

	// Client sends FIN (peer-initiated close).
	clientFIN := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagFIN|header.TCPFlagACK, clientSeq, serverISN+1)
	ch.Inject(clientFIN)

	// Server should ACK the FIN.
	ackRaw := ch.Read(time.Second)
	if ackRaw == nil {
		t.Fatal("expected ACK for peer FIN")
	}
	_, ackHdr := parseTCPResponse(t, ackRaw)
	if !ackHdr.Flags().Has(header.TCPFlagACK) {
		t.Fatalf("expected ACK, got %s", ackHdr.Flags())
	}
	if ackHdr.AckNumber() != clientSeq+1 {
		t.Errorf("ACK AckNum = %d, want %d", ackHdr.AckNumber(), clientSeq+1)
	}

	// Read should return EOF.
	buf := make([]byte, 256)
	_, err := conn.Read(buf)
	if err != io.EOF {
		t.Fatalf("Read err = %v; want io.EOF", err)
	}

	// Server should be in CLOSE_WAIT.
	if state := tcp.ConnState(conn); state != "CLOSE_WAIT" {
		t.Fatalf("state = %s; want CLOSE_WAIT", state)
	}

	// App calls Close() → sends FIN → LAST_ACK.
	conn.Close()

	// Should receive FIN+ACK from server.
	finRaw := ch.Read(time.Second)
	if finRaw == nil {
		t.Fatal("expected FIN from server after Close()")
	}
	_, finHdr := parseTCPResponse(t, finRaw)
	if !finHdr.Flags().Has(header.TCPFlagFIN) {
		t.Fatalf("expected FIN flag, got %s", finHdr.Flags())
	}
	serverFINSeq := finHdr.SequenceNumber()

	// Client ACKs server's FIN → CLOSED.
	finalAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq+1, serverFINSeq+1)
	ch.Inject(finalAck)

	// Give time for processing.
	time.Sleep(100 * time.Millisecond)

	// Connection should be removed from table.
	if n := tcp.ConnTableLen(h); n != 0 {
		t.Errorf("connTable has %d entries, want 0 after LAST_ACK→CLOSED", n)
	}
}

// TestGracefulClose_TimeWaitExpiry tests that TIME_WAIT expires and connection
// is removed from the connTable.
func TestGracefulClose_TimeWaitExpiry(t *testing.T) {
	ch, s, h := setupStack(t, tcp.WithTimeWaitDuration(100*time.Millisecond))
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50102)
	serverPort := uint16(80)
	clientISN := uint32(7000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	clientSeq := clientISN + 1

	// Server initiates close.
	conn.Close()

	// Read FIN from server.
	finRaw := ch.Read(time.Second)
	if finRaw == nil {
		t.Fatal("expected FIN")
	}
	_, finHdr := parseTCPResponse(t, finRaw)
	serverFINSeq := finHdr.SequenceNumber()

	// Client ACKs FIN → server enters FIN_WAIT_2.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverFINSeq+1)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond)

	// Client sends FIN → server enters TIME_WAIT.
	clientFIN := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagFIN|header.TCPFlagACK, clientSeq, serverFINSeq+1)
	ch.Inject(clientFIN)

	// Drain ACK for client FIN.
	ch.Read(time.Second)

	// Connection should still be in connTable (TIME_WAIT).
	time.Sleep(20 * time.Millisecond)
	if n := tcp.ConnTableLen(h); n != 1 {
		t.Errorf("connTable = %d during TIME_WAIT, want 1", n)
	}

	// Wait for TIME_WAIT to expire (100ms + buffer).
	time.Sleep(200 * time.Millisecond)

	// Connection should now be removed.
	if n := tcp.ConnTableLen(h); n != 0 {
		t.Errorf("connTable = %d after TIME_WAIT, want 0", n)
	}

	done := make(chan struct{})
	go func() {
		_ = conn.ForceClose()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("ForceClose blocked after TIME_WAIT expiry")
	}

	_ = serverISN
}

// TestGracefulClose_NoGoroutineLeak tests that no goroutines leak after
// close + TIME_WAIT expiration.
func TestGracefulClose_NoGoroutineLeak(t *testing.T) {
	// Stabilize goroutine count.
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	ch := channel.NewMemory(1500)
	s := stack.New(ch)
	h := tcp.NewTCPHandler(s, tcp.WithTimeWaitDuration(50*time.Millisecond))
	s.RegisterHandler(tcpip.TCPProtocolNumber, h)
	s.Start()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50103)
	serverPort := uint16(80)
	clientISN := uint32(8000)

	// Complete handshake.
	syn := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagSYN, clientISN, 0)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK")
	}
	_, sa := parseTCPResponse(t, raw)
	serverISN := sa.SequenceNumber()

	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1)
	ch.Inject(ack)

	// Accept.
	done := make(chan *tcp.TCPConn, 1)
	go func() {
		conn, _ := h.Listener().Accept()
		done <- conn
	}()

	var conn *tcp.TCPConn
	select {
	case conn = <-done:
	case <-time.After(time.Second):
		t.Fatal("Accept timed out")
	}

	clientSeq := clientISN + 1

	// Server Close → FIN.
	conn.Close()
	finRaw := ch.Read(time.Second)
	if finRaw == nil {
		t.Fatal("expected FIN")
	}
	_, finHdr := parseTCPResponse(t, finRaw)
	serverFINSeq := finHdr.SequenceNumber()

	// Client ACKs FIN.
	finAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverFINSeq+1)
	ch.Inject(finAck)
	time.Sleep(50 * time.Millisecond)

	// Client sends FIN.
	clientFIN := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagFIN|header.TCPFlagACK, clientSeq, serverFINSeq+1)
	ch.Inject(clientFIN)
	ch.Read(time.Second) // drain ACK

	// Wait for TIME_WAIT to expire.
	time.Sleep(200 * time.Millisecond)

	// Shut down.
	h.Close()
	s.Stop()

	// Check goroutine count.
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()

	if after > before+1 {
		t.Errorf("goroutine leak: before=%d, after=%d", before, after)
	}
}

// TestGracefulClose_WriteAfterClose verifies that Write() returns an error
// after Close() has been called.
func TestGracefulClose_WriteAfterClose(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50104)
	serverPort := uint16(80)
	clientISN := uint32(9000)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	conn.Close()

	// Drain FIN.
	ch.Read(time.Second)

	// Write should fail.
	_, err := conn.Write([]byte("should fail"))
	if err == nil {
		t.Fatal("Write after Close should return error")
	}
}

// TestGracefulClose_FINRetransmission verifies that FIN is retransmitted
// when not acknowledged within the RTO.
func TestGracefulClose_FINRetransmission(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50105)
	serverPort := uint16(80)
	clientISN := uint32(10000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)
	_ = serverISN

	conn.Close()

	// Read first FIN.
	fin1 := ch.Read(time.Second)
	if fin1 == nil {
		t.Fatal("expected FIN")
	}
	_, finHdr1 := parseTCPResponse(t, fin1)
	if !finHdr1.Flags().Has(header.TCPFlagFIN) {
		t.Fatalf("expected FIN flag, got %s", finHdr1.Flags())
	}

	// Don't ACK it — wait for retransmission.
	fin2 := ch.Read(2 * time.Second)
	if fin2 == nil {
		t.Fatal("expected retransmitted FIN")
	}
	_, finHdr2 := parseTCPResponse(t, fin2)
	if !finHdr2.Flags().Has(header.TCPFlagFIN) {
		t.Fatalf("expected FIN flag on retransmit, got %s", finHdr2.Flags())
	}

	// Sequence number should be the same.
	if finHdr2.SequenceNumber() != finHdr1.SequenceNumber() {
		t.Errorf("retransmitted FIN seq = %d, want %d", finHdr2.SequenceNumber(), finHdr1.SequenceNumber())
	}
}

// --- Tests ported from gVisor ---

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestFinImmediately (line 4289)
//
// Closing immediately after connection establishment should send FIN+ACK.
// Peer responds with FIN+ACK, and the stack sends a final ACK.
func TestFinImmediately(t *testing.T) {
	ch, s, h := setupStack(t, tcp.WithTimeWaitDuration(100*time.Millisecond))
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Close immediately — should get a FIN+ACK.
	conn.Close()

	clientSeq := clientISN + 1
	v := ch.Read(time.Second)
	if v == nil {
		t.Fatal("expected FIN+ACK")
	}
	_, finHdr := parseTCPResponse(t, v)

	if !finHdr.Flags().Has(header.TCPFlagFIN | header.TCPFlagACK) {
		t.Fatalf("expected FIN|ACK flags, got %s", finHdr.Flags())
	}
	if finHdr.SequenceNumber() != serverISN+1 {
		t.Errorf("FIN SeqNum = %d, want %d", finHdr.SequenceNumber(), serverISN+1)
	}
	if finHdr.AckNumber() != clientSeq {
		t.Errorf("FIN AckNum = %d, want %d", finHdr.AckNumber(), clientSeq)
	}

	// Peer ACKs FIN and sends its own FIN.
	finAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK|header.TCPFlagFIN, clientSeq, serverISN+2)
	ch.Inject(finAck)

	// Stack should ACK the peer's FIN.
	v2 := ch.Read(time.Second)
	if v2 == nil {
		t.Fatal("expected ACK for peer FIN")
	}
	_, ackHdr := parseTCPResponse(t, v2)
	if ackHdr.Flags() != header.TCPFlagACK {
		t.Errorf("expected pure ACK, got %s", ackHdr.Flags())
	}
	if ackHdr.SequenceNumber() != serverISN+2 {
		t.Errorf("ACK SeqNum = %d, want %d", ackHdr.SequenceNumber(), serverISN+2)
	}
	if ackHdr.AckNumber() != clientSeq+1 {
		t.Errorf("ACK AckNum = %d, want %d", ackHdr.AckNumber(), clientSeq+1)
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestFinRetransmit (line 4337)
//
// FIN+ACK should be retransmitted when not acknowledged. After retransmit,
// peer FIN+ACK completes the close.
func TestFinRetransmit(t *testing.T) {
	ch, s, h := setupStack(t, tcp.WithTimeWaitDuration(100*time.Millisecond))
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Close — should get FIN+ACK.
	conn.Close()

	clientSeq := clientISN + 1
	v := ch.Read(time.Second)
	if v == nil {
		t.Fatal("expected FIN+ACK")
	}
	_, finHdr := parseTCPResponse(t, v)
	if !finHdr.Flags().Has(header.TCPFlagFIN | header.TCPFlagACK) {
		t.Fatalf("expected FIN|ACK, got %s", finHdr.Flags())
	}
	if finHdr.SequenceNumber() != serverISN+1 {
		t.Errorf("FIN SeqNum = %d, want %d", finHdr.SequenceNumber(), serverISN+1)
	}

	// Don't ACK — wait for retransmitted FIN.
	v2 := ch.Read(2 * time.Second)
	if v2 == nil {
		t.Fatal("expected retransmitted FIN+ACK")
	}
	_, finHdr2 := parseTCPResponse(t, v2)
	if !finHdr2.Flags().Has(header.TCPFlagFIN | header.TCPFlagACK) {
		t.Fatalf("expected FIN|ACK on retransmit, got %s", finHdr2.Flags())
	}
	if finHdr2.SequenceNumber() != serverISN+1 {
		t.Errorf("retransmitted FIN SeqNum = %d, want %d", finHdr2.SequenceNumber(), serverISN+1)
	}

	// Now ACK and send FIN.
	finAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK|header.TCPFlagFIN, clientSeq, serverISN+2)
	ch.Inject(finAck)

	// Stack ACKs the peer FIN.
	v3 := ch.Read(time.Second)
	if v3 == nil {
		t.Fatal("expected ACK for peer FIN")
	}
	_, ackHdr := parseTCPResponse(t, v3)
	if ackHdr.Flags() != header.TCPFlagACK {
		t.Errorf("expected pure ACK, got %s", ackHdr.Flags())
	}
	if ackHdr.SequenceNumber() != serverISN+2 {
		t.Errorf("ACK SeqNum = %d, want %d", ackHdr.SequenceNumber(), serverISN+2)
	}
	if ackHdr.AckNumber() != clientSeq+1 {
		t.Errorf("ACK AckNum = %d, want %d", ackHdr.AckNumber(), clientSeq+1)
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestFinWithNoPendingData (line 4399)
//
// Writing data, having it acknowledged, then closing should produce a FIN
// with sequence number immediately following the data.
func TestFinWithNoPendingData(t *testing.T) {
	ch, s, h := setupStack(t, tcp.WithTimeWaitDuration(100*time.Millisecond))
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	clientSeq := clientISN + 1

	// Server writes 10 bytes.
	data := make([]byte, 10)
	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	// Read data segment from wire.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	payload := raw[header.IPv4MinHeaderSize+dataHdr.DataOffset():]
	next := dataHdr.SequenceNumber() + uint32(len(payload))

	if dataHdr.SequenceNumber() != serverISN+1 {
		t.Errorf("data SeqNum = %d, want %d", dataHdr.SequenceNumber(), serverISN+1)
	}

	// ACK the data.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, next)
	ch.Inject(ack)
	wg.Wait()

	// Close — FIN should have SeqNum = next (right after data).
	conn.Close()

	v := ch.Read(time.Second)
	if v == nil {
		t.Fatal("expected FIN+ACK")
	}
	_, finHdr := parseTCPResponse(t, v)
	if !finHdr.Flags().Has(header.TCPFlagFIN | header.TCPFlagACK) {
		t.Fatalf("expected FIN|ACK, got %s", finHdr.Flags())
	}
	if finHdr.SequenceNumber() != next {
		t.Errorf("FIN SeqNum = %d, want %d (right after data)", finHdr.SequenceNumber(), next)
	}

	// Peer ACKs FIN and sends FIN.
	finAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK|header.TCPFlagFIN, clientSeq, next+1)
	ch.Inject(finAck)

	// Stack ACKs peer FIN.
	v2 := ch.Read(time.Second)
	if v2 == nil {
		t.Fatal("expected ACK for peer FIN")
	}
	_, ackHdr := parseTCPResponse(t, v2)
	if ackHdr.Flags() != header.TCPFlagACK {
		t.Errorf("expected pure ACK, got %s", ackHdr.Flags())
	}
	if ackHdr.AckNumber() != clientSeq+1 {
		t.Errorf("ACK AckNum = %d, want %d", ackHdr.AckNumber(), clientSeq+1)
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestFinWithPendingData (line 4578)
//
// Writing data, ACKing it (opening cwnd), writing more data (unacked), then
// closing should send the pending data followed by a FIN.
func TestFinWithPendingData(t *testing.T) {
	ch, s, h := setupStack(t, tcp.WithTimeWaitDuration(100*time.Millisecond))
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	clientSeq := clientISN + 1

	// Write 10 bytes and have them acknowledged.
	data1 := make([]byte, 10)
	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data1)
	})

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment 1")
	}
	_, hdr1 := parseTCPResponse(t, raw)
	next := hdr1.SequenceNumber() + uint32(len(data1))

	if hdr1.SequenceNumber() != serverISN+1 {
		t.Errorf("data1 SeqNum = %d, want %d", hdr1.SequenceNumber(), serverISN+1)
	}

	// ACK first data (opens cwnd for more).
	ack1 := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, next)
	ch.Inject(ack1)
	wg.Wait()

	// Write 10 more bytes — don't ACK.
	data2 := make([]byte, 10)
	wg.Go(func() {
		conn.Write(data2)
	})

	raw2 := ch.Read(time.Second)
	if raw2 == nil {
		t.Fatal("expected data segment 2")
	}
	_, hdr2 := parseTCPResponse(t, raw2)
	if hdr2.SequenceNumber() != next {
		t.Errorf("data2 SeqNum = %d, want %d", hdr2.SequenceNumber(), next)
	}
	next += uint32(len(data2))
	wg.Wait()

	// Close — FIN should be sent after the pending data.
	conn.Close()

	v := ch.Read(time.Second)
	if v == nil {
		t.Fatal("expected FIN+ACK after pending data")
	}
	_, finHdr := parseTCPResponse(t, v)
	if !finHdr.Flags().Has(header.TCPFlagFIN | header.TCPFlagACK) {
		t.Fatalf("expected FIN|ACK, got %s", finHdr.Flags())
	}
	if finHdr.SequenceNumber() != next {
		t.Errorf("FIN SeqNum = %d, want %d", finHdr.SequenceNumber(), next)
	}

	// Peer ACKs everything and sends FIN.
	finAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK|header.TCPFlagFIN, clientSeq, next+1)
	ch.Inject(finAck)

	// Stack ACKs peer FIN.
	v2 := ch.Read(time.Second)
	if v2 == nil {
		t.Fatal("expected ACK for peer FIN")
	}
	_, ackHdr := parseTCPResponse(t, v2)
	if ackHdr.AckNumber() != clientSeq+1 {
		t.Errorf("ACK AckNum = %d, want %d", ackHdr.AckNumber(), clientSeq+1)
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestFinWithPartialAck (line 4676)
//
// Peer sends FIN (half-close), server writes data and then closes. A partial
// ACK covering only the data (not the FIN) should not trigger a FIN retransmit.
func TestFinWithPartialAck(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	clientSeq := clientISN + 1

	// Server writes 10 bytes and gets ACK.
	data1 := make([]byte, 10)
	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data1)
	})

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment")
	}
	_, hdr1 := parseTCPResponse(t, raw)
	next := hdr1.SequenceNumber() + uint32(len(data1))

	// ACK data + send FIN from peer (half-close).
	finAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK|header.TCPFlagFIN, clientSeq, next)
	ch.Inject(finAck)
	wg.Wait()

	// Stack should ACK the peer's FIN.
	ackRaw := ch.Read(time.Second)
	if ackRaw == nil {
		t.Fatal("expected ACK for peer FIN")
	}
	_, ackHdr := parseTCPResponse(t, ackRaw)
	if ackHdr.AckNumber() != clientSeq+1 {
		t.Errorf("ACK for FIN: AckNum = %d, want %d", ackHdr.AckNumber(), clientSeq+1)
	}

	// Server is now in CLOSE_WAIT. Write more data.
	data2 := make([]byte, 10)
	wg.Go(func() {
		conn.Write(data2)
	})

	raw2 := ch.Read(time.Second)
	if raw2 == nil {
		t.Fatal("expected data segment in CLOSE_WAIT")
	}
	_, hdr2 := parseTCPResponse(t, raw2)
	if hdr2.SequenceNumber() != next {
		t.Errorf("data2 SeqNum = %d, want %d", hdr2.SequenceNumber(), next)
	}
	next += uint32(len(data2))
	wg.Wait()

	// Server calls Close() → sends FIN (LAST_ACK).
	conn.Close()

	finRaw := ch.Read(time.Second)
	if finRaw == nil {
		t.Fatal("expected FIN after Close() in CLOSE_WAIT")
	}
	_, finHdr := parseTCPResponse(t, finRaw)
	if !finHdr.Flags().Has(header.TCPFlagFIN | header.TCPFlagACK) {
		t.Fatalf("expected FIN|ACK, got %s", finHdr.Flags())
	}
	if finHdr.SequenceNumber() != next {
		t.Errorf("FIN SeqNum = %d, want %d", finHdr.SequenceNumber(), next)
	}

	// Send partial ACK for data only (not FIN).
	partialAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq+1, next)
	ch.Inject(partialAck)

	// Should NOT get a retransmit of the FIN.
	noRetransmit := ch.Read(200 * time.Millisecond)
	if noRetransmit != nil {
		_, extraHdr := parseTCPResponse(t, noRetransmit)
		t.Errorf("unexpected packet after partial ACK: flags=%s seq=%d",
			extraHdr.Flags(), extraHdr.SequenceNumber())
	}

	// Now ACK the FIN.
	fullAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq+1, next+1)
	ch.Inject(fullAck)

	// Give time for CLOSED transition.
	time.Sleep(100 * time.Millisecond)

	// Connection should be removed.
	if n := tcp.ConnTableLen(h); n != 0 {
		t.Errorf("connTable = %d, want 0 after LAST_ACK→CLOSED", n)
	}

	_ = serverISN
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestTCPTimeWaitRSTIgnored (line 7505)
//
// RST received in TIME_WAIT should be silently ignored (RFC 1337).
// An out-of-order ACK in TIME_WAIT should generate an immediate ACK.
func TestTCPTimeWaitRSTIgnored(t *testing.T) {
	ch, s, h := setupStack(t, tcp.WithTimeWaitDuration(2*time.Second))
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	clientSeq := clientISN + 1

	// Server Close → FIN+ACK.
	conn.Close()

	v := ch.Read(time.Second)
	if v == nil {
		t.Fatal("expected FIN+ACK")
	}
	_, finHdr := parseTCPResponse(t, v)
	if !finHdr.Flags().Has(header.TCPFlagFIN | header.TCPFlagACK) {
		t.Fatalf("expected FIN|ACK, got %s", finHdr.Flags())
	}

	// Peer ACKs FIN and sends FIN → server enters TIME_WAIT.
	finAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK|header.TCPFlagFIN, clientSeq, serverISN+2)
	ch.Inject(finAck)

	// Get ACK for peer FIN.
	v2 := ch.Read(time.Second)
	if v2 == nil {
		t.Fatal("expected ACK for peer FIN")
	}
	_, ackHdr := parseTCPResponse(t, v2)
	if ackHdr.SequenceNumber() != serverISN+2 {
		t.Errorf("ACK SeqNum = %d, want %d", ackHdr.SequenceNumber(), serverISN+2)
	}
	if ackHdr.AckNumber() != clientSeq+1 {
		t.Errorf("ACK AckNum = %d, want %d", ackHdr.AckNumber(), clientSeq+1)
	}

	// Now send RST in TIME_WAIT — should be silently ignored.
	rst := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagRST, clientSeq, serverISN+2)
	ch.Inject(rst)

	noResp := ch.Read(300 * time.Millisecond)
	if noResp != nil {
		_, hdr := parseTCPResponse(t, noResp)
		t.Errorf("unexpected response to RST in TIME_WAIT: flags=%s", hdr.Flags())
	}

	// Connection should still be in connTable (not killed by RST).
	if n := tcp.ConnTableLen(h); n != 1 {
		t.Errorf("connTable = %d after RST in TIME_WAIT, want 1 (RST should be ignored)", n)
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestTCPTimeWaitDuplicateFINExtendsTimeWait (line 7909)
//
// A duplicate FIN received in TIME_WAIT should re-ACK it and extend the
// TIME_WAIT timer. The connection should remain in TIME_WAIT past the
// original timer, only closing after the extended duration.
func TestTCPTimeWaitDuplicateFINExtendsTimeWait(t *testing.T) {
	ch, s, h := setupStack(t, tcp.WithTimeWaitDuration(300*time.Millisecond))
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	clientSeq := clientISN + 1

	// Server Close → FIN.
	conn.Close()
	v := ch.Read(time.Second)
	if v == nil {
		t.Fatal("expected FIN")
	}

	// Peer FIN+ACK → server enters TIME_WAIT.
	finAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK|header.TCPFlagFIN, clientSeq, serverISN+2)
	ch.Inject(finAck)

	// Drain ACK for peer FIN.
	ch.Read(time.Second)

	// Wait 150ms (half of 300ms TIME_WAIT).
	time.Sleep(150 * time.Millisecond)

	// Send duplicate FIN — should extend TIME_WAIT and get re-ACK.
	ch.Inject(finAck)

	reAck := ch.Read(time.Second)
	if reAck == nil {
		t.Fatal("expected re-ACK for duplicate FIN in TIME_WAIT")
	}
	_, reAckHdr := parseTCPResponse(t, reAck)
	if reAckHdr.Flags() != header.TCPFlagACK {
		t.Errorf("expected pure ACK for dup FIN, got %s", reAckHdr.Flags())
	}
	if reAckHdr.AckNumber() != clientSeq+1 {
		t.Errorf("re-ACK AckNum = %d, want %d", reAckHdr.AckNumber(), clientSeq+1)
	}

	// Wait 200ms more. At this point we are 350ms past the original TIME_WAIT
	// start (>300ms). Without the extension, conn would be gone.
	time.Sleep(200 * time.Millisecond)

	// Connection should STILL be in TIME_WAIT because the dup FIN reset the timer.
	if n := tcp.ConnTableLen(h); n != 1 {
		t.Errorf("connTable = %d, want 1 (TIME_WAIT should have been extended by dup FIN)", n)
	}

	// Wait for the extended TIME_WAIT to expire (another 200ms should be enough
	// since the timer was reset at 150ms → expires at 150+300=450ms from start;
	// we're now at ~350ms, so ~100ms more + buffer).
	time.Sleep(200 * time.Millisecond)

	if n := tcp.ConnTableLen(h); n != 0 {
		t.Errorf("connTable = %d, want 0 after extended TIME_WAIT", n)
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestTCPCloseWithData (line 8069)
//
// Peer initiates half-close (sends FIN), server writes data in CLOSE_WAIT,
// then closes. Verifies data and FIN are sent correctly, and partial + full
// ACKs are handled.
func TestTCPCloseWithData(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	clientSeq := clientISN + 1

	// Peer sends FIN (passive close triggers CLOSE_WAIT).
	peerFIN := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK|header.TCPFlagFIN, clientSeq, serverISN+1)
	ch.Inject(peerFIN)

	// Get ACK for peer FIN.
	ackRaw := ch.Read(time.Second)
	if ackRaw == nil {
		t.Fatal("expected ACK for peer FIN")
	}
	_, ackHdr := parseTCPResponse(t, ackRaw)
	if ackHdr.AckNumber() != clientSeq+1 {
		t.Errorf("ACK for FIN: AckNum = %d, want %d", ackHdr.AckNumber(), clientSeq+1)
	}

	// Write data in CLOSE_WAIT.
	data := []byte{1, 2, 3}
	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	// Read the data segment.
	dataRaw := ch.Read(time.Second)
	if dataRaw == nil {
		t.Fatal("expected data segment in CLOSE_WAIT")
	}
	_, dataHdr := parseTCPResponse(t, dataRaw)
	payload := dataRaw[header.IPv4MinHeaderSize+dataHdr.DataOffset():]
	if len(payload) != len(data) {
		t.Fatalf("payload len = %d, want %d", len(payload), len(data))
	}
	for i := range data {
		if payload[i] != data[i] {
			t.Errorf("payload[%d] = %d, want %d", i, payload[i], data[i])
		}
	}
	if dataHdr.SequenceNumber() != serverISN+1 {
		t.Errorf("data SeqNum = %d, want %d", dataHdr.SequenceNumber(), serverISN+1)
	}
	if dataHdr.AckNumber() != clientSeq+1 {
		t.Errorf("data AckNum = %d, want %d (peer FIN ACKed)", dataHdr.AckNumber(), clientSeq+1)
	}
	wg.Wait()

	// Close — sends FIN (CLOSE_WAIT → LAST_ACK).
	conn.Close()

	finRaw := ch.Read(time.Second)
	if finRaw == nil {
		t.Fatal("expected FIN after Close() in CLOSE_WAIT")
	}
	_, finHdr := parseTCPResponse(t, finRaw)
	if !finHdr.Flags().Has(header.TCPFlagFIN | header.TCPFlagACK) {
		t.Fatalf("expected FIN|ACK, got %s", finHdr.Flags())
	}
	finSeq := finHdr.SequenceNumber()
	expectedFINSeq := serverISN + 1 + uint32(len(data))
	if finSeq != expectedFINSeq {
		t.Errorf("FIN SeqNum = %d, want %d (after data)", finSeq, expectedFINSeq)
	}

	// Send partial ACK (covers data but not FIN).
	partialAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq+1, serverISN+1+uint32(len(data)-1))
	ch.Inject(partialAck)

	// Send full ACK (covers all data).
	fullAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq+1, serverISN+1+uint32(len(data)))
	ch.Inject(fullAck)

	// ACK the FIN.
	finAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq+1, finSeq+1)
	ch.Inject(finAck)

	// Give time for CLOSED transition.
	time.Sleep(100 * time.Millisecond)

	if n := tcp.ConnTableLen(h); n != 0 {
		t.Errorf("connTable = %d, want 0 after LAST_ACK→CLOSED", n)
	}
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestReadAfterClosedState (line 5017)
//
// Data received during FIN_WAIT_1 (peer sends data+FIN in response to our FIN)
// should be buffered and readable even after the connection transitions through
// TIME_WAIT to CLOSED.
func TestReadAfterClosedState(t *testing.T) {
	ch, s, h := setupStack(t, tcp.WithTimeWaitDuration(100*time.Millisecond))
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	clientSeq := clientISN + 1

	// Server initiates close.
	conn.Close()

	// Read the FIN+ACK.
	v := ch.Read(time.Second)
	if v == nil {
		t.Fatal("expected FIN+ACK")
	}
	_, finHdr := parseTCPResponse(t, v)
	if !finHdr.Flags().Has(header.TCPFlagFIN) {
		t.Fatalf("expected FIN, got %s", finHdr.Flags())
	}

	// Peer sends data + FIN, acknowledging our FIN.
	data := []byte{1, 2, 3}
	dataFIN := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK|header.TCPFlagFIN, clientSeq, serverISN+2, 30000, data)
	ch.Inject(dataFIN)

	// Stack should ACK the data + FIN.
	ackRaw := ch.Read(time.Second)
	if ackRaw == nil {
		t.Fatal("expected ACK for data+FIN")
	}
	_, ackHdr := parseTCPResponse(t, ackRaw)
	expectedAckNum := clientSeq + uint32(len(data)) + 1 // data + FIN
	if ackHdr.AckNumber() != expectedAckNum {
		t.Errorf("ACK AckNum = %d, want %d (data+FIN)", ackHdr.AckNumber(), expectedAckNum)
	}

	// Wait for TIME_WAIT to expire.
	time.Sleep(200 * time.Millisecond)

	// Data should still be readable even after CLOSED.
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read after TIME_WAIT: err = %v, want nil", err)
	}
	if n != len(data) {
		t.Fatalf("Read = %d bytes, want %d", n, len(data))
	}
	for i := range data {
		if buf[i] != data[i] {
			t.Errorf("data[%d] = %d, want %d", i, buf[i], data[i])
		}
	}

	// Next read should return EOF.
	_, err = conn.Read(buf)
	if err != io.EOF {
		t.Errorf("second Read = %v, want io.EOF", err)
	}

	_ = serverISN
}
