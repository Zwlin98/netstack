package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

func TestStats_BasicCounters(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	stats := h.EnableStats()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50000)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Verify connection counters after handshake.
	if got := stats.ActiveConns.Load(); got != 1 {
		t.Errorf("ActiveConns = %d, want 1", got)
	}
	if got := stats.TotalAccepted.Load(); got != 1 {
		t.Errorf("TotalAccepted = %d, want 1", got)
	}

	// SegmentsIn: SYN + handshake ACK = 2.
	if got := stats.SegmentsIn.Load(); got < 2 {
		t.Errorf("SegmentsIn = %d, want >= 2", got)
	}

	// SegmentsOut: at least SYN-ACK = 1.
	if got := stats.SegmentsOut.Load(); got < 1 {
		t.Errorf("SegmentsOut = %d, want >= 1", got)
	}

	// Send data segment.
	data := []byte("hello stats")
	pkt := buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535,
		data,
	)
	ch.Inject(pkt)
	ch.Read(time.Second) // drain ACK

	// Wait for conn.run() to process and update stats.
	time.Sleep(50 * time.Millisecond)

	if got := stats.PayloadBytesIn.Load(); got != uint64(len(data)) {
		t.Errorf("PayloadBytesIn = %d, want %d", got, len(data))
	}

	// Read data from conn to verify it was delivered.
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello stats" {
		t.Errorf("Read = %q, want %q", string(buf[:n]), "hello stats")
	}

	// Write data back.
	conn.Write([]byte("reply"))
	resp := ch.Read(time.Second)
	if resp == nil {
		t.Fatal("expected data response")
	}

	if got := stats.PayloadBytesOut.Load(); got < 5 {
		t.Errorf("PayloadBytesOut = %d, want >= 5", got)
	}

	// Close connection.
	conn.ForceClose()
	time.Sleep(50 * time.Millisecond)

	if got := stats.TotalClosed.Load(); got != 1 {
		t.Errorf("TotalClosed = %d, want 1", got)
	}
	if got := stats.ActiveConns.Load(); got != 0 {
		t.Errorf("ActiveConns after close = %d, want 0", got)
	}
}

func TestStats_ChecksumError(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	stats := h.EnableStats()

	// Build a TCP packet with bad checksum.
	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	pkt := buildTCPPacket(clientAddr, serverAddr, 50000, 80, header.TCPFlagSYN, 1000, 0)
	// Corrupt checksum.
	pkt[len(pkt)-1] ^= 0xff

	ch.Inject(pkt)
	time.Sleep(50 * time.Millisecond)

	if got := stats.ChecksumErrors.Load(); got != 1 {
		t.Errorf("ChecksumErrors = %d, want 1", got)
	}
}

func TestStats_ConnSnapshot(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	h.EnableStats()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50000)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	_, _ = completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	snaps := h.ConnSnapshots()
	if len(snaps) != 1 {
		t.Fatalf("ConnSnapshots() returned %d, want 1", len(snaps))
	}

	snap := snaps[0]
	if snap.State != "ESTABLISHED" {
		t.Errorf("State = %s, want ESTABLISHED", snap.State)
	}
	if snap.Flow.SrcAddr != clientAddr || snap.Flow.DstAddr != serverAddr {
		t.Errorf("Flow = %s→%s, want %s→%s", snap.Flow.SrcAddr, snap.Flow.DstAddr, clientAddr, serverAddr)
	}

	// Single-connection snapshot.
	flow := tcp.FlowID{
		SrcAddr: clientAddr,
		DstAddr: serverAddr,
		SrcPort: clientPort,
		DstPort: serverPort,
	}
	single := h.ConnSnapshot(flow)
	if single == nil {
		t.Fatal("ConnSnapshot returned nil for existing flow")
	}
	if single.State != "ESTABLISHED" {
		t.Errorf("single snapshot State = %s, want ESTABLISHED", single.State)
	}

	// Non-existent flow.
	noFlow := tcp.FlowID{SrcAddr: tcpip.From4(1, 1, 1, 1)}
	if h.ConnSnapshot(noFlow) != nil {
		t.Error("ConnSnapshot should return nil for unknown flow")
	}
}
