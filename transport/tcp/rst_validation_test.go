package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// TestRSTExactSequenceMatch verifies that RST with seg.seq == rcv.nxt is accepted.
func TestRSTExactSequenceMatch(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(55100)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send RST with seq = clientISN+1 (which is rcv.nxt after handshake).
	rst := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagRST, clientISN+1, 0)
	ch.Inject(rst)
	time.Sleep(50 * time.Millisecond)

	// Connection should be closed.
	state := tcp.ConnState(conn)
	if state != "CLOSED" {
		t.Fatalf("state = %s, want CLOSED after exact-match RST", state)
	}
}

// TestRSTInWindowNotExact verifies that RST within window but not exact
// triggers challenge ACK and does NOT close the connection.
func TestRSTInWindowNotExact(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(55101)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send RST with seq = clientISN+2 (within window but not exact).
	rst := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagRST, clientISN+2, 0)
	ch.Inject(rst)
	time.Sleep(50 * time.Millisecond)

	// Connection should still be ESTABLISHED.
	state := tcp.ConnState(conn)
	if state != "ESTABLISHED" {
		t.Fatalf("state = %s, want ESTABLISHED after in-window non-exact RST", state)
	}

	// Should have received a challenge ACK.
	resp := ch.Read(500 * time.Millisecond)
	if resp == nil {
		t.Fatal("expected challenge ACK in response to in-window RST")
	}
	_, ackHdr := parseTCPResponse(t, resp)
	if !ackHdr.Flags().Has(header.TCPFlagACK) {
		t.Fatalf("expected ACK flags, got %v", ackHdr.Flags())
	}

	conn.ForceClose()
}

// TestRSTOutsideWindow verifies that RST outside the receive window is silently discarded.
func TestRSTOutsideWindow(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(55102)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send RST with seq far outside the window.
	rst := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagRST, clientISN+1+500000, 0)
	ch.Inject(rst)
	time.Sleep(50 * time.Millisecond)

	// Connection should still be ESTABLISHED.
	state := tcp.ConnState(conn)
	if state != "ESTABLISHED" {
		t.Fatalf("state = %s, want ESTABLISHED after out-of-window RST", state)
	}

	// No response expected (silently discarded).
	resp := ch.Read(200 * time.Millisecond)
	if resp != nil {
		t.Fatal("expected no response for out-of-window RST")
	}

	conn.ForceClose()
}
