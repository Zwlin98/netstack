package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// TestSimultaneousClose verifies the CLOSING state transition during simultaneous close.
func TestSimultaneousClose(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	restore := tcp.SetTimeWaitDuration(200 * time.Millisecond)
	defer restore()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(56000)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server initiates close (sends FIN).
	conn.Close()
	time.Sleep(50 * time.Millisecond)

	// Read server's FIN.
	var serverFINSeq uint32
	for {
		raw := ch.Read(500 * time.Millisecond)
		if raw == nil {
			break
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		if tcpHdr.Flags().Has(header.TCPFlagFIN) {
			serverFINSeq = tcpHdr.SequenceNumber()
			break
		}
	}

	// Now send client's FIN WITHOUT first ACKing server's FIN.
	// This simulates simultaneous close.
	clientFIN := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagFIN|header.TCPFlagACK, clientISN+1, serverISN+1)
	ch.Inject(clientFIN)
	time.Sleep(50 * time.Millisecond)

	// Server should be in CLOSING state (got peer FIN, own FIN not yet ACKed).
	state := tcp.ConnState(conn)
	if state != "CLOSING" {
		t.Fatalf("state = %s, want CLOSING after simultaneous close", state)
	}

	// Server should have sent ACK for client's FIN.
	drainPackets(ch, 200*time.Millisecond)

	// Now ACK server's FIN → should transition CLOSING → TIME_WAIT.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+2, serverFINSeq+1)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond)

	state = tcp.ConnState(conn)
	if state != "TIME_WAIT" {
		t.Fatalf("state = %s, want TIME_WAIT after CLOSING receives FIN ACK", state)
	}

	// Wait for TIME_WAIT to expire.
	time.Sleep(300 * time.Millisecond)
}
