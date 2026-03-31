package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// TestFinWait2Timeout verifies that FIN_WAIT_2 times out when peer doesn't send FIN.
func TestFinWait2Timeout(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	// Use short timeout for test.
	old := tcp.FinWait2Timeout
	tcp.FinWait2Timeout = 500 * time.Millisecond
	defer func() { tcp.FinWait2Timeout = old }()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(57000)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server initiates close.
	conn.Close()
	time.Sleep(50 * time.Millisecond)

	// Read server's FIN.
	var finSeq uint32
	for {
		raw := ch.Read(500 * time.Millisecond)
		if raw == nil {
			t.Fatal("expected FIN from server")
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		if tcpHdr.Flags().Has(header.TCPFlagFIN) {
			finSeq = tcpHdr.SequenceNumber()
			break
		}
	}

	// ACK the FIN → server transitions to FIN_WAIT_2.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, finSeq+1)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond)

	state := tcp.ConnState(conn)
	if state != "FIN_WAIT_2" {
		t.Fatalf("state = %s, want FIN_WAIT_2", state)
	}

	// Don't send client's FIN — wait for timeout.
	time.Sleep(700 * time.Millisecond)

	state = tcp.ConnState(conn)
	if state != "CLOSED" {
		t.Fatalf("state = %s, want CLOSED after FIN_WAIT_2 timeout", state)
	}
}

// TestFinWait2NormalFIN verifies normal FIN arrival before timeout.
func TestFinWait2NormalFIN(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	restore := tcp.SetTimeWaitDuration(200 * time.Millisecond)
	defer restore()

	old := tcp.FinWait2Timeout
	tcp.FinWait2Timeout = 2 * time.Second
	defer func() { tcp.FinWait2Timeout = old }()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(57001)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server initiates close.
	conn.Close()
	time.Sleep(50 * time.Millisecond)

	// Read server's FIN.
	var finSeq uint32
	for {
		raw := ch.Read(500 * time.Millisecond)
		if raw == nil {
			t.Fatal("expected FIN from server")
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		if tcpHdr.Flags().Has(header.TCPFlagFIN) {
			finSeq = tcpHdr.SequenceNumber()
			break
		}
	}

	// ACK server's FIN → FIN_WAIT_2.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, finSeq+1)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond)

	// Send client's FIN before timeout.
	clientFIN := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagFIN|header.TCPFlagACK, clientISN+1, serverISN+2)
	ch.Inject(clientFIN)
	time.Sleep(50 * time.Millisecond)

	state := tcp.ConnState(conn)
	if state != "TIME_WAIT" {
		t.Fatalf("state = %s, want TIME_WAIT after receiving FIN in FIN_WAIT_2", state)
	}

	// Wait for TIME_WAIT.
	time.Sleep(300 * time.Millisecond)
}
