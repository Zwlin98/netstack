package tcp_test

import (
	"testing"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// TestInitialWindowStandardMSS verifies IW=10 for standard 1500 MTU.
// MSS = 1500 - 20 - 20 = 1460. IW = min(10*1460, max(2*1460, 14600)) = 14600.
func TestInitialWindowStandardMSS(t *testing.T) {
	ch, s, h := setupStack(t) // MTU=1500
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	// Use completeHandshakeWithMSS to include MSS option in SYN.
	_, conn := completeHandshakeWithMSS(t, ch, h, clientAddr, serverAddr, 55000, 80, 1000, 1460)

	cwnd := tcp.SenderCwnd(conn)
	mss := tcp.SenderMSS(conn)

	if mss != 1460 {
		t.Fatalf("MSS = %d, want 1460", mss)
	}
	// IW = min(10*1460, max(2*1460, 14600)) = min(14600, 14600) = 14600
	if cwnd != 14600 {
		t.Fatalf("initial cwnd = %d, want 14600 (10*MSS)", cwnd)
	}
	conn.ForceClose()
}

// TestInitialWindowSmallMTU verifies IW=10 with small MTU (MSS=32).
// IW = min(10*32, max(2*32, 14600)) = min(320, 14600) = 320.
func TestInitialWindowSmallMTU(t *testing.T) {
	mtu := header.IPv4MinHeaderSize + header.TCPMinHeaderSize + 32
	ch, s, h := setupStackWithMTU(t, mtu)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, 55001, 80, 2000)

	cwnd := tcp.SenderCwnd(conn)
	mss := tcp.SenderMSS(conn)

	if mss != 32 {
		t.Fatalf("MSS = %d, want 32", mss)
	}
	// IW = min(10*32, max(2*32, 14600)) = min(320, 14600) = 320
	if cwnd != 320 {
		t.Fatalf("initial cwnd = %d, want 320 (10*32)", cwnd)
	}
	conn.ForceClose()
}
