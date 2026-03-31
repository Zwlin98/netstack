package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// completeHandshakeWithMSS performs a handshake with a SYN that includes an MSS option.
func completeHandshakeWithMSS(t *testing.T, ch *channel.MemoryChannel, h *tcp.TCPHandler,
	clientAddr, serverAddr tcpip.Address, clientPort, serverPort uint16, clientISN uint32,
	mss uint16,
) (serverISN uint32, conn *tcp.TCPConn) {
	t.Helper()

	// Build SYN with MSS option.
	var opts []byte
	buf := make([]byte, 4)
	n := header.EncodeMSSOption(buf, mss)
	opts = buf[:n]

	syn := buildTCPPacketWithOptions(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagSYN, clientISN, 0, opts)
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

// TestMSSNegotiation_PeerSmallerMSS verifies that when the peer advertises
// MSS=512 (smaller than local), segments are constrained to 512 bytes.
func TestMSSNegotiation_PeerSmallerMSS(t *testing.T) {
	ch, s, h := setupStack(t) // MTU=1500, local MSS=1460
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50020)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshakeWithMSS(t, ch, h, clientAddr, serverAddr,
		clientPort, serverPort, clientISN, 512)

	// Write more data than MSS to force segmentation.
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	go conn.Write(data)

	// Read first segment — should be at most 512 bytes.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment, got nil")
	}
	_, tcpHdr := parseTCPResponse(t, raw)
	dataLen := len(raw) - int(header.IPv4(raw).HeaderLength()) - int(tcpHdr.DataOffset())
	if dataLen > 512 {
		t.Errorf("first segment data = %d bytes, want <= 512 (peer MSS)", dataLen)
	}

	// ACK and read next segment.
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+uint32(dataLen), 65535, nil)
	ch.Inject(ack)

	raw2 := ch.Read(time.Second)
	if raw2 == nil {
		t.Fatal("expected second data segment, got nil")
	}
	_, tcpHdr2 := parseTCPResponse(t, raw2)
	dataLen2 := len(raw2) - int(header.IPv4(raw2).HeaderLength()) - int(tcpHdr2.DataOffset())
	if dataLen2 > 512 {
		t.Errorf("second segment data = %d bytes, want <= 512 (peer MSS)", dataLen2)
	}
}

// TestMSSNegotiation_PeerAbsentDefaultsTo536 verifies that when the peer
// omits the MSS option, the sender defaults to min(local, 536).
func TestMSSNegotiation_PeerAbsentDefaultsTo536(t *testing.T) {
	ch, s, h := setupStack(t) // MTU=1500, local MSS=1460
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50021)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	// Plain SYN without MSS option.
	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr,
		clientPort, serverPort, clientISN)

	// Write more data than 536 to force segmentation.
	data := make([]byte, 800)
	for i := range data {
		data[i] = byte(i % 256)
	}
	go conn.Write(data)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment, got nil")
	}
	_, tcpHdr := parseTCPResponse(t, raw)
	dataLen := len(raw) - int(header.IPv4(raw).HeaderLength()) - int(tcpHdr.DataOffset())
	if dataLen > 536 {
		t.Errorf("segment data = %d bytes, want <= 536 (default peer MSS)", dataLen)
	}
	_ = serverISN
}

// TestMSSNegotiation_PeerLargerUsesLocal verifies that when the peer
// advertises a larger MSS, the local MSS is used.
func TestMSSNegotiation_PeerLargerUsesLocal(t *testing.T) {
	// Use a small MTU so local MSS is small.
	ch, s, h := setupStackWithMTU(t, 600) // local MSS = 600 - 20 - 20 = 560
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50022)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	// Peer advertises MSS=8960 (much larger than local).
	serverISN, conn := completeHandshakeWithMSS(t, ch, h, clientAddr, serverAddr,
		clientPort, serverPort, clientISN, 8960)

	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	go conn.Write(data)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment, got nil")
	}
	_, tcpHdr := parseTCPResponse(t, raw)
	dataLen := len(raw) - int(header.IPv4(raw).HeaderLength()) - int(tcpHdr.DataOffset())
	localMSS := 600 - header.IPv4MinHeaderSize - header.TCPMinHeaderSize
	if dataLen > localMSS {
		t.Errorf("segment data = %d bytes, want <= %d (local MSS, not peer's 8960)", dataLen, localMSS)
	}
	_ = serverISN
}
