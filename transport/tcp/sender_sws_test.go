package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// TestSenderSWS_SmallWindowSuppresses verifies that the sender does not
// transmit data when the effective window is below min(MSS, maxWnd/2)
// and more data is pending than fits in the window.
func TestSenderSWS_SmallWindowSuppresses(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50001)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server writes data.
	data := make([]byte, 500)
	go func() { conn.Write(data) }()

	// Read the data segment quickly.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	dataEnd := dataHdr.SequenceNumber() + uint32(len(data))

	// ACK all data with a tiny window.
	tinyWnd := uint16(100)
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, dataEnd, tinyWnd, nil)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond)

	// Now write more data that exceeds the tiny window.
	go func() { conn.Write(make([]byte, 5000)) }()
	time.Sleep(50 * time.Millisecond)

	// The sender should NOT send data because 100 < min(MSS=536, maxWnd/2=32767).
	raw = ch.Read(200 * time.Millisecond)
	if raw != nil {
		_, hdr := parseTCPResponse(t, raw)
		payloadLen := len(raw) - int(header.IPv4(raw).HeaderLength()) - int(hdr.DataOffset())
		if payloadLen > 0 {
			t.Errorf("sender should suppress data with tiny window, but sent %d bytes", payloadLen)
		}
	}
	_ = serverISN
}

// TestSenderSWS_AllDataFitsOverride verifies that when all remaining data
// fits in the small window, the sender sends it anyway.
func TestSenderSWS_AllDataFitsOverride(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50002)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server writes initial data.
	data := make([]byte, 100)
	go func() { conn.Write(data) }()

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected initial data segment")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	dataEnd := dataHdr.SequenceNumber() + uint32(len(data))

	// ACK all data and advertise a tiny window (50 bytes).
	tinyWnd := uint16(50)
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, dataEnd, tinyWnd, nil)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond)

	// Now write small data that fits in the tiny window.
	go func() { conn.Write([]byte("ok")) }()

	// The sender should send because all data (2 bytes) fits in the window (50 bytes).
	raw = ch.Read(time.Second)
	if raw == nil {
		t.Fatal("sender should send when all data fits, even with small window")
	}
	_, hdr := parseTCPResponse(t, raw)
	payloadLen := len(raw) - int(header.IPv4(raw).HeaderLength()) - int(hdr.DataOffset())
	if payloadLen == 0 {
		t.Error("expected non-zero payload when all data fits in window")
	}
	_ = serverISN
}

// TestSenderSWS_MaxWndTracking verifies that maxWnd only tracks the maximum
// and is not reduced when the peer shrinks its window.
func TestSenderSWS_MaxWndTracking(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50003)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Initial maxWnd should be based on handshake SYN window (65535 unscaled).
	initialMaxWnd := tcp.SenderMaxWnd(conn)
	if initialMaxWnd == 0 {
		t.Fatal("maxWnd should be initialized from handshake")
	}

	// Send an ACK with a large window (same as handshake, just confirms tracking).
	largeWnd := uint16(65535)
	ack1 := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, largeWnd, nil)
	ch.Inject(ack1)
	time.Sleep(50 * time.Millisecond)

	maxWndAfterLarge := tcp.SenderMaxWnd(conn)

	// Send an ACK with a smaller window.
	smallWnd := uint16(1000)
	ack2 := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, smallWnd, nil)
	ch.Inject(ack2)
	time.Sleep(50 * time.Millisecond)

	maxWndAfterSmall := tcp.SenderMaxWnd(conn)

	// maxWnd should not decrease.
	if maxWndAfterSmall < maxWndAfterLarge {
		t.Errorf("maxWnd decreased from %d to %d", maxWndAfterLarge, maxWndAfterSmall)
	}
}

// TestSenderSWS_ZWPBypass verifies that zero-window probes bypass the
// sender SWS avoidance check.
func TestSenderSWS_ZWPBypass(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50004)
	serverPort := uint16(80)
	clientISN := uint32(4000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Write data so there's something to send.
	go func() { conn.Write(make([]byte, 500)) }()

	// Read the initial data segment.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	dataEnd := dataHdr.SequenceNumber() + 500

	// ACK all data with zero window.
	zeroWnd := uint16(0)
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, dataEnd, zeroWnd, nil)
	ch.Inject(ack)

	// Write more data — sender should buffer it and eventually probe.
	go func() { conn.Write([]byte("probe-me")) }()

	// Wait for zero-window probe (should arrive within ~2 seconds).
	raw = ch.Read(3 * time.Second)
	if raw == nil {
		t.Fatal("expected zero-window probe, got nil — SWS may have blocked it")
	}
	_, probeHdr := parseTCPResponse(t, raw)
	payloadLen := len(raw) - int(header.IPv4(raw).HeaderLength()) - int(probeHdr.DataOffset())
	if payloadLen == 0 {
		t.Error("expected 1-byte zero-window probe payload")
	}
	_ = serverISN
}
