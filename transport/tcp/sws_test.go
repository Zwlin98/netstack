package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// TestSWS_BufferNearlyFull verifies that when the read buffer is nearly full,
// the advertised window is 0 (Clark's algorithm).
func TestSWS_BufferNearlyFull(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(62001)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, _ := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Fill the read buffer by sending data without reading.
	// Default buffer is 256KB, MSS=536 (no MSS option → default).
	// Send 2 segments at a time to trigger immediate ACK (every-2-segment rule).
	clientSeq := clientISN + 1
	chunkSize := 536
	chunk := make([]byte, chunkSize)

	gotZeroWindow := false
	for i := 0; i < 260; i++ { // ~260 * 536 * 2 > 256KB
		// Send 2 segments to trigger immediate ACK.
		for j := 0; j < 2; j++ {
			pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
				header.TCPFlagACK, clientSeq, serverISN+1, 65535, chunk)
			ch.Inject(pkt)
			clientSeq += uint32(chunkSize)
		}

		// Read ACK(s).
		raw := ch.Read(time.Second)
		if raw == nil {
			break
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		if tcpHdr.WindowSize() == 0 {
			gotZeroWindow = true
			break
		}

		// Drain any extra ACK.
		if extra := ch.Read(50 * time.Millisecond); extra != nil {
			_, eh := parseTCPResponse(t, extra)
			if eh.WindowSize() == 0 {
				gotZeroWindow = true
				break
			}
		}
	}

	if !gotZeroWindow {
		t.Error("expected advertised window to reach 0 when buffer nearly full")
	}
}

// TestSWS_BufferDrainedPastThreshold verifies that after draining past the
// SWS threshold, the window opens to actual free space.
func TestSWS_BufferDrainedPastThreshold(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(62002)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Fill the buffer to get zero window.
	clientSeq := clientISN + 1
	chunkSize := 536
	chunk := make([]byte, chunkSize)
	gotZero := false
	for i := 0; i < 260; i++ {
		for j := 0; j < 2; j++ {
			pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
				header.TCPFlagACK, clientSeq, serverISN+1, 65535, chunk)
			ch.Inject(pkt)
			clientSeq += uint32(chunkSize)
		}
		raw := ch.Read(time.Second)
		if raw == nil {
			break
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		if tcpHdr.WindowSize() == 0 {
			gotZero = true
			break
		}
		if extra := ch.Read(50 * time.Millisecond); extra != nil {
			_, eh := parseTCPResponse(t, extra)
			if eh.WindowSize() == 0 {
				gotZero = true
				break
			}
		}
	}
	if !gotZero {
		t.Fatal("prerequisite: could not fill buffer to get zero window")
	}

	// Now drain enough data by reading from the connection.
	drainBuf := make([]byte, 4096)
	n, err := conn.Read(drainBuf)
	if err != nil || n == 0 {
		t.Fatalf("expected to read data, got n=%d err=%v", n, err)
	}

	// Send a segment to trigger an ACK with the updated window.
	triggerPkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535, []byte("x"))
	ch.Inject(triggerPkt)

	// Read ACK - may be delayed, so wait a bit.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK after draining")
	}
	_, tcpHdr := parseTCPResponse(t, raw)
	if tcpHdr.WindowSize() == 0 {
		t.Error("expected non-zero window after draining buffer past threshold")
	}
}

// TestSWS_EmptyBuffer verifies full window is advertised when buffer is empty.
func TestSWS_EmptyBuffer(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(62003)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, _ := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send 2 small data segments to trigger immediate ACK.
	pkt1 := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, []byte("Hi"))
	pkt2 := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1+2, serverISN+1, 65535, []byte("!!"))
	ch.Inject(pkt1)
	ch.Inject(pkt2)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK, got nil")
	}
	_, tcpHdr := parseTCPResponse(t, raw)

	// With an nearly empty buffer (256KB free), window should be large (non-zero).
	if tcpHdr.WindowSize() == 0 {
		t.Error("expected non-zero window with nearly empty buffer")
	}

	_ = tcp.ConnState // keep import
}
