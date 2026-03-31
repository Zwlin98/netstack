package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
)

// TestNagle_SmallWriteHeldWhileInFlight verifies that a sub-MSS write is held
// when there is already unACKed data in flight (Nagle enabled by default).
func TestNagle_SmallWriteHeldWhileInFlight(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(61001)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// First small write — no data in flight, should be sent immediately.
	go conn.Write([]byte("A"))

	raw1 := ch.Read(time.Second)
	if raw1 == nil {
		t.Fatal("expected first segment to be sent immediately")
	}

	// Second small write — data in flight, should be held by Nagle.
	go conn.Write([]byte("B"))

	raw2 := ch.Read(100 * time.Millisecond)
	if raw2 != nil {
		t.Error("expected second sub-MSS write to be held by Nagle, but it was sent")
	}

	_ = conn
}

// TestNagle_ACKFlushesBuffered verifies that when an ACK clears all in-flight
// data, any buffered sub-MSS data is flushed immediately.
func TestNagle_ACKFlushesBuffered(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(61002)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// First write — sent immediately (no data in flight).
	go conn.Write([]byte("X"))

	raw1 := ch.Read(time.Second)
	if raw1 == nil {
		t.Fatal("expected first segment")
	}

	// Second small write — held by Nagle.
	writeDone := make(chan struct{})
	go func() {
		conn.Write([]byte("Y"))
		close(writeDone)
	}()

	// Verify it's held.
	time.Sleep(50 * time.Millisecond)
	held := ch.Read(50 * time.Millisecond)
	if held != nil {
		t.Error("expected sub-MSS write to be held while data in flight")
	}

	// ACK the first segment — should flush buffered data.
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+1, 65535, nil)
	ch.Inject(ack)

	raw2 := ch.Read(time.Second)
	if raw2 == nil {
		t.Fatal("expected buffered data to be flushed after ACK")
	}
	_, tcpHdr := parseTCPResponse(t, raw2)
	payload := raw2[int(header.IPv4(raw2).HeaderLength())+int(tcpHdr.DataOffset()):]
	if string(payload) != "Y" {
		t.Errorf("flushed data = %q, want %q", payload, "Y")
	}

	<-writeDone
}

// TestNagle_MSSWriteSentImmediately verifies that MSS-sized writes are sent
// even when there is data in flight (Nagle only holds sub-MSS).
func TestNagle_MSSWriteSentImmediately(t *testing.T) {
	ch, s, h := setupStackWithMTU(t, 600) // local MSS = 560
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(61003)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	localMSS := 600 - header.IPv4MinHeaderSize - header.TCPMinHeaderSize // 560

	// First small write — creates in-flight data.
	go conn.Write([]byte("A"))
	raw1 := ch.Read(time.Second)
	if raw1 == nil {
		t.Fatal("expected first segment")
	}

	// Now write exactly MSS bytes — should be sent immediately despite in-flight data.
	fullMSS := make([]byte, localMSS)
	go conn.Write(fullMSS)

	raw2 := ch.Read(time.Second)
	if raw2 == nil {
		t.Fatal("expected MSS-sized write to be sent immediately even with data in flight")
	}

	_ = conn
}

// TestNagle_SetNoDelay verifies that SetNoDelay(true) disables Nagle,
// allowing sub-MSS writes to be sent while data is in flight.
func TestNagle_SetNoDelay(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(61004)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	conn.SetNoDelay(true)

	// First small write.
	go conn.Write([]byte("A"))
	raw1 := ch.Read(time.Second)
	if raw1 == nil {
		t.Fatal("expected first segment")
	}

	// Second small write — should be sent immediately (Nagle disabled).
	go conn.Write([]byte("B"))
	raw2 := ch.Read(time.Second)
	if raw2 == nil {
		t.Fatal("expected sub-MSS write to be sent immediately with NoDelay=true")
	}
}
