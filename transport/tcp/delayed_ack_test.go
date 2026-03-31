package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
)

// TestDelayedACK_FiresAfter200ms verifies that a single data segment
// triggers a delayed ACK after ~200ms instead of an immediate ACK.
func TestDelayedACK_FiresAfter200ms(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50000)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, _ := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send a single data segment.
	data := []byte("hello")
	pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, data)
	ch.Inject(pkt)

	// ACK should NOT arrive immediately (within 50ms).
	earlyACK := ch.Read(50 * time.Millisecond)
	if earlyACK != nil {
		t.Error("expected no immediate ACK for single data segment, but got one")
	}

	// ACK should arrive after ~200ms delayed ACK timer fires.
	ack := ch.Read(300 * time.Millisecond)
	if ack == nil {
		t.Fatal("expected delayed ACK after ~200ms, got nil")
	}
	_, tcpHdr := parseTCPResponse(t, ack)
	if !tcpHdr.Flags().Has(header.TCPFlagACK) {
		t.Errorf("expected ACK flag, got %s", tcpHdr.Flags())
	}
	if tcpHdr.AckNumber() != clientISN+1+uint32(len(data)) {
		t.Errorf("ACK number = %d, want %d", tcpHdr.AckNumber(), clientISN+1+uint32(len(data)))
	}
}

// TestDelayedACK_ImmediateOn2ndSegment verifies the every-other-segment
// rule: the 2nd data segment triggers an immediate ACK.
func TestDelayedACK_ImmediateOn2ndSegment(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50001)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	serverISN, _ := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send first data segment.
	data1 := []byte("hello")
	pkt1 := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, data1)
	ch.Inject(pkt1)

	// Send second data segment immediately.
	data2 := []byte("world")
	pkt2 := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1+uint32(len(data1)), serverISN+1, 65535, data2)
	ch.Inject(pkt2)

	// ACK should arrive quickly (within 100ms), not delayed.
	ack := ch.Read(100 * time.Millisecond)
	if ack == nil {
		t.Fatal("expected immediate ACK on 2nd segment, got nil")
	}
	_, tcpHdr := parseTCPResponse(t, ack)
	if tcpHdr.AckNumber() != clientISN+1+uint32(len(data1))+uint32(len(data2)) {
		t.Errorf("ACK number = %d, want %d", tcpHdr.AckNumber(),
			clientISN+1+uint32(len(data1))+uint32(len(data2)))
	}
}

// TestDelayedACK_ImmediateOnOOO verifies that out-of-order segments
// trigger an immediate ACK (duplicate ACK for fast retransmit).
func TestDelayedACK_ImmediateOnOOO(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50002)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	serverISN, _ := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send out-of-order segment (skip first segment).
	oooData := []byte("world")
	oooSeq := clientISN + 1 + 100 // gap of 100 bytes
	pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, oooSeq, serverISN+1, 65535, oooData)
	ch.Inject(pkt)

	// ACK should arrive immediately (duplicate ACK with rcv.nxt).
	ack := ch.Read(50 * time.Millisecond)
	if ack == nil {
		t.Fatal("expected immediate ACK on OOO segment, got nil")
	}
	_, tcpHdr := parseTCPResponse(t, ack)
	// Should ACK up to the gap (clientISN+1, not past the OOO segment).
	if tcpHdr.AckNumber() != clientISN+1 {
		t.Errorf("ACK number = %d, want %d (dup ACK at gap)", tcpHdr.AckNumber(), clientISN+1)
	}
}

// TestDelayedACK_CancelledOnOutgoingData verifies that sending data
// piggybacks the ACK and cancels the delayed ACK timer.
func TestDelayedACK_CancelledOnOutgoingData(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50003)
	serverPort := uint16(80)
	clientISN := uint32(4000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send a data segment from client.
	data := []byte("request")
	pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, data)
	ch.Inject(pkt)

	// Wait a bit to ensure the segment is processed but before delayed ACK fires.
	time.Sleep(20 * time.Millisecond)

	// Now write data from the server side — this should piggyback the ACK.
	reply := []byte("response")
	go conn.Write(reply)

	// The outgoing data segment should carry the ACK.
	raw := ch.Read(100 * time.Millisecond)
	if raw == nil {
		t.Fatal("expected outgoing data with piggybacked ACK, got nil")
	}
	_, tcpHdr := parseTCPResponse(t, raw)

	if !tcpHdr.Flags().Has(header.TCPFlagACK) {
		t.Errorf("expected ACK flag on data segment, got %s", tcpHdr.Flags())
	}
	if tcpHdr.AckNumber() != clientISN+1+uint32(len(data)) {
		t.Errorf("piggybacked ACK = %d, want %d", tcpHdr.AckNumber(), clientISN+1+uint32(len(data)))
	}

	// No additional delayed ACK should fire.
	extra := ch.Read(300 * time.Millisecond)
	if extra != nil {
		t.Error("unexpected extra ACK after piggyback — delayed ACK timer should have been cancelled")
	}
}

// TestDelayedACK_ImmediateOnFIN verifies that FIN triggers immediate ACK.
func TestDelayedACK_ImmediateOnFIN(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50004)
	serverPort := uint16(80)
	clientISN := uint32(5000)

	serverISN, _ := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send FIN.
	fin := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagFIN|header.TCPFlagACK, clientISN+1, serverISN+1)
	ch.Inject(fin)

	// ACK should arrive immediately.
	ack := ch.Read(50 * time.Millisecond)
	if ack == nil {
		t.Fatal("expected immediate ACK on FIN, got nil")
	}
	_, tcpHdr := parseTCPResponse(t, ack)
	if !tcpHdr.Flags().Has(header.TCPFlagACK) {
		t.Errorf("expected ACK flag, got %s", tcpHdr.Flags())
	}
	// FIN occupies one sequence number.
	if tcpHdr.AckNumber() != clientISN+2 {
		t.Errorf("ACK number = %d, want %d", tcpHdr.AckNumber(), clientISN+2)
	}
}
