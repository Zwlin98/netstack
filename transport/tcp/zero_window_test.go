package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
)

// TestZeroWindowProbe_StartsOnZeroWindow verifies that when the peer
// advertises window=0 and the server has pending data, a zero-window
// probe is sent.
func TestZeroWindowProbe_StartsOnZeroWindow(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50010)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Write data to the server side.
	go conn.Write([]byte("initial"))

	// Read the outgoing data segment.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment, got nil")
	}
	_, tcpHdr := parseTCPResponse(t, raw)
	dataLen := uint32(len(raw)) - uint32(header.IPv4(raw).HeaderLength()) - uint32(tcpHdr.DataOffset())

	// ACK the data with window=0.
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+dataLen, 0, nil)
	ch.Inject(ack)

	// Wait for zero-window ACK to be processed by the run loop.
	time.Sleep(100 * time.Millisecond)

	// Write more data — should be blocked by zero window.
	go conn.Write([]byte("blocked"))

	// A zero-window probe should arrive (within the RTO + some margin).
	probe := ch.Read(3 * time.Second)
	if probe == nil {
		t.Fatal("expected zero-window probe, got nil")
	}
	_, probeHdr := parseTCPResponse(t, probe)
	if !probeHdr.Flags().Has(header.TCPFlagACK) {
		t.Errorf("probe should have ACK flag, got %s", probeHdr.Flags())
	}
	// Probe should contain data (1 byte from probing).
	probeDataLen := len(probe) - int(header.IPv4(probe).HeaderLength()) - int(probeHdr.DataOffset())
	if probeDataLen == 0 {
		t.Error("probe should contain data")
	}
}

// TestZeroWindowProbe_CancelsOnWindowOpen verifies that when the peer
// opens the window, probing stops and normal sending resumes.
func TestZeroWindowProbe_CancelsOnWindowOpen(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50011)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Write initial data.
	go conn.Write([]byte("x"))
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment")
	}
	_, tcpHdr := parseTCPResponse(t, raw)
	dataLen := uint32(len(raw)) - uint32(header.IPv4(raw).HeaderLength()) - uint32(tcpHdr.DataOffset())
	nextAck := serverISN + 1 + dataLen

	// ACK with window=0.
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, nextAck, 0, nil)
	ch.Inject(ack)
	time.Sleep(100 * time.Millisecond)

	// Write more data so probing starts.
	go conn.Write([]byte("more data"))

	// Wait for a probe to arrive.
	probe := ch.Read(3 * time.Second)
	if probe == nil {
		t.Fatal("expected probe")
	}
	_, probeHdr := parseTCPResponse(t, probe)
	probeDataLen := uint32(len(probe)) - uint32(header.IPv4(probe).HeaderLength()) - uint32(probeHdr.DataOffset())
	nextAck += probeDataLen

	// Open the window by ACKing with a large window.
	windowOpen := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, nextAck, 65535, nil)
	ch.Inject(windowOpen)

	// Normal data should flow now.
	dataPkt := ch.Read(2 * time.Second)
	if dataPkt == nil {
		t.Fatal("expected normal data after window opened, got nil")
	}
	_, dataHdr := parseTCPResponse(t, dataPkt)
	resumedLen := len(dataPkt) - int(header.IPv4(dataPkt).HeaderLength()) - int(dataHdr.DataOffset())
	if resumedLen <= 0 {
		t.Error("expected data in resumed segment")
	}
}

// TestZeroWindowProbe_NoAbortAfterManyProbes verifies that the connection
// is not aborted due to zero-window probes (they don't count toward retries).
func TestZeroWindowProbe_NoAbortAfterManyProbes(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50012)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Write initial data.
	go conn.Write([]byte("x"))
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data")
	}
	_, tcpHdr := parseTCPResponse(t, raw)
	dataLen := uint32(len(raw)) - uint32(header.IPv4(raw).HeaderLength()) - uint32(tcpHdr.DataOffset())
	nextAck := serverISN + 1 + dataLen

	// ACK with window=0.
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, nextAck, 0, nil)
	ch.Inject(ack)
	time.Sleep(100 * time.Millisecond)

	// Write data to trigger probing.
	go conn.Write([]byte("abcdefghijklmnop"))

	// Receive multiple probes/retransmits, ACK each with wnd=0.
	for i := 0; i < 5; i++ {
		pkt := ch.Read(5 * time.Second)
		if pkt == nil {
			t.Fatalf("expected packet #%d, got nil — connection may have been aborted", i+1)
		}
		_, pktHdr := parseTCPResponse(t, pkt)
		pktDataLen := uint32(len(pkt)) - uint32(header.IPv4(pkt).HeaderLength()) - uint32(pktHdr.DataOffset())
		if pktDataLen > 0 {
			nextAck = pktHdr.SequenceNumber() + pktDataLen
		}

		// Respond with wnd=0.
		ackResp := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientISN+1, nextAck, 0, nil)
		ch.Inject(ackResp)
	}

	// Connection should still be alive. Open the window to verify.
	windowOpen := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, nextAck, 65535, nil)
	ch.Inject(windowOpen)

	// Should get data flowing.
	resumed := ch.Read(2 * time.Second)
	if resumed == nil {
		t.Fatal("connection appears dead after many probes — should still be alive")
	}
}
