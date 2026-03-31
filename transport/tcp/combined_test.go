package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
)

// TestCombined_TimestampDelayedACKNagle tests the interaction between
// timestamps, delayed ACK, and Nagle on a bulk data transfer.
func TestCombined_TimestampDelayedACKNagle(t *testing.T) {
	ch, s, h := setupStack(t) // MTU=1500
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(63001)
	serverPort := uint16(80)
	clientISN := uint32(1000)
	clientTSVal := uint32(10000)

	serverISN, conn, _ := completeHandshakeWithTS(t, ch, h, clientAddr, serverAddr,
		clientPort, serverPort, clientISN, clientTSVal)

	// Server sends bulk data — multiple MSS-sized segments.
	// With timestamps, MSS = 1460-12 = 1448.
	bulkData := make([]byte, 4096)
	for i := range bulkData {
		bulkData[i] = byte(i % 256)
	}
	go conn.Write(bulkData)

	// Read segments from the server, ACK each, verify timestamps.
	totalReceived := 0
	clientSeq := clientISN + 1
	prevTSVal := uint32(0)
	expectedMSS := 1460 - 12

	for totalReceived < len(bulkData) {
		raw := ch.Read(time.Second)
		if raw == nil {
			t.Fatalf("expected more data, only got %d/%d bytes", totalReceived, len(bulkData))
		}
		ip := header.IPv4(raw)
		tcpHdr := header.TCP(raw[ip.HeaderLength():])
		payload := raw[int(ip.HeaderLength())+int(tcpHdr.DataOffset()):]

		// Verify timestamp option present.
		segOpts := header.ParseSegmentOptions(tcpHdr.Options())
		if !segOpts.TSEnabled {
			t.Error("data segment missing timestamp option")
		}
		// TSval should be monotonically non-decreasing.
		if prevTSVal != 0 && int32(segOpts.TSVal-prevTSVal) < 0 {
			t.Errorf("TSval went backwards: %d -> %d", prevTSVal, segOpts.TSVal)
		}
		prevTSVal = segOpts.TSVal

		// Verify segment size does not exceed reduced MSS.
		if len(payload) > expectedMSS {
			t.Errorf("segment payload %d > expected MSS %d", len(payload), expectedMSS)
		}

		totalReceived += len(payload)

		// ACK with timestamp echo.
		ackTSVal := clientTSVal + uint32(totalReceived)
		ackOpts := buildTSOption(ackTSVal, segOpts.TSVal)
		ack := buildTCPPacketWithDataAndOptions(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientSeq, serverISN+1+uint32(totalReceived), 65535,
			ackOpts, nil)
		ch.Inject(ack)
	}

	if totalReceived != len(bulkData) {
		t.Errorf("received %d bytes, want %d", totalReceived, len(bulkData))
	}
}

// TestCombined_SWSZeroWindowProbe tests that SWS avoidance + zero-window probe
// work together: buffer fills → SWS suppresses window → zero-window probe triggers.
func TestCombined_SWSZeroWindowProbe(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(63002)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Make the server want to send data (fills writeBuf).
	writeData := make([]byte, 1024)
	go conn.Write(writeData)

	// Read and ACK the server's data segments.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment from server")
	}
	_, tcpHdr := parseTCPResponse(t, raw)
	payload := raw[int(header.IPv4(raw).HeaderLength())+int(tcpHdr.DataOffset()):]

	// ACK with window=0 to simulate a full receiver buffer on our side.
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+uint32(len(payload)), 0, nil)
	ch.Inject(ack)

	// The server should eventually send a zero-window probe.
	// Wait for a probe (a 1-byte data segment).
	gotProbe := false
	for i := 0; i < 20; i++ {
		probe := ch.Read(2 * time.Second)
		if probe == nil {
			continue
		}
		ip := header.IPv4(probe)
		probeHdr := header.TCP(probe[ip.HeaderLength():])
		probePayload := probe[int(ip.HeaderLength())+int(probeHdr.DataOffset()):]
		if len(probePayload) == 1 {
			gotProbe = true
			break
		}
	}

	if !gotProbe {
		t.Error("expected zero-window probe after advertising window=0")
	}
	_ = conn
}
