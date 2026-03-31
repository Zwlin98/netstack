package tcp_test

import (
	"sync"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// buildTCPPacketWithData constructs a TCP packet with payload.
func buildTCPPacketWithData(src, dst tcpip.Address, srcPort, dstPort uint16, flags header.TCPFlags, seqNum, ackNum uint32, wnd uint16, data []byte) []byte {
	tcpLen := header.TCPMinHeaderSize + len(data)
	totalLen := header.IPv4MinHeaderSize + tcpLen
	buf := make([]byte, totalLen)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    tcpip.TCPProtocolNumber,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(header.Checksum(buf[:header.IPv4MinHeaderSize], 0))

	tcpBuf := buf[header.IPv4MinHeaderSize:]
	tcpHdr := header.TCP(tcpBuf)
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seqNum,
		AckNum:     ackNum,
		DataOffset: header.TCPMinHeaderSize / 4,
		Flags:      flags,
		WindowSize: wnd,
	})
	copy(tcpBuf[header.TCPMinHeaderSize:], data)
	tcpHdr.SetChecksum(0)
	partial := header.PseudoHeaderChecksum(tcpip.TCPProtocolNumber, src, dst, uint16(tcpLen))
	tcpHdr.SetChecksum(header.Checksum(tcpBuf, partial))

	return buf
}

// TestDataTransfer_MultiSegment tests handshake → multi-segment data → verify order → ForceClose.
func TestDataTransfer_MultiSegment(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50000)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send 3 data segments from the "client".
	segments := []string{"Hello, ", "TCP ", "World!"}
	clientSeq := clientISN + 1
	for _, seg := range segments {
		pkt := buildTCPPacketWithData(
			clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientSeq, serverISN+1, 65535,
			[]byte(seg),
		)
		ch.Inject(pkt)
		clientSeq += uint32(len(seg))

		// Drain the ACK response.
		ackResp := ch.Read(time.Second)
		if ackResp == nil {
			t.Fatal("expected ACK for data segment")
		}
		_, ackHdr := parseTCPResponse(t, ackResp)
		if !ackHdr.Flags().Has(header.TCPFlagACK) {
			t.Fatalf("expected ACK flag, got %s", ackHdr.Flags())
		}
	}

	// Read all data from the connection.
	var received []byte
	buf := make([]byte, 256)
	for len(received) < len("Hello, TCP World!") {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read err: %v", err)
		}
		received = append(received, buf[:n]...)
	}

	want := "Hello, TCP World!"
	if string(received) != want {
		t.Fatalf("received = %q; want %q", received, want)
	}

	conn.ForceClose()
}

// TestDataTransfer_Bidirectional tests both directions of data transfer.
func TestDataTransfer_Bidirectional(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50001)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server writes data.
	var wg sync.WaitGroup
	serverData := []byte("response from server")
	wg.Go(func() {
		n, err := conn.Write(serverData)
		if err != nil || n != len(serverData) {
			t.Errorf("Write = %d, %v; want %d, nil", n, err, len(serverData))
		}
	})

	// Read the data segment from MemoryChannel (the "wire").
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment from server")
	}
	_, tcpHdr := parseTCPResponse(t, raw)

	if !tcpHdr.Flags().Has(header.TCPFlagACK) {
		t.Fatalf("expected ACK flag on data, got %s", tcpHdr.Flags())
	}

	payload := raw[header.IPv4MinHeaderSize+tcpHdr.DataOffset():]
	if string(payload) != string(serverData) {
		t.Fatalf("server sent %q; want %q", payload, serverData)
	}

	// ACK the server's data segment (client → server direction).
	clientSeq := clientISN + 1
	serverDataAck := tcpHdr.SequenceNumber() + uint32(len(payload))
	ackPkt := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverDataAck)
	ch.Inject(ackPkt)

	wg.Wait()

	// Now client sends data to server.
	clientData := []byte("request from client")
	pkt := buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1+uint32(len(serverData)), 65535,
		clientData,
	)
	ch.Inject(pkt)

	// Drain the ACK for client data.
	ackResp := ch.Read(time.Second)
	if ackResp == nil {
		t.Fatal("expected ACK for client data")
	}

	// Read the data.
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if string(buf[:n]) != string(clientData) {
		t.Fatalf("server received %q; want %q", buf[:n], clientData)
	}

	conn.ForceClose()
}

// TestDataTransfer_WindowZeroPauseResume tests that the sender pauses when window=0
// and resumes when the window opens.
// TestDataTransfer_WindowZeroPauseResume completes the handshake with window=0
// so the sender starts with no room. Data should be held until a window update.
func TestDataTransfer_WindowZeroPauseResume(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50002)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	// Manual handshake with window=0 in the completion ACK.
	syn := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagSYN, clientISN, 0)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected SYN+ACK")
	}
	_, synAckHdr := parseTCPResponse(t, raw)
	serverISN := synAckHdr.SequenceNumber()

	// Complete handshake with window=0.
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 0, nil)
	ch.Inject(ack)

	// Accept.
	acceptDone := make(chan struct{})
	var conn *tcp.TCPConn
	go func() {
		conn, _ = h.Listener().Accept()
		close(acceptDone)
	}()
	select {
	case <-acceptDone:
	case <-time.After(time.Second):
		t.Fatal("Accept timed out")
	}

	// Server writes data. sendPending sees window=0, data stays in writeBuf.
	data := []byte("window test data")
	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	// Should NOT get a data segment since window=0.
	noData := ch.Read(200 * time.Millisecond)
	if noData != nil {
		t.Fatal("expected no segment when window=0")
	}

	// Window update: ACK with window > 0.
	windowUpdate := buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1, 65535, nil)
	ch.Inject(windowUpdate)

	// Should now receive the data.
	raw2 := ch.Read(time.Second)
	if raw2 == nil {
		t.Fatal("expected data after window update")
	}
	_, tcpHdr2 := parseTCPResponse(t, raw2)
	payload2 := raw2[header.IPv4MinHeaderSize+tcpHdr2.DataOffset():]
	if string(payload2) != string(data) {
		t.Fatalf("received %q; want %q", payload2, data)
	}

	wg.Wait()
	conn.ForceClose()
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestOutOfOrderReceive (line 2022)
//
// Sends the second half of data first (out-of-order), verifies the ACK still
// indicates the original expected sequence, then sends the first half and
// verifies the full data is reassembled in order.
func TestOutOfOrderReceive(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	data := []byte{1, 2, 3, 4, 5, 6}
	clientSeq := clientISN + 1

	// Send second half first (bytes 4,5,6 at seq+3).
	pkt1 := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq+3, serverISN+1, 30000, data[3:])
	ch.Inject(pkt1)

	// Should get ACK with AckNum = clientSeq (still expecting first byte).
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK for OOO segment")
	}
	_, ackHdr := parseTCPResponse(t, raw)
	if ackHdr.AckNumber() != clientSeq {
		t.Errorf("ACK for OOO: AckNum = %d, want %d (still expecting first byte)", ackHdr.AckNumber(), clientSeq)
	}

	// Send first half (bytes 1,2,3 at seq).
	pkt2 := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 30000, data[:3])
	ch.Inject(pkt2)

	// Should get ACK covering all 6 bytes.
	raw2 := ch.Read(time.Second)
	if raw2 == nil {
		t.Fatal("expected ACK for in-order segment")
	}
	_, ackHdr2 := parseTCPResponse(t, raw2)
	if ackHdr2.AckNumber() != clientSeq+uint32(len(data)) {
		t.Errorf("final ACK: AckNum = %d, want %d", ackHdr2.AckNumber(), clientSeq+uint32(len(data)))
	}

	// Read all data and verify correct order.
	buf := make([]byte, 64)
	var received []byte
	for len(received) < len(data) {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read err: %v", err)
		}
		received = append(received, buf[:n]...)
	}
	for i := range data {
		if received[i] != data[i] {
			t.Fatalf("data[%d] = %d, want %d (reassembly order wrong)", i, received[i], data[i])
		}
	}

	conn.ForceClose()
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestOutOfOrderFlood (line 2092)
//
// Sends many copies of a future segment (all at the same OOO offset), then
// sends the missing in-order segment. Verifies the OOO buffer merges correctly
// and the final ACK covers all delivered data.
func TestOutOfOrderFlood(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	data := []byte{1, 2, 3, 4, 5, 6}
	clientSeq := clientISN + 1

	// Send 100 copies of the second-half segment (OOO).
	ooo := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq+3, serverISN+1, 30000, data[3:])
	for i := 0; i < 100; i++ {
		ch.Inject(ooo)
		raw := ch.Read(time.Second)
		if raw == nil {
			t.Fatalf("expected ACK for OOO segment #%d", i)
		}
		_, ackHdr := parseTCPResponse(t, raw)
		// ACK should still indicate first expected byte.
		if ackHdr.AckNumber() != clientSeq {
			t.Errorf("OOO #%d: AckNum = %d, want %d", i, ackHdr.AckNumber(), clientSeq)
		}
	}

	// Now send the first half.
	first := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 30000, data[:3])
	ch.Inject(first)

	// ACK should now cover all data (first half + one copy of second half).
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected final ACK")
	}
	_, ackHdr := parseTCPResponse(t, raw)
	// First 3 bytes + second 3 bytes = 6 bytes total.
	if ackHdr.AckNumber() != clientSeq+6 {
		t.Errorf("final ACK: AckNum = %d, want %d", ackHdr.AckNumber(), clientSeq+6)
	}

	// Verify all data received in order.
	buf := make([]byte, 64)
	var received []byte
	for len(received) < 6 {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read err: %v", err)
		}
		received = append(received, buf[:n]...)
	}
	for i := range data {
		if received[i] != data[i] {
			t.Fatalf("data[%d] = %d, want %d", i, received[i], data[i])
		}
	}

	conn.ForceClose()
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestSendGreaterThanMTU (line 3593)
//
// Writing data larger than MSS should produce multiple segments, each capped
// at MSS (1460 bytes).
func TestSendGreaterThanMTU(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Write 4000 bytes — should be split into ceil(4000/1460) = 3 segments.
	data := make([]byte, 4000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		_, err := conn.Write(data)
		if err != nil {
			t.Errorf("Write err: %v", err)
		}
	})

	// Collect all segments and reconstruct the sent data.
	var sentData []byte
	expectedSeq := serverISN + 1
	remaining := len(data)

	for remaining > 0 {
		raw := ch.Read(time.Second)
		if raw == nil {
			t.Fatalf("expected data segment, %d bytes remaining", remaining)
		}
		_, tcpHdr := parseTCPResponse(t, raw)

		if tcpHdr.SequenceNumber() != expectedSeq {
			t.Errorf("segment SeqNum = %d, want %d", tcpHdr.SequenceNumber(), expectedSeq)
		}

		payload := raw[header.IPv4MinHeaderSize+tcpHdr.DataOffset():]

		// Each segment should be at most MSS bytes (MTU 1500 - 20 IP - 20 TCP = 1460).
		mss := 1500 - header.IPv4MinHeaderSize - header.TCPMinHeaderSize
		if len(payload) > mss {
			t.Errorf("segment payload = %d bytes, exceeds MSS %d", len(payload), mss)
		}

		sentData = append(sentData, payload...)
		expectedSeq += uint32(len(payload))
		remaining -= len(payload)

		// ACK each segment so the sender window stays open.
		ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientISN+1, expectedSeq)
		ch.Inject(ack)
	}

	// Verify complete data was sent correctly.
	if len(sentData) != len(data) {
		t.Fatalf("total sent = %d bytes, want %d", len(sentData), len(data))
	}
	for i := range data {
		if sentData[i] != data[i] {
			t.Fatalf("byte %d: sent %d, want %d", i, sentData[i], data[i])
		}
	}

	wg.Wait()
	conn.ForceClose()
}

// Inspired by gvisor receiver duplicate handling (rcv.go handleData: seq < nxt → ignore).
//
// Sending the same data segment twice should deliver data only once.
func TestDuplicateReceive(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	data := []byte("hello")
	clientSeq := clientISN + 1

	// Send same segment twice.
	pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 30000, data)
	ch.Inject(pkt)
	ch.Read(time.Second) // drain ACK

	ch.Inject(pkt)
	ch.Read(time.Second) // drain ACK

	// Read should return exactly 5 bytes, not 10.
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Read = %d bytes, want %d (duplicate should be ignored)", n, len(data))
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("Read = %q, want %q", buf[:n], "hello")
	}

	conn.ForceClose()
}

// Ported from gvisor: pkg/tcpip/transport/tcp/test/e2e/tcp_test.go:TestOutOfOrderReceive (line 2047-2056)
//
// When an out-of-order segment arrives, the ACK must carry rcv.nxt (the last
// contiguous byte), not acknowledge the OOO data.
func TestACKForOutOfOrderSegment(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(4096)
	serverPort := uint16(1234)
	clientISN := uint32(789)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)
	_ = conn

	clientSeq := clientISN + 1

	// Send segment at seq+10 (gap of 10 bytes).
	oooData := []byte("future")
	pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq+10, serverISN+1, 30000, oooData)
	ch.Inject(pkt)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected ACK")
	}
	_, ackHdr := parseTCPResponse(t, raw)

	// ACK must indicate clientSeq (still expecting first byte), NOT clientSeq+10+6.
	if ackHdr.AckNumber() != clientSeq {
		t.Errorf("OOO ACK: AckNum = %d, want %d (should not advance past gap)", ackHdr.AckNumber(), clientSeq)
	}

	// SeqNum should be current snd.nxt.
	if ackHdr.SequenceNumber() != serverISN+1 {
		t.Errorf("OOO ACK: SeqNum = %d, want %d", ackHdr.SequenceNumber(), serverISN+1)
	}

	conn.ForceClose()
}
