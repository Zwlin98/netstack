package tcp_test

import (
	"io"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
)

// TestCloseWrite_SendsFINReadStillWorks verifies that CloseWrite sends
// FIN but the read side remains open for receiving data.
func TestCloseWrite_SendsFINReadStillWorks(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50040)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Server calls CloseWrite — should send FIN.
	conn.CloseWrite()

	finRaw := ch.Read(time.Second)
	if finRaw == nil {
		t.Fatal("expected FIN after CloseWrite")
	}
	_, finHdr := parseTCPResponse(t, finRaw)
	if !finHdr.Flags().Has(header.TCPFlagFIN) {
		t.Fatalf("expected FIN flag, got %s", finHdr.Flags())
	}

	// ACK the FIN.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+2)
	ch.Inject(ack)

	// Peer sends data — read side should still work.
	data := []byte("after close write")
	dataPkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+2, 65535, data)
	ch.Inject(dataPkt)

	// ACK for data (delayed ACK or immediate).
	ch.Read(500 * time.Millisecond)

	// Read the data from the server side.
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read after CloseWrite: err = %v, want nil", err)
	}
	if n != len(data) {
		t.Fatalf("Read = %d bytes, want %d", n, len(data))
	}
	if string(buf[:n]) != string(data) {
		t.Errorf("Read data = %q, want %q", string(buf[:n]), string(data))
	}
}

// TestCloseWrite_BlocksWrite verifies that Write returns error after CloseWrite.
func TestCloseWrite_BlocksWrite(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50041)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	conn.CloseWrite()
	// Drain FIN.
	ch.Read(time.Second)

	// Write should fail.
	_, err := conn.Write([]byte("should fail"))
	if err == nil {
		t.Error("expected error on Write after CloseWrite, got nil")
	}
}

// TestCloseRead_ReturnsEOFWriteStillWorks verifies that CloseRead
// causes Read to return EOF but Write still works.
func TestCloseRead_ReturnsEOFWriteStillWorks(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50042)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// CloseRead — should NOT send FIN.
	conn.CloseRead()

	// No FIN should be sent.
	finCheck := ch.Read(200 * time.Millisecond)
	if finCheck != nil {
		_, tcpHdr := parseTCPResponse(t, finCheck)
		if tcpHdr.Flags().Has(header.TCPFlagFIN) {
			t.Error("CloseRead should not send FIN")
		}
	}

	// Read should return EOF.
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err != io.EOF {
		t.Errorf("Read after CloseRead: err = %v, want io.EOF", err)
	}

	// Write should still work.
	go conn.Write([]byte("still writing"))

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected data segment after CloseRead, got nil")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	dataLen := len(raw) - int(header.IPv4(raw).HeaderLength()) - int(dataHdr.DataOffset())
	if dataLen == 0 {
		t.Error("expected data in segment")
	}

	_ = serverISN
}

// TestCloseWrite_Idempotent verifies that multiple CloseWrite calls don't panic.
func TestCloseWrite_Idempotent(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, 50043, 80, 4000)

	conn.CloseWrite()
	conn.CloseWrite()
	conn.CloseWrite()
	// Should not panic.

	// Drain FIN.
	ch.Read(time.Second)
}

// TestHalfClose_WriteThenReadPattern verifies the HTTP-style pattern:
// write request → CloseWrite → read response → Close.
func TestHalfClose_WriteThenReadPattern(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50044)
	serverPort := uint16(80)
	clientISN := uint32(5000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Write "request" data.
	go conn.Write([]byte("GET /"))

	reqRaw := ch.Read(time.Second)
	if reqRaw == nil {
		t.Fatal("expected request data")
	}
	_, reqHdr := parseTCPResponse(t, reqRaw)
	reqDataLen := uint32(len(reqRaw)) - uint32(header.IPv4(reqRaw).HeaderLength()) - uint32(reqHdr.DataOffset())

	// ACK the request.
	ack1 := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+reqDataLen, 65535, nil)
	ch.Inject(ack1)

	// CloseWrite — done sending.
	conn.CloseWrite()

	finRaw := ch.Read(time.Second)
	if finRaw == nil {
		t.Fatal("expected FIN")
	}
	_, finHdr := parseTCPResponse(t, finRaw)
	if !finHdr.Flags().Has(header.TCPFlagFIN) {
		t.Fatalf("expected FIN, got %s", finHdr.Flags())
	}

	// ACK the FIN.
	ack2 := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+2+reqDataLen)
	ch.Inject(ack2)

	// Peer sends response data.
	response := []byte("200 OK")
	respPkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+2+reqDataLen, 65535, response)
	ch.Inject(respPkt)

	// Drain the ACK.
	ch.Read(500 * time.Millisecond)

	// Read the response.
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read response: err = %v", err)
	}
	if string(buf[:n]) != string(response) {
		t.Errorf("response = %q, want %q", string(buf[:n]), string(response))
	}

	// Peer sends FIN.
	fin := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagFIN|header.TCPFlagACK, clientISN+1+uint32(len(response)), serverISN+2+reqDataLen)
	ch.Inject(fin)

	// ACK for FIN.
	ch.Read(500 * time.Millisecond)

	// Now Read should return EOF.
	_, err = conn.Read(buf)
	if err != io.EOF {
		t.Errorf("final Read: err = %v, want io.EOF", err)
	}
}
