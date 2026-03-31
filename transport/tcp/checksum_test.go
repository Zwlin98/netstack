package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
)

// TestChecksumValidation_ValidPacket verifies that a packet with correct checksum is accepted.
func TestChecksumValidation_ValidPacket(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	// Send a valid SYN — should get SYN+ACK.
	syn := buildTCPPacket(clientAddr, serverAddr, 60000, 80, header.TCPFlagSYN, 1000, 0)
	ch.Inject(syn)

	resp := ch.Read(time.Second)
	if resp == nil {
		t.Fatal("expected SYN+ACK for valid checksum SYN")
	}
	_, tcpHdr := parseTCPResponse(t, resp)
	if !tcpHdr.Flags().Has(header.TCPFlagSYN) || !tcpHdr.Flags().Has(header.TCPFlagACK) {
		t.Fatalf("expected SYN+ACK, got flags %v", tcpHdr.Flags())
	}
}

// TestChecksumValidation_InvalidPacket verifies that a packet with bad checksum is silently dropped.
func TestChecksumValidation_InvalidPacket(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)

	// Build a valid SYN then corrupt the TCP checksum.
	syn := buildTCPPacket(clientAddr, serverAddr, 60001, 80, header.TCPFlagSYN, 2000, 0)
	// Corrupt the TCP checksum by flipping a byte in the TCP payload area.
	tcpStart := header.IPv4MinHeaderSize
	syn[tcpStart+16] ^= 0xFF // checksum field is at offset 16-17 in TCP header
	// Also flip a data byte to ensure it's actually invalid.
	syn[tcpStart+4] ^= 0x01

	ch.Inject(syn)

	resp := ch.Read(500 * time.Millisecond)
	if resp != nil {
		t.Fatal("expected no response for bad checksum SYN, but got a response")
	}
}

// TestChecksumValidation_InvalidDataPacket verifies that a data packet with bad checksum
// is dropped and does not deliver data.
func TestChecksumValidation_InvalidDataPacket(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60002)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)
	clientSeq := clientISN + 1

	// Build a valid data packet then corrupt it.
	pkt := buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535,
		[]byte("CORRUPTED"),
	)
	// Corrupt a byte in the payload to make checksum invalid.
	pkt[len(pkt)-1] ^= 0xFF

	ch.Inject(pkt)
	time.Sleep(100 * time.Millisecond)

	// Send a valid packet after — this should still work.
	pkt2 := buildTCPPacketWithData(
		clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientSeq, serverISN+1, 65535,
		[]byte("VALID"),
	)
	ch.Inject(pkt2)
	time.Sleep(100 * time.Millisecond)
	drainPackets(ch, 200*time.Millisecond)

	buf := make([]byte, 20)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read err: %v", err)
	}
	if string(buf[:n]) != "VALID" {
		t.Fatalf("read data = %q, want %q — corrupted packet was not dropped", string(buf[:n]), "VALID")
	}
}
