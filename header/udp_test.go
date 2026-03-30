package header

import (
	"testing"

	"github.com/Zwlin98/netstack/tcpip"
)

func TestUDPRoundTrip(t *testing.T) {
	payload := []byte("hello DNS")
	buf := make([]byte, UDPHeaderSize+len(payload))
	copy(buf[UDPHeaderSize:], payload)
	udp := UDP(buf)

	fields := &UDPFields{
		SrcPort:  12345,
		DstPort:  53,
		Length:   uint16(UDPHeaderSize + len(payload)),
		Checksum: 0,
	}
	udp.Encode(fields)

	if got := udp.SourcePort(); got != 12345 {
		t.Errorf("SourcePort() = %d, want 12345", got)
	}
	if got := udp.DestinationPort(); got != 53 {
		t.Errorf("DestinationPort() = %d, want 53", got)
	}
	if got := udp.Length(); got != uint16(UDPHeaderSize+len(payload)) {
		t.Errorf("Length() = %d, want %d", got, UDPHeaderSize+len(payload))
	}
	if got := string(udp.Payload()); got != "hello DNS" {
		t.Errorf("Payload() = %q, want %q", got, "hello DNS")
	}
}

func TestUDPKnownDNSPacket(t *testing.T) {
	// Construct a DNS query UDP packet: src=52345, dst=53, query payload
	dnsQuery := []byte{
		0xAA, 0xBB, // Transaction ID
		0x01, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}

	totalLen := uint16(UDPHeaderSize + len(dnsQuery))
	buf := make([]byte, int(totalLen))
	copy(buf[UDPHeaderSize:], dnsQuery)

	udp := UDP(buf)
	udp.Encode(&UDPFields{
		SrcPort: 52345,
		DstPort: 53,
		Length:  totalLen,
	})

	if got := udp.SourcePort(); got != 52345 {
		t.Errorf("SrcPort = %d, want 52345", got)
	}
	if got := udp.DestinationPort(); got != 53 {
		t.Errorf("DstPort = %d, want 53", got)
	}
	if got := udp.Length(); got != totalLen {
		t.Errorf("Length = %d, want %d", got, totalLen)
	}

	// Verify payload is the DNS query.
	gotPayload := udp.Payload()
	if len(gotPayload) != len(dnsQuery) {
		t.Fatalf("payload len = %d, want %d", len(gotPayload), len(dnsQuery))
	}
	if gotPayload[0] != 0xAA || gotPayload[1] != 0xBB {
		t.Error("DNS transaction ID mismatch")
	}
}

func TestUDPChecksumWithPseudoHeader(t *testing.T) {
	src := tcpip.From4(192, 168, 0, 1)
	dst := tcpip.From4(192, 168, 0, 199)

	payload := []byte("test data")
	totalLen := uint16(UDPHeaderSize + len(payload))
	buf := make([]byte, int(totalLen))
	copy(buf[UDPHeaderSize:], payload)

	udp := UDP(buf)
	udp.Encode(&UDPFields{
		SrcPort: 1234,
		DstPort: 5678,
		Length:  totalLen,
	})

	// Compute checksum.
	udp.SetChecksum(0)
	phc := PseudoHeaderChecksum(tcpip.UDPProtocolNumber, src, dst, totalLen)
	csum := Checksum(buf, phc)
	udp.SetChecksum(csum)

	// Verify.
	phc2 := PseudoHeaderChecksum(tcpip.UDPProtocolNumber, src, dst, totalLen)
	verify := Checksum(buf, phc2)
	if verify != 0 {
		t.Errorf("UDP checksum verification = 0x%04x, want 0x0000", verify)
	}
}

func TestUDPSetters(t *testing.T) {
	buf := make([]byte, UDPHeaderSize)
	udp := UDP(buf)

	udp.SetSourcePort(9999)
	if udp.SourcePort() != 9999 {
		t.Errorf("SetSourcePort: got %d, want 9999", udp.SourcePort())
	}

	udp.SetDestinationPort(8080)
	if udp.DestinationPort() != 8080 {
		t.Errorf("SetDestinationPort: got %d, want 8080", udp.DestinationPort())
	}

	udp.SetLength(100)
	if udp.Length() != 100 {
		t.Errorf("SetLength: got %d, want 100", udp.Length())
	}

	udp.SetChecksum(0x1234)
	if udp.Checksum() != 0x1234 {
		t.Errorf("SetChecksum: got 0x%04x, want 0x1234", udp.Checksum())
	}
}
