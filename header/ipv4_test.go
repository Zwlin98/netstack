package header

import (
	"testing"

	"github.com/Zwlin98/netstack/tcpip"
)

func TestIPv4RoundTrip(t *testing.T) {
	buf := make([]byte, IPv4MinHeaderSize+10) // 20-byte header + 10 payload
	ip := IPv4(buf)

	fields := &IPv4Fields{
		TOS:            0,
		TotalLength:    30,
		ID:             0x1234,
		Flags:          0x02, // Don't Fragment
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       tcpip.TCPProtocolNumber,
		SrcAddr:        tcpip.From4(192, 168, 1, 1),
		DstAddr:        tcpip.From4(10, 0, 0, 1),
	}
	ip.Encode(fields)

	// Compute and set checksum.
	ip.SetChecksum(0)
	csum := Checksum(buf[:IPv4MinHeaderSize], 0)
	ip.SetChecksum(csum)

	// Verify all getters.
	if got := ip.HeaderLength(); got != 20 {
		t.Errorf("HeaderLength() = %d, want 20", got)
	}
	if got := ip.TotalLength(); got != 30 {
		t.Errorf("TotalLength() = %d, want 30", got)
	}
	if got := ip.ID(); got != 0x1234 {
		t.Errorf("ID() = 0x%04x, want 0x1234", got)
	}
	if got := ip.Flags(); got != 0x02 {
		t.Errorf("Flags() = %d, want 2", got)
	}
	if got := ip.FragmentOffset(); got != 0 {
		t.Errorf("FragmentOffset() = %d, want 0", got)
	}
	if got := ip.TTL(); got != 64 {
		t.Errorf("TTL() = %d, want 64", got)
	}
	if got := ip.Protocol(); got != tcpip.TCPProtocolNumber {
		t.Errorf("Protocol() = %d, want %d", got, tcpip.TCPProtocolNumber)
	}
	if got := ip.SourceAddress(); got != tcpip.From4(192, 168, 1, 1) {
		t.Errorf("SourceAddress() = %s, want 192.168.1.1", got)
	}
	if got := ip.DestinationAddress(); got != tcpip.From4(10, 0, 0, 1) {
		t.Errorf("DestinationAddress() = %s, want 10.0.0.1", got)
	}

	// Verify checksum.
	if got := Checksum(buf[:IPv4MinHeaderSize], 0); got != 0 {
		t.Errorf("checksum verification = 0x%04x, want 0x0000", got)
	}
}

func TestIPv4Payload(t *testing.T) {
	payload := []byte("hello")
	buf := make([]byte, IPv4MinHeaderSize+len(payload))
	copy(buf[IPv4MinHeaderSize:], payload)

	ip := IPv4(buf)
	ip.Encode(&IPv4Fields{
		TotalLength: uint16(IPv4MinHeaderSize + len(payload)),
		TTL:         64,
		Protocol:    tcpip.UDPProtocolNumber,
		SrcAddr:     tcpip.From4(1, 2, 3, 4),
		DstAddr:     tcpip.From4(5, 6, 7, 8),
	})

	got := ip.Payload()
	if string(got) != "hello" {
		t.Errorf("Payload() = %q, want %q", got, "hello")
	}

	// Verify payload shares underlying array (zero-copy).
	got[0] = 'H'
	if buf[IPv4MinHeaderSize] != 'H' {
		t.Error("Payload() should share backing array with original buffer")
	}
}

func TestIPv4KnownPacket(t *testing.T) {
	// Real captured IPv4 header: UDP packet from 192.168.0.1 to 192.168.0.199
	// 45 00 00 73 00 00 40 00 40 11 b8 61 c0 a8 00 01 c0 a8 00 c7
	raw := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}

	ip := IPv4(raw)

	if got := ip.HeaderLength(); got != 20 {
		t.Errorf("HeaderLength() = %d, want 20", got)
	}
	if got := ip.TotalLength(); got != 0x0073 {
		t.Errorf("TotalLength() = 0x%04x, want 0x0073", got)
	}
	if got := ip.ID(); got != 0x0000 {
		t.Errorf("ID() = 0x%04x, want 0x0000", got)
	}
	if got := ip.Flags(); got != 0x02 {
		t.Errorf("Flags() = %d, want 2 (DF)", got)
	}
	if got := ip.TTL(); got != 64 {
		t.Errorf("TTL() = %d, want 64", got)
	}
	if got := ip.Protocol(); got != tcpip.UDPProtocolNumber {
		t.Errorf("Protocol() = %d, want %d (UDP)", got, tcpip.UDPProtocolNumber)
	}
	if got := ip.SourceAddress(); got != tcpip.From4(192, 168, 0, 1) {
		t.Errorf("SourceAddress() = %s, want 192.168.0.1", got)
	}
	if got := ip.DestinationAddress(); got != tcpip.From4(192, 168, 0, 199) {
		t.Errorf("DestinationAddress() = %s, want 192.168.0.199", got)
	}

	// Checksum should verify.
	if got := Checksum(raw, 0); got != 0 {
		t.Errorf("checksum verification = 0x%04x, want 0x0000", got)
	}
}

func TestIPv4Setters(t *testing.T) {
	buf := make([]byte, IPv4MinHeaderSize)
	ip := IPv4(buf)
	ip.Encode(&IPv4Fields{TTL: 64, Protocol: tcpip.TCPProtocolNumber})

	ip.SetTTL(128)
	if ip.TTL() != 128 {
		t.Errorf("SetTTL: got %d, want 128", ip.TTL())
	}

	ip.SetID(0xABCD)
	if ip.ID() != 0xABCD {
		t.Errorf("SetID: got 0x%04x, want 0xABCD", ip.ID())
	}

	ip.SetTotalLength(1500)
	if ip.TotalLength() != 1500 {
		t.Errorf("SetTotalLength: got %d, want 1500", ip.TotalLength())
	}

	src := tcpip.From4(172, 16, 0, 1)
	ip.SetSourceAddress(src)
	if ip.SourceAddress() != src {
		t.Errorf("SetSourceAddress: got %s, want %s", ip.SourceAddress(), src)
	}

	dst := tcpip.From4(172, 16, 0, 2)
	ip.SetDestinationAddress(dst)
	if ip.DestinationAddress() != dst {
		t.Errorf("SetDestinationAddress: got %s, want %s", ip.DestinationAddress(), dst)
	}

	ip.SetProtocol(tcpip.UDPProtocolNumber)
	if ip.Protocol() != tcpip.UDPProtocolNumber {
		t.Errorf("SetProtocol: got %d, want %d", ip.Protocol(), tcpip.UDPProtocolNumber)
	}

	ip.SetFlags(0x02)
	if ip.Flags() != 0x02 {
		t.Errorf("SetFlags: got %d, want 2", ip.Flags())
	}
}
