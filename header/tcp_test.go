package header

import (
	"testing"

	"github.com/Zwlin98/netstack/tcpip"
)

func TestTCPFlagsString(t *testing.T) {
	tests := []struct {
		flags TCPFlags
		want  string
	}{
		{TCPFlagSYN, "SYN"},
		{TCPFlagSYN | TCPFlagACK, "SYN|ACK"},
		{TCPFlagFIN | TCPFlagACK, "FIN|ACK"},
		{TCPFlagRST, "RST"},
		{TCPFlagPSH | TCPFlagACK, "PSH|ACK"},
		{0, "none"},
		{TCPFlagFIN | TCPFlagSYN | TCPFlagRST | TCPFlagPSH | TCPFlagACK | TCPFlagURG, "FIN|SYN|RST|PSH|ACK|URG"},
	}
	for _, tt := range tests {
		if got := tt.flags.String(); got != tt.want {
			t.Errorf("TCPFlags(%d).String() = %q, want %q", tt.flags, got, tt.want)
		}
	}
}

func TestTCPFlagsHas(t *testing.T) {
	f := TCPFlagSYN | TCPFlagACK
	if !f.Has(TCPFlagSYN) {
		t.Error("SYN|ACK should have SYN")
	}
	if !f.Has(TCPFlagACK) {
		t.Error("SYN|ACK should have ACK")
	}
	if f.Has(TCPFlagFIN) {
		t.Error("SYN|ACK should not have FIN")
	}
	if !f.Contains(TCPFlagSYN | TCPFlagACK) {
		t.Error("SYN|ACK should contain SYN|ACK")
	}
}

func TestTCPRoundTrip(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\n")
	buf := make([]byte, TCPMinHeaderSize+len(payload))
	copy(buf[TCPMinHeaderSize:], payload)
	tcp := TCP(buf)

	fields := &TCPFields{
		SrcPort:       12345,
		DstPort:       80,
		SeqNum:        0x01020304,
		AckNum:        0x05060708,
		DataOffset:    5, // 20 bytes
		Flags:         TCPFlagPSH | TCPFlagACK,
		WindowSize:    65535,
		Checksum:      0,
		UrgentPointer: 0,
	}
	tcp.Encode(fields)

	if got := tcp.SourcePort(); got != 12345 {
		t.Errorf("SourcePort() = %d, want 12345", got)
	}
	if got := tcp.DestinationPort(); got != 80 {
		t.Errorf("DestinationPort() = %d, want 80", got)
	}
	if got := tcp.SequenceNumber(); got != 0x01020304 {
		t.Errorf("SequenceNumber() = 0x%08x, want 0x01020304", got)
	}
	if got := tcp.AckNumber(); got != 0x05060708 {
		t.Errorf("AckNumber() = 0x%08x, want 0x05060708", got)
	}
	if got := tcp.DataOffset(); got != 20 {
		t.Errorf("DataOffset() = %d, want 20", got)
	}
	if got := tcp.Flags(); !got.Has(TCPFlagPSH | TCPFlagACK) {
		t.Errorf("Flags() = %s, want PSH|ACK", got)
	}
	if got := tcp.WindowSize(); got != 65535 {
		t.Errorf("WindowSize() = %d, want 65535", got)
	}
	if got := string(tcp.Payload()); got != "GET / HTTP/1.1\r\n" {
		t.Errorf("Payload() = %q, want %q", got, "GET / HTTP/1.1\r\n")
	}
}

func TestTCPKnownSYNPacket(t *testing.T) {
	// Real TCP SYN packet (20-byte header, no options, no payload)
	// Src port: 49152, Dst port: 80, Seq: 0x12345678, Ack: 0, DataOff: 5, Flags: SYN, Win: 65535
	raw := make([]byte, TCPMinHeaderSize)
	tcp := TCP(raw)
	tcp.Encode(&TCPFields{
		SrcPort:    49152,
		DstPort:    80,
		SeqNum:     0x12345678,
		AckNum:     0,
		DataOffset: 5,
		Flags:      TCPFlagSYN,
		WindowSize: 65535,
	})

	if got := tcp.SourcePort(); got != 49152 {
		t.Errorf("SrcPort = %d, want 49152", got)
	}
	if got := tcp.DestinationPort(); got != 80 {
		t.Errorf("DstPort = %d, want 80", got)
	}
	if !tcp.Flags().Has(TCPFlagSYN) {
		t.Error("should have SYN flag")
	}
	if tcp.Flags().Has(TCPFlagACK) {
		t.Error("should not have ACK flag")
	}
}

func TestTCPKnownSYNACKPacket(t *testing.T) {
	raw := make([]byte, TCPMinHeaderSize)
	tcp := TCP(raw)
	tcp.Encode(&TCPFields{
		SrcPort:    80,
		DstPort:    49152,
		SeqNum:     0xAABBCCDD,
		AckNum:     0x12345679,
		DataOffset: 5,
		Flags:      TCPFlagSYN | TCPFlagACK,
		WindowSize: 28960,
	})

	if got := tcp.Flags(); !got.Has(TCPFlagSYN | TCPFlagACK) {
		t.Errorf("flags = %s, want SYN|ACK", got)
	}
	if got := tcp.AckNumber(); got != 0x12345679 {
		t.Errorf("AckNum = 0x%08x, want 0x12345679", got)
	}
}

func TestTCPChecksumWithPseudoHeader(t *testing.T) {
	src := tcpip.From4(192, 168, 1, 1)
	dst := tcpip.From4(192, 168, 1, 2)

	payload := []byte("hello")
	totalLen := uint16(TCPMinHeaderSize + len(payload))
	buf := make([]byte, int(totalLen))
	copy(buf[TCPMinHeaderSize:], payload)

	tcp := TCP(buf)
	tcp.Encode(&TCPFields{
		SrcPort:    1234,
		DstPort:    5678,
		SeqNum:     1,
		AckNum:     0,
		DataOffset: 5,
		Flags:      TCPFlagSYN,
		WindowSize: 65535,
	})

	// Compute checksum.
	tcp.SetChecksum(0)
	phc := PseudoHeaderChecksum(tcpip.TCPProtocolNumber, src, dst, totalLen)
	csum := Checksum(buf, phc)
	tcp.SetChecksum(csum)

	// Verify: checksum over pseudo-header + full segment should be 0.
	phc2 := PseudoHeaderChecksum(tcpip.TCPProtocolNumber, src, dst, totalLen)
	verify := Checksum(buf, phc2)
	if verify != 0 {
		t.Errorf("TCP checksum verification = 0x%04x, want 0x0000", verify)
	}
}
