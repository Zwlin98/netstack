package header

import "testing"

func TestICMPv4RoundTrip(t *testing.T) {
	payload := []byte("ping data here!")
	buf := make([]byte, ICMPv4HeaderSize+len(payload))
	copy(buf[ICMPv4HeaderSize:], payload)
	icmp := ICMPv4(buf)

	icmp.Encode(&ICMPv4Fields{
		Type:     ICMPv4Echo,
		Code:     0,
		Ident:    0x1234,
		Sequence: 1,
	})

	// Compute checksum over the whole ICMP message.
	icmp.SetChecksum(0)
	csum := Checksum(buf, 0)
	icmp.SetChecksum(csum)

	if got := icmp.Type(); got != ICMPv4Echo {
		t.Errorf("Type() = %d, want %d (Echo)", got, ICMPv4Echo)
	}
	if got := icmp.Code(); got != 0 {
		t.Errorf("Code() = %d, want 0", got)
	}
	if got := icmp.Ident(); got != 0x1234 {
		t.Errorf("Ident() = 0x%04x, want 0x1234", got)
	}
	if got := icmp.Sequence(); got != 1 {
		t.Errorf("Sequence() = %d, want 1", got)
	}
	if got := string(icmp.Payload()); got != "ping data here!" {
		t.Errorf("Payload() = %q, want %q", got, "ping data here!")
	}

	// Verify checksum.
	if got := Checksum(buf, 0); got != 0 {
		t.Errorf("checksum verification = 0x%04x, want 0x0000", got)
	}
}

func TestICMPv4EchoToReply(t *testing.T) {
	// Simulate converting an echo request to an echo reply.
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	buf := make([]byte, ICMPv4HeaderSize+len(payload))
	copy(buf[ICMPv4HeaderSize:], payload)
	icmp := ICMPv4(buf)

	// Encode as Echo request.
	icmp.Encode(&ICMPv4Fields{
		Type:     ICMPv4Echo,
		Code:     0,
		Ident:    0x5678,
		Sequence: 42,
	})
	icmp.SetChecksum(0)
	icmp.SetChecksum(Checksum(buf, 0))

	// Verify echo request checksum.
	if got := Checksum(buf, 0); got != 0 {
		t.Fatalf("echo request checksum verification failed: 0x%04x", got)
	}

	// Convert to echo reply: change type, recalculate checksum.
	icmp.SetType(ICMPv4EchoReply)
	icmp.SetChecksum(0)
	icmp.SetChecksum(Checksum(buf, 0))

	if got := icmp.Type(); got != ICMPv4EchoReply {
		t.Errorf("Type() = %d, want %d (EchoReply)", got, ICMPv4EchoReply)
	}
	// Ident and Sequence should be preserved.
	if got := icmp.Ident(); got != 0x5678 {
		t.Errorf("Ident() = 0x%04x, want 0x5678", got)
	}
	if got := icmp.Sequence(); got != 42 {
		t.Errorf("Sequence() = %d, want 42", got)
	}

	// Verify reply checksum.
	if got := Checksum(buf, 0); got != 0 {
		t.Errorf("echo reply checksum verification = 0x%04x, want 0x0000", got)
	}
}

func TestICMPv4KnownPacket(t *testing.T) {
	// Known ICMP echo request packet bytes (header only, 8 bytes):
	// Type=8, Code=0, Checksum=0xf7fd, Ident=0x0001, Sequence=0x0001
	raw := []byte{
		0x08, 0x00, 0xf7, 0xfd, 0x00, 0x01, 0x00, 0x01,
	}
	icmp := ICMPv4(raw)

	if got := icmp.Type(); got != ICMPv4Echo {
		t.Errorf("Type() = %d, want %d", got, ICMPv4Echo)
	}
	if got := icmp.Code(); got != 0 {
		t.Errorf("Code() = %d, want 0", got)
	}
	if got := icmp.Ident(); got != 0x0001 {
		t.Errorf("Ident() = 0x%04x, want 0x0001", got)
	}
	if got := icmp.Sequence(); got != 0x0001 {
		t.Errorf("Sequence() = 0x%04x, want 0x0001", got)
	}

	// ICMP checksum covers the entire message (header + payload).
	// With just the 8-byte header, verify the checksum.
	if got := Checksum(raw, 0); got != 0 {
		t.Errorf("checksum verification = 0x%04x, want 0x0000", got)
	}
}

func TestICMPv4Setters(t *testing.T) {
	buf := make([]byte, ICMPv4HeaderSize)
	icmp := ICMPv4(buf)

	icmp.SetType(ICMPv4DstUnreachable)
	if icmp.Type() != ICMPv4DstUnreachable {
		t.Errorf("SetType: got %d, want %d", icmp.Type(), ICMPv4DstUnreachable)
	}

	icmp.SetCode(3)
	if icmp.Code() != 3 {
		t.Errorf("SetCode: got %d, want 3", icmp.Code())
	}

	icmp.SetIdent(0xABCD)
	if icmp.Ident() != 0xABCD {
		t.Errorf("SetIdent: got 0x%04x, want 0xABCD", icmp.Ident())
	}

	icmp.SetSequence(100)
	if icmp.Sequence() != 100 {
		t.Errorf("SetSequence: got %d, want 100", icmp.Sequence())
	}
}
