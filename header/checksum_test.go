package header

import (
	"testing"

	"github.com/Zwlin98/netstack/tcpip"
)

func TestChecksumRFC1071(t *testing.T) {
	// RFC 1071 example: 0x0001 + 0xf203 + ... = checksum
	// Use a real IPv4 header to validate.
	// IPv4 header from a real capture:
	// 45 00 00 3c 1c 46 40 00 40 06 00 00 ac 10 0a 63 ac 10 0a 0c
	// The checksum field (bytes 10-11) is zeroed for computation.
	hdr := []byte{
		0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
		0xac, 0x10, 0x0a, 0x0c,
	}

	got := Checksum(hdr, 0)
	if got != 0 {
		// When we include a correct checksum in the data, result should be 0.
		// But the checksum field is zeroed here, so compute the expected value.
		// Let's compute without the checksum field and verify.
	}

	// Compute checksum with the checksum field zeroed out.
	csum := Checksum(hdr, 0)
	// Fill in the checksum and verify.
	hdr[10] = byte(csum >> 8)
	hdr[11] = byte(csum)

	// Now verification: checksum over the complete header should be 0.
	verify := Checksum(hdr, 0)
	if verify != 0 {
		t.Errorf("verification checksum = 0x%04x, want 0x0000", verify)
	}
}

func TestChecksumEmpty(t *testing.T) {
	got := Checksum(nil, 0)
	if got != 0xffff {
		t.Errorf("Checksum(nil, 0) = 0x%04x, want 0xffff", got)
	}
}

func TestChecksumOddLength(t *testing.T) {
	// Single byte 0x01 → sum = 0x0100 → complement = 0xfeff
	data := []byte{0x01}
	got := Checksum(data, 0)
	if got != 0xfeff {
		t.Errorf("Checksum([0x01], 0) = 0x%04x, want 0xfeff", got)
	}
}

func TestChecksumKnownIPv4(t *testing.T) {
	// Known IPv4 header with correct checksum b1e6:
	// 45 00 00 73 00 00 40 00 40 11 b8 61 c0 a8 00 01 c0 a8 00 c7
	hdr := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}
	// Verify: checksum over complete header with valid checksum should be 0.
	got := Checksum(hdr, 0)
	if got != 0 {
		t.Errorf("checksum over valid IPv4 header = 0x%04x, want 0x0000", got)
	}
}

func TestPseudoHeaderChecksum(t *testing.T) {
	src := tcpip.From4(192, 168, 0, 1)
	dst := tcpip.From4(192, 168, 0, 199)

	// Compute pseudo-header checksum for a UDP packet.
	phc := PseudoHeaderChecksum(tcpip.UDPProtocolNumber, src, dst, 95)

	// The pseudo-header partial checksum should be non-zero.
	if phc == 0 {
		t.Error("PseudoHeaderChecksum should return non-zero partial checksum")
	}

	// Verify it produces a valid checksum when combined with the transport data.
	// We'll construct a minimal pseudo-header manually and compare.
	var pseudo [12]byte
	srcB := src.To4()
	dstB := dst.To4()
	copy(pseudo[0:4], srcB[:])
	copy(pseudo[4:8], dstB[:])
	pseudo[8] = 0
	pseudo[9] = 17 // UDP
	pseudo[10] = 0
	pseudo[11] = 95

	manualCsum := Checksum(pseudo[:], 0)
	// phc is the un-complemented accumulator, manualCsum is complemented.
	// They should complement to the same value.
	if ^phc != manualCsum {
		t.Errorf("PseudoHeaderChecksum mismatch: ^phc=0x%04x, manual=0x%04x", ^phc, manualCsum)
	}
}
