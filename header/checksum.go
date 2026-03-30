package header

import (
	"encoding/binary"

	"github.com/Zwlin98/netstack/tcpip"
)

// Checksum computes the internet checksum (RFC 1071) over the given bytes.
// The initial parameter allows chaining: pass the result of a previous
// Checksum or PseudoHeaderChecksum call to accumulate.
func Checksum(b []byte, initial uint16) uint16 {
	sum := uint32(initial)

	// Sum 16-bit words.
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}

	// Handle odd byte.
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}

	// Fold 32-bit sum into 16 bits.
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return ^uint16(sum)
}

// PseudoHeaderChecksum computes the TCP/UDP pseudo-header checksum.
// The result should be passed as the initial value to Checksum when
// computing the full transport checksum.
func PseudoHeaderChecksum(proto tcpip.TransportProtocolNumber, src, dst tcpip.Address, totalLen uint16) uint16 {
	var buf [12]byte

	// Source address (4 bytes).
	srcBytes := src.To4()
	copy(buf[0:4], srcBytes[:])

	// Destination address (4 bytes).
	dstBytes := dst.To4()
	copy(buf[4:8], dstBytes[:])

	// Zero, protocol, total length.
	buf[8] = 0
	buf[9] = byte(proto)
	binary.BigEndian.PutUint16(buf[10:12], totalLen)

	// Compute partial checksum (without complement — undo the NOT).
	csum := Checksum(buf[:], 0)
	return ^csum // return the un-complemented accumulator
}
