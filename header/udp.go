package header

import "encoding/binary"

const UDPHeaderSize = 8

// UDP byte offsets.
const (
	udpSrcPort  = 0
	udpDstPort  = 2
	udpLength   = 4
	udpChecksum = 6
)

// UDPFields contains the fields of a UDP header for use with Encode.
type UDPFields struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

// UDP is a []byte view of a UDP header.
type UDP []byte

// SourcePort returns the source port.
func (b UDP) SourcePort() uint16 {
	return binary.BigEndian.Uint16(b[udpSrcPort:])
}

// DestinationPort returns the destination port.
func (b UDP) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(b[udpDstPort:])
}

// Length returns the length field (header + payload).
func (b UDP) Length() uint16 {
	return binary.BigEndian.Uint16(b[udpLength:])
}

// Checksum returns the checksum.
func (b UDP) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[udpChecksum:])
}

// SetSourcePort sets the source port.
func (b UDP) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(b[udpSrcPort:], port)
}

// SetDestinationPort sets the destination port.
func (b UDP) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(b[udpDstPort:], port)
}

// SetLength sets the length field.
func (b UDP) SetLength(length uint16) {
	binary.BigEndian.PutUint16(b[udpLength:], length)
}

// SetChecksum sets the checksum.
func (b UDP) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(b[udpChecksum:], v)
}

// Payload returns the bytes after the UDP header.
func (b UDP) Payload() []byte {
	return b[UDPHeaderSize:]
}

// Encode fills all fields from a UDPFields struct.
func (b UDP) Encode(f *UDPFields) {
	binary.BigEndian.PutUint16(b[udpSrcPort:], f.SrcPort)
	binary.BigEndian.PutUint16(b[udpDstPort:], f.DstPort)
	binary.BigEndian.PutUint16(b[udpLength:], f.Length)
	binary.BigEndian.PutUint16(b[udpChecksum:], f.Checksum)
}
