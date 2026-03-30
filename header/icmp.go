package header

import "encoding/binary"

const ICMPv4HeaderSize = 8

// ICMPv4 byte offsets.
const (
	icmpv4Type     = 0
	icmpv4Code     = 1
	icmpv4Checksum = 2
	icmpv4Ident    = 4
	icmpv4Sequence = 6
)

// ICMPv4Type is the ICMP message type.
type ICMPv4Type uint8

const (
	ICMPv4EchoReply      ICMPv4Type = 0
	ICMPv4DstUnreachable ICMPv4Type = 3
	ICMPv4Echo           ICMPv4Type = 8
	ICMPv4TimeExceeded   ICMPv4Type = 11
)

// ICMPv4Fields contains the fields of an ICMPv4 header for use with Encode.
type ICMPv4Fields struct {
	Type     ICMPv4Type
	Code     uint8
	Checksum uint16
	Ident    uint16
	Sequence uint16
}

// ICMPv4 is a []byte view of an ICMPv4 header.
type ICMPv4 []byte

// Type returns the ICMP type.
func (b ICMPv4) Type() ICMPv4Type {
	return ICMPv4Type(b[icmpv4Type])
}

// Code returns the ICMP code.
func (b ICMPv4) Code() uint8 {
	return b[icmpv4Code]
}

// Checksum returns the checksum.
func (b ICMPv4) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4Checksum:])
}

// Ident returns the identifier (for echo request/reply).
func (b ICMPv4) Ident() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4Ident:])
}

// Sequence returns the sequence number (for echo request/reply).
func (b ICMPv4) Sequence() uint16 {
	return binary.BigEndian.Uint16(b[icmpv4Sequence:])
}

// SetType sets the ICMP type.
func (b ICMPv4) SetType(typ ICMPv4Type) {
	b[icmpv4Type] = uint8(typ)
}

// SetCode sets the ICMP code.
func (b ICMPv4) SetCode(code uint8) {
	b[icmpv4Code] = code
}

// SetChecksum sets the checksum.
func (b ICMPv4) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(b[icmpv4Checksum:], v)
}

// SetIdent sets the identifier.
func (b ICMPv4) SetIdent(id uint16) {
	binary.BigEndian.PutUint16(b[icmpv4Ident:], id)
}

// SetSequence sets the sequence number.
func (b ICMPv4) SetSequence(seq uint16) {
	binary.BigEndian.PutUint16(b[icmpv4Sequence:], seq)
}

// Payload returns the bytes after the ICMP header.
func (b ICMPv4) Payload() []byte {
	return b[ICMPv4HeaderSize:]
}

// Encode fills all fields from an ICMPv4Fields struct.
func (b ICMPv4) Encode(f *ICMPv4Fields) {
	b[icmpv4Type] = uint8(f.Type)
	b[icmpv4Code] = f.Code
	binary.BigEndian.PutUint16(b[icmpv4Checksum:], f.Checksum)
	binary.BigEndian.PutUint16(b[icmpv4Ident:], f.Ident)
	binary.BigEndian.PutUint16(b[icmpv4Sequence:], f.Sequence)
}
