package header

import (
	"encoding/binary"

	"github.com/Zwlin98/netstack/tcpip"
)

const (
	IPv4MinHeaderSize = 20
	IPv4MaxHeaderSize = 60
	IPv4Version       = 4
)

const (
	IPv4FlagMoreFragments = 1 << iota
	IPv4FlagDontFragment
)

// IPv4 byte offsets.
const (
	ipv4VersionIHL    = 0
	ipv4TOS           = 1
	ipv4TotalLength   = 2
	ipv4ID            = 4
	ipv4FlagsFragment = 6
	ipv4TTL           = 8
	ipv4Protocol      = 9
	ipv4Checksum      = 10
	ipv4SrcAddr       = 12
	ipv4DstAddr       = 16
)

// IPv4Fields contains the fields of an IPv4 header for use with Encode.
type IPv4Fields struct {
	TOS            uint8
	TotalLength    uint16
	ID             uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       tcpip.TransportProtocolNumber
	Checksum       uint16
	SrcAddr        tcpip.Address
	DstAddr        tcpip.Address
}

// IPv4 is a []byte view of an IPv4 header.
type IPv4 []byte

// HeaderLength returns the header length in bytes (IHL * 4).
func (b IPv4) HeaderLength() int {
	return int(b[ipv4VersionIHL]&0x0f) * 4
}

// TotalLength returns the total packet length including header and payload.
func (b IPv4) TotalLength() uint16 {
	return binary.BigEndian.Uint16(b[ipv4TotalLength:])
}

// Protocol returns the transport protocol number.
func (b IPv4) Protocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b[ipv4Protocol])
}

// SourceAddress returns the source IPv4 address.
func (b IPv4) SourceAddress() tcpip.Address {
	return tcpip.Address(binary.BigEndian.Uint32(b[ipv4SrcAddr:]))
}

// DestinationAddress returns the destination IPv4 address.
func (b IPv4) DestinationAddress() tcpip.Address {
	return tcpip.Address(binary.BigEndian.Uint32(b[ipv4DstAddr:]))
}

// TTL returns the time-to-live field.
func (b IPv4) TTL() uint8 {
	return b[ipv4TTL]
}

// Checksum returns the header checksum.
func (b IPv4) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[ipv4Checksum:])
}

// ID returns the identification field.
func (b IPv4) ID() uint16 {
	return binary.BigEndian.Uint16(b[ipv4ID:])
}

// Flags returns the 3-bit flags field.
func (b IPv4) Flags() uint8 {
	return b[ipv4FlagsFragment] >> 5
}

// More reports whether the more fragments flag is set.
func (b IPv4) More() bool {
	return b.Flags()&IPv4FlagMoreFragments != 0
}

// FragmentOffset returns the 13-bit fragment offset (in 8-byte units).
func (b IPv4) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[ipv4FlagsFragment:]) & 0x1fff
}

// TOS returns the type of service field.
func (b IPv4) TOS() uint8 {
	return b[ipv4TOS]
}

// SetTotalLength sets the total length field.
func (b IPv4) SetTotalLength(length uint16) {
	binary.BigEndian.PutUint16(b[ipv4TotalLength:], length)
}

// SetProtocol sets the protocol field.
func (b IPv4) SetProtocol(proto tcpip.TransportProtocolNumber) {
	b[ipv4Protocol] = byte(proto)
}

// SetSourceAddress sets the source address.
func (b IPv4) SetSourceAddress(addr tcpip.Address) {
	binary.BigEndian.PutUint32(b[ipv4SrcAddr:], uint32(addr))
}

// SetDestinationAddress sets the destination address.
func (b IPv4) SetDestinationAddress(addr tcpip.Address) {
	binary.BigEndian.PutUint32(b[ipv4DstAddr:], uint32(addr))
}

// SetTTL sets the time-to-live field.
func (b IPv4) SetTTL(ttl uint8) {
	b[ipv4TTL] = ttl
}

// SetChecksum sets the header checksum.
func (b IPv4) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(b[ipv4Checksum:], v)
}

// SetID sets the identification field.
func (b IPv4) SetID(id uint16) {
	binary.BigEndian.PutUint16(b[ipv4ID:], id)
}

// SetFlags sets the 3-bit flags field.
func (b IPv4) SetFlags(flags uint8) {
	b[ipv4FlagsFragment] = (flags << 5) | (b[ipv4FlagsFragment] & 0x1f)
}

// SetFlagsFragmentOffset sets the flags and fragment offset fields.
func (b IPv4) SetFlagsFragmentOffset(flags uint8, offset uint16) {
	flagsFrag := uint16(flags)<<13 | (offset & 0x1fff)
	binary.BigEndian.PutUint16(b[ipv4FlagsFragment:], flagsFrag)
}

// Encode fills all fields from an IPv4Fields struct.
// It sets version=4, IHL=5 (20-byte fixed header, no options).
func (b IPv4) Encode(f *IPv4Fields) {
	b[ipv4VersionIHL] = (IPv4Version << 4) | 5 // version 4, IHL 5
	b[ipv4TOS] = f.TOS
	binary.BigEndian.PutUint16(b[ipv4TotalLength:], f.TotalLength)
	binary.BigEndian.PutUint16(b[ipv4ID:], f.ID)
	flagsFrag := uint16(f.Flags)<<13 | (f.FragmentOffset & 0x1fff)
	binary.BigEndian.PutUint16(b[ipv4FlagsFragment:], flagsFrag)
	b[ipv4TTL] = f.TTL
	b[ipv4Protocol] = byte(f.Protocol)
	binary.BigEndian.PutUint16(b[ipv4Checksum:], f.Checksum)
	binary.BigEndian.PutUint32(b[ipv4SrcAddr:], uint32(f.SrcAddr))
	binary.BigEndian.PutUint32(b[ipv4DstAddr:], uint32(f.DstAddr))
}

// Payload returns the bytes after the IP header.
func (b IPv4) Payload() []byte {
	hdrLen := b.HeaderLength()
	return b[hdrLen:]
}
