package header

import (
	"encoding/binary"
	"strings"
)

const TCPMinHeaderSize = 20

// TCP byte offsets.
const (
	tcpSrcPort       = 0
	tcpDstPort       = 2
	tcpSeqNum        = 4
	tcpAckNum        = 8
	tcpDataOffset    = 12
	tcpFlags         = 13
	tcpWindowSize    = 14
	tcpChecksum      = 16
	tcpUrgentPointer = 18
)

// TCPFlags is a bitmask of TCP flags.
type TCPFlags uint8

const (
	TCPFlagFIN TCPFlags = 1 << iota
	TCPFlagSYN
	TCPFlagRST
	TCPFlagPSH
	TCPFlagACK
	TCPFlagURG
)

// Has reports whether f contains all flags in mask.
func (f TCPFlags) Has(mask TCPFlags) bool {
	return f&mask == mask
}

// Contains reports whether f contains all flags in mask. Alias for Has.
func (f TCPFlags) Contains(mask TCPFlags) bool {
	return f.Has(mask)
}

// String returns a human-readable representation like "SYN|ACK".
func (f TCPFlags) String() string {
	var parts []string
	if f.Has(TCPFlagFIN) {
		parts = append(parts, "FIN")
	}
	if f.Has(TCPFlagSYN) {
		parts = append(parts, "SYN")
	}
	if f.Has(TCPFlagRST) {
		parts = append(parts, "RST")
	}
	if f.Has(TCPFlagPSH) {
		parts = append(parts, "PSH")
	}
	if f.Has(TCPFlagACK) {
		parts = append(parts, "ACK")
	}
	if f.Has(TCPFlagURG) {
		parts = append(parts, "URG")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

// TCPFields contains the fields of a TCP header for use with Encode.
type TCPFields struct {
	SrcPort       uint16
	DstPort       uint16
	SeqNum        uint32
	AckNum        uint32
	DataOffset    uint8 // in 32-bit words
	Flags         TCPFlags
	WindowSize    uint16
	Checksum      uint16
	UrgentPointer uint16
}

// TCP is a []byte view of a TCP header.
type TCP []byte

// SourcePort returns the source port.
func (b TCP) SourcePort() uint16 {
	return binary.BigEndian.Uint16(b[tcpSrcPort:])
}

// DestinationPort returns the destination port.
func (b TCP) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(b[tcpDstPort:])
}

// SequenceNumber returns the sequence number.
func (b TCP) SequenceNumber() uint32 {
	return binary.BigEndian.Uint32(b[tcpSeqNum:])
}

// AckNumber returns the acknowledgment number.
func (b TCP) AckNumber() uint32 {
	return binary.BigEndian.Uint32(b[tcpAckNum:])
}

// DataOffset returns the data offset in bytes (header length).
func (b TCP) DataOffset() uint8 {
	return (b[tcpDataOffset] >> 4) * 4
}

// Flags returns the TCP flags.
func (b TCP) Flags() TCPFlags {
	return TCPFlags(b[tcpFlags] & 0x3f)
}

// WindowSize returns the window size.
func (b TCP) WindowSize() uint16 {
	return binary.BigEndian.Uint16(b[tcpWindowSize:])
}

// Checksum returns the checksum.
func (b TCP) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[tcpChecksum:])
}

// UrgentPointer returns the urgent pointer.
func (b TCP) UrgentPointer() uint16 {
	return binary.BigEndian.Uint16(b[tcpUrgentPointer:])
}

// SetSourcePort sets the source port.
func (b TCP) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(b[tcpSrcPort:], port)
}

// SetDestinationPort sets the destination port.
func (b TCP) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(b[tcpDstPort:], port)
}

// SetChecksum sets the checksum.
func (b TCP) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(b[tcpChecksum:], v)
}

// Payload returns the bytes after the TCP header.
func (b TCP) Payload() []byte {
	offset := b.DataOffset()
	return b[offset:]
}

// Encode fills all fields from a TCPFields struct.
func (b TCP) Encode(f *TCPFields) {
	binary.BigEndian.PutUint16(b[tcpSrcPort:], f.SrcPort)
	binary.BigEndian.PutUint16(b[tcpDstPort:], f.DstPort)
	binary.BigEndian.PutUint32(b[tcpSeqNum:], f.SeqNum)
	binary.BigEndian.PutUint32(b[tcpAckNum:], f.AckNum)
	b[tcpDataOffset] = f.DataOffset << 4
	b[tcpFlags] = uint8(f.Flags)
	binary.BigEndian.PutUint16(b[tcpWindowSize:], f.WindowSize)
	binary.BigEndian.PutUint16(b[tcpChecksum:], f.Checksum)
	binary.BigEndian.PutUint16(b[tcpUrgentPointer:], f.UrgentPointer)
}
