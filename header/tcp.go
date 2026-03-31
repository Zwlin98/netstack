package header

import (
	"encoding/binary"
	"strings"
)

const (
	TCPMinHeaderSize = 20
	TCPMaxHeaderSize = 60

	// TCP option kinds.
	TCPOptionEOL           = 0
	TCPOptionNOP           = 1
	TCPOptionMSS           = 2
	TCPOptionWS            = 3
	TCPOptionSACKPermitted = 4
	TCPOptionSACK          = 5
	TCPOptionTS            = 8

	// TCP option lengths.
	TCPOptionMSSLength           = 4
	TCPOptionWSLength            = 3
	TCPOptionSACKPermittedLength = 2
	TCPOptionTSLength            = 10

	// MaxWndScale is the maximum window scale shift (RFC 7323).
	MaxWndScale = 14

	// TCPMaxSACKBlocks is the maximum number of SACK blocks per segment.
	TCPMaxSACKBlocks = 4
)

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

// Options returns the TCP options bytes (between header and payload).
// Returns nil if DataOffset equals TCPMinHeaderSize.
func (b TCP) Options() []byte {
	offset := int(b.DataOffset())
	if offset <= TCPMinHeaderSize || offset > len(b) {
		return nil
	}
	return b[TCPMinHeaderSize:offset]
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

// SACKBlock represents a SACK block with [Start, End) byte range.
type SACKBlock struct {
	Start uint32
	End   uint32
}

// SynOptions holds options parsed from a SYN or SYN+ACK segment.
type SynOptions struct {
	MSS        uint16 // Maximum Segment Size (0 if not present)
	WS         int    // Window Scale shift count (-1 if not present)
	SACKPermit bool   // SACK Permitted
	TSEnabled  bool   // Timestamp option present
	TSVal      uint32 // Timestamp value from peer
}

// SegmentOptions holds options parsed from a regular (non-SYN) segment.
type SegmentOptions struct {
	SACKBlocks []SACKBlock
	TSEnabled  bool   // Timestamp option present
	TSVal      uint32 // Timestamp value from peer
	TSecr      uint32 // Timestamp echo reply
}

// ParseSynOptions parses TCP options from a SYN or SYN+ACK segment.
func ParseSynOptions(opts []byte) SynOptions {
	so := SynOptions{WS: -1}
	for i := 0; i < len(opts); {
		switch opts[i] {
		case TCPOptionEOL:
			return so
		case TCPOptionNOP:
			i++
			continue
		}
		// All other options have kind + length.
		if i+1 >= len(opts) {
			return so
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			return so
		}
		switch opts[i] {
		case TCPOptionMSS:
			if optLen == TCPOptionMSSLength {
				so.MSS = binary.BigEndian.Uint16(opts[i+2:])
			}
		case TCPOptionWS:
			if optLen == TCPOptionWSLength {
				so.WS = min(int(opts[i+2]), MaxWndScale)
			}
		case TCPOptionSACKPermitted:
			if optLen == TCPOptionSACKPermittedLength {
				so.SACKPermit = true
			}
		case TCPOptionTS:
			if optLen == TCPOptionTSLength {
				so.TSEnabled = true
				so.TSVal = binary.BigEndian.Uint32(opts[i+2:])
			}
		}
		i += optLen
	}
	return so
}

// ParseSegmentOptions parses TCP options from a regular segment (SACK blocks).
func ParseSegmentOptions(opts []byte) SegmentOptions {
	var so SegmentOptions
	for i := 0; i < len(opts); {
		switch opts[i] {
		case TCPOptionEOL:
			return so
		case TCPOptionNOP:
			i++
			continue
		}
		if i+1 >= len(opts) {
			return so
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			return so
		}
		switch opts[i] {
		case TCPOptionSACK:
			payload := optLen - 2
			if payload%8 == 0 {
				numBlocks := min(payload/8, TCPMaxSACKBlocks)
				so.SACKBlocks = make([]SACKBlock, numBlocks)
				for j := range numBlocks {
					off := i + 2 + j*8
					so.SACKBlocks[j] = SACKBlock{
						Start: binary.BigEndian.Uint32(opts[off:]),
						End:   binary.BigEndian.Uint32(opts[off+4:]),
					}
				}
			}
		case TCPOptionTS:
			if optLen == TCPOptionTSLength {
				so.TSEnabled = true
				so.TSVal = binary.BigEndian.Uint32(opts[i+2:])
				so.TSecr = binary.BigEndian.Uint32(opts[i+6:])
			}
		}
		i += optLen
	}
	return so
}

// EncodeMSSOption writes the MSS option into buf.
// Returns the number of bytes written.
func EncodeMSSOption(buf []byte, mss uint16) int {
	if len(buf) < TCPOptionMSSLength {
		return 0
	}
	buf[0] = TCPOptionMSS
	buf[1] = TCPOptionMSSLength
	binary.BigEndian.PutUint16(buf[2:], mss)
	return TCPOptionMSSLength
}

// EncodeWSOption writes the Window Scale option into buf.
// Returns the number of bytes written.
func EncodeWSOption(buf []byte, ws int) int {
	if len(buf) < TCPOptionWSLength {
		return 0
	}
	buf[0] = TCPOptionWS
	buf[1] = TCPOptionWSLength
	buf[2] = byte(ws)
	return TCPOptionWSLength
}

// EncodeSACKPermittedOption writes the SACK Permitted option into buf.
// Returns the number of bytes written.
func EncodeSACKPermittedOption(buf []byte) int {
	if len(buf) < TCPOptionSACKPermittedLength {
		return 0
	}
	buf[0] = TCPOptionSACKPermitted
	buf[1] = TCPOptionSACKPermittedLength
	return TCPOptionSACKPermittedLength
}

// EncodeTimestampOption writes NOP+NOP+Timestamp option into buf (12 bytes total).
// Returns the number of bytes written.
func EncodeTimestampOption(buf []byte, tsval, tsecr uint32) int {
	if len(buf) < 12 {
		return 0
	}
	buf[0] = TCPOptionNOP
	buf[1] = TCPOptionNOP
	buf[2] = TCPOptionTS
	buf[3] = TCPOptionTSLength
	binary.BigEndian.PutUint32(buf[4:], tsval)
	binary.BigEndian.PutUint32(buf[8:], tsecr)
	return 12
}

// EncodeSACKBlocks writes SACK blocks into buf.
// Returns the number of bytes written.
func EncodeSACKBlocks(buf []byte, blocks []SACKBlock) int {
	n := min(len(blocks), TCPMaxSACKBlocks)
	needed := 2 + n*8
	for needed > len(buf) && n > 0 {
		n--
		needed = 2 + n*8
	}
	if n == 0 {
		return 0
	}
	buf[0] = TCPOptionSACK
	buf[1] = byte(needed)
	for i := range n {
		off := 2 + i*8
		binary.BigEndian.PutUint32(buf[off:], blocks[i].Start)
		binary.BigEndian.PutUint32(buf[off+4:], blocks[i].End)
	}
	return needed
}
