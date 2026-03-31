// Package packet provides a PacketBuffer type for efficient network packet
package packet

import "sync"

const (
	// MaxHeadroom is the maximum headroom reserved for headers.
	// 20 (IPv4) + 20 (TCP base) + 28 (TCP options: 3 SACK blocks padded) = 68.
	// Rounded up to 80 for margin.
	MaxHeadroom = 80

	// MaxPacketSize is the maximum total buffer size.
	MaxPacketSize = 1560
)

// PacketBuffer is a buffer for network packets that supports zero-copy
// header prepending via headroom and object pooling via sync.Pool.
type PacketBuffer struct {
	buf []byte // backing storage

	// Headroom tracking.
	headroom int // total headroom reserved
	consumed int // headroom consumed by Prepend

	// Header views (set during parsing or construction).
	NetworkHeader   []byte // slice into buf for IP header
	TransportHeader []byte // slice into buf for TCP/UDP/ICMP header
	Data            []byte // slice into buf for payload
}

var pool = sync.Pool{
	New: func() any {
		return &PacketBuffer{
			buf: make([]byte, MaxPacketSize),
		}
	},
}

// NewPacketBuffer allocates a PacketBuffer from the pool with the given
// headroom reserved. Used for the send path where headers are prepended.
func NewPacketBuffer(headroom int) *PacketBuffer {
	pb := pool.Get().(*PacketBuffer)
	pb.reset(headroom)
	return pb
}

// NewPacketBufferWithData creates a PacketBuffer wrapping existing data.
// Used for the receive path where data is already in a buffer.
// No headroom is reserved.
func NewPacketBufferWithData(data []byte) *PacketBuffer {
	pb := pool.Get().(*PacketBuffer)
	pb.reset(0)
	n := copy(pb.buf, data)
	pb.Data = pb.buf[:n]
	return pb
}

// Prepend consumes headroom and returns a slice to write a header into.
// The returned slice is positioned immediately before any previously
// prepended data.
func (pb *PacketBuffer) Prepend(size int) []byte {
	pb.consumed += size
	start := pb.headroom - pb.consumed
	return pb.buf[start : start+size]
}

// AsSlice returns the complete packet bytes from the first prepended
// header to the end of the data region.
func (pb *PacketBuffer) AsSlice() []byte {
	start := pb.headroom - pb.consumed
	end := pb.headroom
	if pb.Data != nil {
		// Data starts at headroom offset and extends to its length.
		end = pb.headroom + len(pb.Data)
	}
	return pb.buf[start:end]
}

// Buf returns the underlying buffer starting from the headroom offset.
// Useful for reading data directly into the buffer (e.g., from TUN).
func (pb *PacketBuffer) Buf() []byte {
	return pb.buf[pb.headroom:]
}

// AppendData copies payload data into the buffer area after headroom.
// Must be called before Prepend so headers and data are contiguous.
func (pb *PacketBuffer) AppendData(data []byte) {
	pb.Data = pb.buf[pb.headroom : pb.headroom+len(data)]
	copy(pb.Data, data)
}

// Release returns the PacketBuffer to the pool.
func (pb *PacketBuffer) Release() {
	pb.NetworkHeader = nil
	pb.TransportHeader = nil
	pb.Data = nil
	pb.headroom = 0
	pb.consumed = 0
	pool.Put(pb)
}

func (pb *PacketBuffer) reset(headroom int) {
	pb.headroom = headroom
	pb.consumed = 0
	pb.NetworkHeader = nil
	pb.TransportHeader = nil
	pb.Data = nil
}
