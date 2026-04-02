package channel

import (
	"errors"
	"time"
)

var errClosed = errors.New("channel closed")

// MemoryChannel is an in-process Channel backed by Go channels.
// Used for testing and in-process packet exchange.
type MemoryChannel struct {
	inbound  chan []byte
	outbound chan []byte
	mtu      int
	closed   chan struct{}
}

// NewMemory creates a new MemoryChannel with the given MTU.
func NewMemory(mtu int) *MemoryChannel {
	return &MemoryChannel{
		inbound:  make(chan []byte, 256),
		outbound: make(chan []byte, 256),
		mtu:      mtu,
		closed:   make(chan struct{}),
	}
}

// ReadPacket reads one IP packet from the inbound channel into buf.
func (c *MemoryChannel) ReadPacket(buf []byte) (int, error) {
	select {
	case pkt := <-c.inbound:
		n := copy(buf, pkt)
		return n, nil
	case <-c.closed:
		return 0, errClosed
	}
}

// WritePacket writes one complete IP packet to the outbound channel.
func (c *MemoryChannel) WritePacket(data []byte) error {
	select {
	case <-c.closed:
		return errClosed
	default:
	}
	pkt := make([]byte, len(data))
	copy(pkt, data)
	select {
	case c.outbound <- pkt:
		return nil
	case <-c.closed:
		return errClosed
	}
}

// Close shuts down the channel, unblocking any pending ReadPacket.
func (c *MemoryChannel) Close() error {
	select {
	case <-c.closed:
		return nil // already closed
	default:
		close(c.closed)
	}
	return nil
}

// MTU returns the maximum transmission unit.
func (c *MemoryChannel) MTU() int {
	return c.mtu
}

// Inject pushes a packet into the inbound channel (test helper).
func (c *MemoryChannel) Inject(data []byte) {
	pkt := make([]byte, len(data))
	copy(pkt, data)
	c.inbound <- pkt
}

// Read reads a packet from the outbound channel with a timeout (test helper).
// Returns nil if no packet is available within the timeout.
func (c *MemoryChannel) Read(timeout time.Duration) []byte {
	select {
	case pkt := <-c.outbound:
		return pkt
	case <-time.After(timeout):
		return nil
	}
}

// TryRead attempts a non-blocking read from the outbound channel (test helper).
// Returns nil immediately if no packet is available.
func (c *MemoryChannel) TryRead() []byte {
	select {
	case pkt := <-c.outbound:
		return pkt
	default:
		return nil
	}
}
