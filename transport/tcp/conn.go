package tcp

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/tcpip"
)

// TCPConn represents a single TCP connection.
type TCPConn struct {
	flow    FlowID
	handler *TCPHandler

	state tcpState

	iss uint32 // our initial sequence number
	irs uint32 // peer's initial sequence number

	// Sender / Receiver (initialized on transition to ESTABLISHED).
	snd *sender
	rcv *receiver

	// User-facing buffers.
	readBuf  *ringBuffer
	writeBuf *ringBuffer

	// Notify conn.run() that writeBuf has data.
	writeNotify chan struct{}

	inbound chan *packet.PacketBuffer

	done      chan struct{}
	closeOnce sync.Once
}

// OriginalDst returns the original destination address of the connection.
func (c *TCPConn) OriginalDst() tcpip.FullAddress {
	return tcpip.FullAddress{Addr: c.flow.DstAddr, Port: c.flow.DstPort}
}

func (c *TCPConn) closeDone() {
	c.closeOnce.Do(func() {
		c.state = stateClosed
		close(c.done)
	})
}

// Read reads data from the connection. Blocks until data is available.
// Returns io.EOF when the remote side has closed and all data has been read.
func (c *TCPConn) Read(b []byte) (int, error) {
	if c.readBuf == nil {
		return 0, io.EOF
	}
	return c.readBuf.Read(b, c.done)
}

// Write writes data to the connection. Blocks until all data is written.
func (c *TCPConn) Write(b []byte) (int, error) {
	if c.writeBuf == nil {
		return 0, errBufferClosed
	}
	n, err := c.writeBuf.Write(b, c.done)
	if n > 0 {
		// Wake up conn.run() to send data.
		select {
		case c.writeNotify <- struct{}{}:
		default:
		}
	}
	return n, err
}

// Close shuts down the connection, sending RST to the remote peer.
func (c *TCPConn) Close() {
	if c.state == stateEstablished && c.snd != nil {
		c.sendRSTSegment(c.snd.nxt)
	}
	c.closeDone()
	c.handler.removeConn(c.flow)
}

// ForceClose sends RST and tears down the connection immediately.
func (c *TCPConn) ForceClose() error {
	c.Close()
	return nil
}

func (c *TCPConn) handleRST() {
	c.state = stateClosed
	c.closeDone()
}

func (c *TCPConn) run() {
	defer c.cleanup()

	rtoTimer := time.NewTimer(0)
	if !rtoTimer.Stop() {
		<-rtoTimer.C
	}
	defer rtoTimer.Stop()

	for {
		select {
		case pb := <-c.inbound:
			c.handleSegment(pb)
			pb.Release()
			// After processing a segment, manage the RTO timer.
			if c.snd != nil {
				if c.snd.hasUnacked() {
					rtoTimer.Reset(c.snd.rto)
				} else {
					if !rtoTimer.Stop() {
						select {
						case <-rtoTimer.C:
						default:
						}
					}
				}
			}

		case <-rtoTimer.C:
			if c.snd != nil {
				c.snd.handleRTO(c)
				if c.state != stateClosed && c.snd.hasUnacked() {
					rtoTimer.Reset(c.snd.rto)
				}
			}

		case <-c.writeNotify:
			if c.snd != nil {
				c.snd.sendPending(c)
				if c.snd.hasUnacked() {
					rtoTimer.Reset(c.snd.rto)
				}
			}

		case <-c.done:
			return
		}
	}
}

// abort sends RST and closes the connection (used when max retries exceeded).
func (c *TCPConn) abort() {
	if c.snd != nil {
		c.sendRSTSegment(c.snd.nxt)
	}
	c.closeDone()
}

func (c *TCPConn) handleSegment(pb *packet.PacketBuffer) {
	seg := parseSeg(pb)

	// Common: RST handling applies to all states.
	if seg.flags.Has(header.TCPFlagRST) {
		c.handleRST()
		return
	}

	// Common: unexpected SYN in non-SYN_RCVD state → challenge ACK.
	if seg.flags.Has(header.TCPFlagSYN) && c.state != stateSynRcvd {
		c.sendACK()
		return
	}

	switch c.state {
	case stateSynRcvd:
		c.handleSynRcvd(seg)
	case stateEstablished:
		c.handleEstablished(seg)
	}
}

func (c *TCPConn) cleanup() {
	c.handler.removeConn(c.flow)
	for {
		select {
		case pb := <-c.inbound:
			pb.Release()
		default:
			return
		}
	}
}

func generateISN() uint32 {
	var buf [4]byte
	rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}
