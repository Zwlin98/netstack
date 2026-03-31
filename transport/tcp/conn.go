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

var timeWaitDuration = 2 * time.Minute // 2*MSL (MSL = 1 minute)

// TCPConn represents a single TCP connection.
type TCPConn struct {
	flow    FlowID
	handler *TCPHandler

	state tcpState

	iss uint32 // our initial sequence number
	irs uint32 // peer's initial sequence number

	// Window scaling (RFC 7323).
	sndWndScale uint8 // peer's window scale shift count
	rcvWndScale uint8 // our window scale shift count

	// SACK (RFC 2018).
	sackPermitted bool // both sides support SACK

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
	closeOnce sync.Once // guards graceful Close (FIN)
	doneOnce  sync.Once // guards close(done)

	// Graceful close: app signals run loop via closeCh.
	closeCh chan struct{}

	// TIME_WAIT timer, managed within run loop.
	timeWaitTimer *time.Timer
}

// OriginalDst returns the original destination address of the connection.
func (c *TCPConn) OriginalDst() tcpip.FullAddress {
	return tcpip.FullAddress{Addr: c.flow.DstAddr, Port: c.flow.DstPort}
}

func (c *TCPConn) closeDone() {
	c.doneOnce.Do(func() {
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
// Returns an error if the connection is closing or closed.
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

// Close initiates a graceful FIN-based close. Non-blocking: returns
// immediately after signaling the run loop. Write() will return an error
// after Close(); Read() continues to drain buffered data until EOF.
func (c *TCPConn) Close() {
	c.closeOnce.Do(func() {
		c.writeBuf.CloseWrite()
		select {
		case c.closeCh <- struct{}{}:
		default:
		}
	})
}

// ForceClose sends RST and tears down the connection immediately.
func (c *TCPConn) ForceClose() error {
	if c.state == stateEstablished && c.snd != nil {
		c.sendRSTSegment(c.snd.nxt)
	}
	c.closeDone()
	c.handler.removeConn(c.flow)
	return nil
}

// sendFIN sends a FIN+ACK and records it for retransmission.
func (c *TCPConn) sendFIN() {
	c.sendFINSegment(c.snd.nxt)
	c.snd.recordSentFIN(c.snd.nxt)
	c.snd.nxt++ // FIN occupies one sequence number
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

	c.timeWaitTimer = time.NewTimer(0)
	if !c.timeWaitTimer.Stop() {
		<-c.timeWaitTimer.C
	}
	defer c.timeWaitTimer.Stop()

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

		case <-c.closeCh:
			c.handleClose()
			if c.snd != nil && c.snd.hasUnacked() {
				rtoTimer.Reset(c.snd.rto)
			}

		case <-c.timeWaitTimer.C:
			// TIME_WAIT expired → CLOSED.
			return

		case <-c.done:
			return
		}
	}
}

// handleClose processes a graceful close request from the application.
func (c *TCPConn) handleClose() {
	switch c.state {
	case stateEstablished:
		c.sendFIN()
		c.state = stateFinWait1
	case stateCloseWait:
		c.sendFIN()
		c.state = stateLastAck
	}
}

// enterTimeWait transitions to TIME_WAIT state and starts the 2*MSL timer.
func (c *TCPConn) enterTimeWait() {
	c.state = stateTimeWait
	c.readBuf.CloseWrite()
	c.timeWaitTimer.Reset(timeWaitDuration)
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

	// Common: RST handling applies to all states except TIME_WAIT.
	// RFC 1337: Ignore RST in TIME_WAIT to prevent TIME-WAIT assassination.
	if seg.flags.Has(header.TCPFlagRST) {
		if c.state == stateTimeWait {
			return
		}
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
	case stateFinWait1:
		c.handleFinWait1(seg)
	case stateFinWait2:
		c.handleFinWait2(seg)
	case stateCloseWait:
		// In CLOSE_WAIT, we still process ACKs for our data.
		if seg.flags.Has(header.TCPFlagACK) && c.snd != nil {
			c.snd.wnd = uint32(seg.wnd) << c.sndWndScale
			c.snd.handleACK(seg.ack, c)
		}
	case stateLastAck:
		c.handleLastAck(seg)
	case stateTimeWait:
		c.handleTimeWait(seg)
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

// calculateWindowScale returns the window scale shift count for a given buffer size.
// The scale factor is the number of bits needed to represent the buffer beyond 16 bits.
func calculateWindowScale(bufSize int) uint8 {
	if bufSize <= 0xFFFF {
		return 0
	}
	scale := uint8(0)
	for (bufSize >> (16 + scale)) > 0 {
		scale++
	}
	if scale > header.MaxWndScale {
		scale = header.MaxWndScale
	}
	return scale
}

func generateISN() uint32 {
	var buf [4]byte
	rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}
