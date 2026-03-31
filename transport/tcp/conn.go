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

const (
	delayedACKTimeout          = 200 * time.Millisecond
	maxZeroWindowProbeInterval = 60 * time.Second
)

// TCP Keepalive defaults (RFC 1122 Section 4.2.3.6).
// Exported vars to allow test override.
var (
	KeepaliveIdle     = 7200 * time.Second // 2 hours
	KeepaliveInterval = 75 * time.Second
	KeepaliveCount    = 9
)

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

	// MSS negotiation.
	peerMSS uint16 // peer's MSS from SYN (0 if absent → default 536)

	// Delayed ACK (RFC 1122 Section 4.2.3.2).
	delayedACKTimer *time.Timer // fires after 200ms to send pending ACK
	unackedSegs     int         // data segments received since last ACK sent

	// Zero Window Probe (RFC 793 / RFC 1122).
	zeroWindowTimer   *time.Timer  // fires to send zero-window probe
	zeroWindowProbing bool         // currently in zero-window probe mode
	probeInterval     time.Duration // current probe interval (doubles on each probe)

	// TCP Keepalive (RFC 1122 Section 4.2.3.6).
	keepaliveTimer  *time.Timer // fires after idle timeout or probe interval
	keepaliveProbes int         // number of unanswered probes sent

	// Half-close (shutdown).
	writeShutdown bool // CloseWrite called — no more writes, FIN sent
	readShutdown  bool // CloseRead called — discard incoming data

	// Sender / Receiver (initialized on transition to ESTABLISHED).
	snd *sender
	rcv *receiver

	// User-facing buffers.
	readBuf  *ringBuffer
	writeBuf *ringBuffer

	// Notify conn.run() that writeBuf has data.
	writeNotify chan struct{}

	inbound chan *packet.PacketBuffer

	done          chan struct{}
	closeOnce     sync.Once // guards graceful Close (FIN)
	closeReadOnce sync.Once // guards CloseRead
	doneOnce      sync.Once // guards close(done)

	// Graceful close: app signals run loop via closeCh.
	closeCh chan struct{}

	// TIME_WAIT timer, managed within run loop.
	timeWaitTimer *time.Timer
}

// LocalAddr returns the local (server-side) address of the connection.
func (c *TCPConn) LocalAddr() tcpip.FullAddress {
	return tcpip.FullAddress{Addr: c.flow.DstAddr, Port: c.flow.DstPort}
}

// RemoteAddr returns the remote (client-side) address of the connection.
func (c *TCPConn) RemoteAddr() tcpip.FullAddress {
	return tcpip.FullAddress{Addr: c.flow.SrcAddr, Port: c.flow.SrcPort}
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
	if c.writeShutdown {
		return 0, errBufferClosed
	}
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

// CloseWrite sends FIN while keeping the read side open.
// After CloseWrite, Write() returns an error but Read() still works.
func (c *TCPConn) CloseWrite() {
	c.closeOnce.Do(func() {
		c.writeShutdown = true
		c.writeBuf.CloseWrite()
		select {
		case c.closeCh <- struct{}{}:
		default:
		}
	})
}

// CloseRead closes the read side. Read() returns EOF, incoming data is discarded.
// Does not send FIN — the write side remains open.
func (c *TCPConn) CloseRead() {
	c.closeReadOnce.Do(func() {
		c.readShutdown = true
		c.readBuf.CloseWrite()
	})
}

// Close initiates a graceful FIN-based close. Sends FIN (like CloseWrite)
// but does NOT immediately close the read side — data arriving before the
// peer's FIN is still buffered and readable. The read buffer is closed
// when the connection enters TIME_WAIT or CLOSED.
func (c *TCPConn) Close() {
	c.CloseWrite()
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

// cancelDelayedACK stops the delayed ACK timer if running.
func (c *TCPConn) cancelDelayedACK() {
	if c.delayedACKTimer != nil {
		if !c.delayedACKTimer.Stop() {
			select {
			case <-c.delayedACKTimer.C:
			default:
			}
		}
	}
}

// checkZeroWindow starts zero-window probing if the sender is blocked on a zero window.
func (c *TCPConn) checkZeroWindow() {
	if c.snd == nil || c.zeroWindowProbing {
		return
	}
	if c.snd.wnd == 0 && c.writeBuf.Len() > 0 {
		c.zeroWindowProbing = true
		c.probeInterval = c.snd.rto
		c.zeroWindowTimer.Reset(c.probeInterval)
	}
}

// cancelZeroWindowProbe stops zero-window probing (window opened).
func (c *TCPConn) cancelZeroWindowProbe() {
	if !c.zeroWindowProbing {
		return
	}
	c.zeroWindowProbing = false
	if !c.zeroWindowTimer.Stop() {
		select {
		case <-c.zeroWindowTimer.C:
		default:
		}
	}
}

// sendZeroWindowProbe sends a 1-byte data probe to elicit a window update.
func (c *TCPConn) sendZeroWindowProbe() {
	if c.snd == nil || c.writeBuf == nil {
		return
	}
	// Peek 1 byte from writeBuf without consuming it.
	probe := make([]byte, 1)
	n := c.writeBuf.ReadNoBlock(probe)
	if n == 0 {
		// No data to probe with — stop probing.
		c.cancelZeroWindowProbe()
		return
	}
	probe = probe[:n]
	c.sendData(probe, c.snd.nxt)
	c.snd.recordSent(c.snd.nxt, probe)
	c.snd.nxt += uint32(n)
}

// sendKeepaliveProbe sends a keepalive probe: seq = snd.una - 1, no data, ACK.
func (c *TCPConn) sendKeepaliveProbe() {
	if c.snd == nil || c.rcv == nil {
		return
	}
	pb := packet.NewPacketBuffer(packet.MaxHeadroom)
	tcpBuf := pb.Prepend(header.TCPMinHeaderSize)
	hdr := header.TCP(tcpBuf)
	hdr.Encode(&header.TCPFields{
		SrcPort:    c.flow.DstPort,
		DstPort:    c.flow.SrcPort,
		SeqNum:     c.snd.una - 1, // deliberate bad sequence to elicit ACK
		AckNum:     c.rcv.nxt,
		DataOffset: header.TCPMinHeaderSize / 4,
		Flags:      header.TCPFlagACK,
		WindowSize: c.rcv.wnd(),
	})
	setTCPChecksum(hdr, c.flow.DstAddr, c.flow.SrcAddr, header.TCPMinHeaderSize)
	c.handler.stack.SendPacket(pb, c.flow.DstAddr, c.flow.SrcAddr, tcpip.TCPProtocolNumber)
}

// resetKeepalive resets the keepalive timer to the idle timeout and clears probes.
func (c *TCPConn) resetKeepalive() {
	if c.keepaliveTimer != nil {
		c.keepaliveProbes = 0
		c.keepaliveTimer.Reset(KeepaliveIdle)
	}
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

	c.delayedACKTimer = time.NewTimer(0)
	if !c.delayedACKTimer.Stop() {
		<-c.delayedACKTimer.C
	}
	defer c.delayedACKTimer.Stop()

	c.zeroWindowTimer = time.NewTimer(0)
	if !c.zeroWindowTimer.Stop() {
		<-c.zeroWindowTimer.C
	}
	defer c.zeroWindowTimer.Stop()

	c.keepaliveTimer = time.NewTimer(0)
	if !c.keepaliveTimer.Stop() {
		<-c.keepaliveTimer.C
	}
	defer c.keepaliveTimer.Stop()

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

		case <-c.delayedACKTimer.C:
			// Delayed ACK timer fired — send ACK and reset counter.
			c.sendACK()
			c.unackedSegs = 0

		case <-c.zeroWindowTimer.C:
			// Zero window probe timer fired — send probe and double interval.
			if c.snd != nil && c.zeroWindowProbing {
				c.sendZeroWindowProbe()
				c.probeInterval *= 2
				if c.probeInterval > maxZeroWindowProbeInterval {
					c.probeInterval = maxZeroWindowProbeInterval
				}
				c.zeroWindowTimer.Reset(c.probeInterval)
			}

		case <-c.keepaliveTimer.C:
			if c.state == stateEstablished && c.snd != nil {
				// Don't send keepalive probes while data is pending —
				// RTO retransmission already provides liveness detection.
				if c.snd.hasUnacked() {
					c.keepaliveTimer.Reset(KeepaliveIdle)
					continue
				}
				c.keepaliveProbes++
				if c.keepaliveProbes > KeepaliveCount {
					// Dead peer detected — abort with RST.
					c.sendRSTSegment(c.snd.nxt)
					c.closeDone()
					c.handler.removeConn(c.flow)
					return
				}
				// Send keepalive probe: seq = snd.una - 1, no data, ACK flag.
				c.sendKeepaliveProbe()
				c.keepaliveTimer.Reset(KeepaliveInterval)
			}

		case <-c.writeNotify:
			if c.snd != nil {
				c.snd.sendPending(c)
				c.resetKeepalive() // sending data resets keepalive
				// Check if sender is blocked on zero window.
				c.checkZeroWindow()
				// Piggybacking: outgoing data carries ACK, cancel delayed ACK.
				if c.unackedSegs > 0 {
					if !c.delayedACKTimer.Stop() {
						select {
						case <-c.delayedACKTimer.C:
						default:
						}
					}
					c.unackedSegs = 0
				}
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
	if !c.readShutdown {
		c.readBuf.CloseWrite()
	}
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
