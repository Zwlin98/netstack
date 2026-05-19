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

	// Window scaling (RFC 7323).
	sndWndScale uint8 // peer's window scale shift count
	rcvWndScale uint8 // our window scale shift count

	// SACK (RFC 2018).
	sackPermitted bool // both sides support SACK

	// MSS negotiation.
	peerMSS uint16 // peer's MSS from SYN (0 if absent → default 536)

	// TCP Timestamps (RFC 7323).
	tsEnabled     bool   // timestamps negotiated
	tsRecent      uint32 // TS.Recent: last valid TSval from peer (for TSecr echo)
	tsLastAckSent uint32 // Last.ACK.sent: RCV.NXT when tsRecent was last updated
	tsOffset      uint32 // random offset added to our TSval

	// Nagle algorithm (RFC 1122 §4.2.3.4).
	noDelay bool // when true, Nagle is disabled (TCP_NODELAY)

	// Delayed ACK (RFC 1122 Section 4.2.3.2).
	delayedACKTimer *time.Timer // fires after 200ms to send pending ACK
	unackedSegs     int         // data segments received since last ACK sent

	// Zero Window Probe (RFC 793 / RFC 1122).
	zeroWindowTimer   *time.Timer   // fires to send zero-window probe
	zeroWindowProbing bool          // currently in zero-window probe mode
	probeInterval     time.Duration // current probe interval (doubles on each probe)

	// TCP Keepalive (RFC 1122 Section 4.2.3.6).
	keepaliveTimer  *time.Timer // fires after idle timeout or probe interval
	keepaliveProbes int         // number of unanswered probes sent

	// Half-close (shutdown).
	writeShutdown bool // CloseWrite called — no more writes, FIN sent
	readShutdown  bool // CloseRead called — discard incoming data
	finPending    bool // FIN queued but writeBuf not yet drained

	// Sender / Receiver (initialized on transition to ESTABLISHED).
	snd *sender
	rcv *receiver

	// User-facing buffers.
	readBuf  *ringBuffer
	writeBuf *ringBuffer

	// Notify conn.run() that writeBuf has data.
	writeNotify chan struct{}

	// Notify conn.run() that readBuf was drained and a window update should be sent.
	windowNotify chan struct{}
	lastWndZero  bool // last advertised window was 0

	inbound chan *packet.PacketBuffer

	done           chan struct{}
	closeOnce      sync.Once // guards graceful Close (FIN)
	closeReadOnce  sync.Once // guards CloseRead
	doneOnce       sync.Once // guards close(done)
	forceCloseOnce sync.Once // guards forceCloseCh

	// Graceful close: app signals run loop via closeCh.
	closeCh chan struct{}
	// Force close: external callers ask run loop to abort without racing state.
	forceCloseCh chan struct{}

	// TIME_WAIT timer, managed within run loop.
	timeWaitTimer *time.Timer

	// FIN_WAIT_2 timer (RFC 1122): close if peer doesn't send FIN.
	finWait2Timer *time.Timer

	// SYN_RCVD timer: close half-open connections that never complete handshake.
	synRcvdTimer *time.Timer

	// Stats (nil when disabled).
	stats       *Stats
	statsActive bool // true if this conn was counted in ActiveConns

	// Per-connection snapshot (mutex-protected for race-free reads).
	snapshotMu   sync.Mutex
	snapshotData ConnSnapshot

	// Config snapshots (set at creation, immutable for connection lifetime).
	keepaliveIdle     time.Duration
	keepaliveInterval time.Duration
	keepaliveCount    int
	finWait2Timeout   time.Duration
	synRcvdTimeout    time.Duration
	timeWaitDuration  time.Duration
	delayedACKTimeout time.Duration
	maxZWPInterval    time.Duration
	rcvWndSize        uint16
	minRTO            time.Duration
	maxRTO            time.Duration
	initialRTO        time.Duration
	maxRetries        int
	initialSSThresh   uint32
	maxReadBufSize    int
	readBufSize       int // target ReadBufferSize for lazy growth
	writeBufSize      int // target WriteBufferSize for lazy growth
}

// updateSnapshot updates the mutex-protected snapshot data.
// Called from conn.run() at key state-change points.
func (c *TCPConn) updateSnapshot() {
	snap := ConnSnapshot{
		Flow:         c.flow,
		State:        c.state.String(),
		ReadBufUsed:  c.readBuf.Len(),
		WriteBufUsed: c.writeBuf.Len(),
		BufCap:       c.readBuf.Cap(),
		ReadBufCap:   c.readBuf.Cap(),
		WriteBufCap:  c.writeBuf.Cap(),
	}
	if c.snd != nil {
		snap.SRTT = c.snd.srtt
		snap.RTO = c.snd.rto
		snap.Cwnd = c.snd.cwnd
		snap.SSThresh = c.snd.ssthresh
		snap.SndWnd = c.snd.wnd
		snap.SndNxt = c.snd.nxt
		snap.SndMSS = c.snd.mss
		snap.SndMaxWnd = c.snd.maxWnd
		snap.Unacked = len(c.snd.unacked)
		snap.Retries = c.snd.retries
		snap.InRecovery = c.snd.inRecovery
		snap.DSACKSeen = c.snd.dsackSeen
	}
	if c.rcv != nil {
		snap.RcvWnd = c.rcv.wnd()
		snap.OOO = len(c.rcv.ooo)
	}
	c.snapshotMu.Lock()
	c.snapshotData = snap
	c.snapshotMu.Unlock()
}

// SetNoDelay enables or disables the Nagle algorithm.
// When true, small writes are sent immediately regardless of in-flight data.
func (c *TCPConn) SetNoDelay(noDelay bool) {
	c.noDelay = noDelay
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
	n, err := c.readBuf.Read(b, c.done)
	if n > 0 {
		// If reading freed enough buffer space to open the receive window,
		// notify conn.run() to send a window update ACK.
		select {
		case c.windowNotify <- struct{}{}:
		default:
		}
	}
	return n, err
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
	// Lazy allocation: grow writeBuf to target size on first write.
	if c.writeBufSize > 0 && c.writeBuf.Cap() < c.writeBufSize {
		c.writeBuf.Grow(c.writeBufSize)
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
	c.forceCloseOnce.Do(func() {
		close(c.forceCloseCh)
	})
	return nil
}

func (c *TCPConn) forceCloseFromRun() {
	if c.state == stateEstablished && c.snd != nil {
		c.sendRSTSegment(c.snd.nxt)
	}
	c.closeDone()
}

// sendFIN sends a FIN+ACK and records it for retransmission.
func (c *TCPConn) sendFIN() {
	c.sendFINSegment(c.snd.nxt)
	c.snd.recordSentFIN(c.snd.nxt)
	c.snd.nxt++ // FIN occupies one sequence number
}

// updateTSLastAckSent records RCV.NXT at the time we send an ACK,
// for the TS.Recent update rule (RFC 7323 §4.3).
func (c *TCPConn) updateTSLastAckSent() {
	if c.tsEnabled && c.rcv != nil {
		c.tsLastAckSent = c.rcv.nxt
	}
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
	if st := c.stats; st != nil {
		st.ZeroWindowProbes.Add(1)
	}
	if c.snd == nil || c.writeBuf == nil {
		return
	}
	// Peek 1 byte from writeBuf without consuming it.
	ref := packet.GetRefBuf()
	n := c.writeBuf.ReadNoBlock(ref.Buf()[:1])
	if n == 0 {
		ref.DecRef()
		// No data to probe with — stop probing.
		c.cancelZeroWindowProbe()
		return
	}
	ref.SetLen(n)
	c.sendData(ref.Bytes(), c.snd.nxt)
	c.snd.recordSent(c.snd.nxt, ref)
	c.snd.nxt += uint32(n)
}

// sendKeepaliveProbe sends a keepalive probe: seq = snd.una - 1, no data, ACK.
func (c *TCPConn) sendKeepaliveProbe() {
	if c.snd == nil || c.rcv == nil {
		return
	}

	var optBuf [12]byte
	optLen := 0
	if c.tsEnabled {
		optLen += header.EncodeTimestampOption(optBuf[optLen:], c.handler.now(), c.tsRecent)
	}

	hdrSize := header.TCPMinHeaderSize + optLen
	pb := packet.NewPacketBuffer(packet.MaxHeadroom)
	tcpBuf := pb.Prepend(hdrSize)
	hdr := header.TCP(tcpBuf)
	hdr.Encode(&header.TCPFields{
		SrcPort:    c.flow.DstPort,
		DstPort:    c.flow.SrcPort,
		SeqNum:     c.snd.una - 1, // deliberate bad sequence to elicit ACK
		AckNum:     c.rcv.nxt,
		DataOffset: uint8(hdrSize / 4),
		Flags:      header.TCPFlagACK,
		WindowSize: c.rcv.wnd(),
	})
	if optLen > 0 {
		copy(tcpBuf[header.TCPMinHeaderSize:], optBuf[:optLen])
	}
	setTCPChecksum(hdr, c.flow.DstAddr, c.flow.SrcAddr, uint16(hdrSize))
	c.handler.stack.SendPacket(pb, c.flow.DstAddr, c.flow.SrcAddr, tcpip.TCPProtocolNumber)
	c.updateTSLastAckSent()
}

// resetKeepalive resets the keepalive timer to the idle timeout and clears probes.
func (c *TCPConn) resetKeepalive() {
	if c.keepaliveTimer != nil {
		c.keepaliveProbes = 0
		c.keepaliveTimer.Reset(c.keepaliveIdle)
	}
}

func (c *TCPConn) handleRST() {
	if st := c.stats; st != nil {
		st.ResetsReceived.Add(1)
	}
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

	c.finWait2Timer = time.NewTimer(0)
	if !c.finWait2Timer.Stop() {
		<-c.finWait2Timer.C
	}
	defer c.finWait2Timer.Stop()

	c.keepaliveTimer = time.NewTimer(0)
	if !c.keepaliveTimer.Stop() {
		<-c.keepaliveTimer.C
	}
	defer c.keepaliveTimer.Stop()

	// SYN_RCVD timer: start if connection is in SYN_RCVD state.
	c.synRcvdTimer = time.NewTimer(0)
	if !c.synRcvdTimer.Stop() {
		<-c.synRcvdTimer.C
	}
	defer c.synRcvdTimer.Stop()
	if c.state == stateSynRcvd {
		c.synRcvdTimer.Reset(c.synRcvdTimeout)
	}
	c.updateSnapshot()

	for {
		select {
		case pb := <-c.inbound:
			c.handleSegment(pb)
			pb.Release()
			c.updateSnapshot()
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
			// Deferred FIN: ACK may have opened send window, try to drain.
			if c.finPending && c.snd != nil {
				c.snd.sendPending(c)
				if c.writeBuf.Len() == 0 {
					c.finalizeFIN()
				}
			}

		case <-rtoTimer.C:
			if c.snd != nil {
				c.snd.handleRTO(c)
				c.updateSnapshot()
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
				if c.probeInterval > c.maxZWPInterval {
					c.probeInterval = c.maxZWPInterval
				}
				c.zeroWindowTimer.Reset(c.probeInterval)
			}

		case <-c.keepaliveTimer.C:
			if c.state == stateEstablished && c.snd != nil {
				// Don't send keepalive probes while data is pending —
				// RTO retransmission already provides liveness detection.
				if c.snd.hasUnacked() {
					c.keepaliveTimer.Reset(c.keepaliveIdle)
					continue
				}
				c.keepaliveProbes++
				if c.keepaliveProbes > c.keepaliveCount {
					if st := c.stats; st != nil {
						st.TimeoutKeepalive.Add(1)
						st.TotalReset.Add(1)
					}
					// Dead peer detected — abort with RST.
					c.sendRSTSegment(c.snd.nxt)
					c.closeDone()
					c.updateSnapshot()
					return
				}
				// Send keepalive probe: seq = snd.una - 1, no data, ACK flag.
				c.sendKeepaliveProbe()
				c.keepaliveTimer.Reset(c.keepaliveInterval)
			}

		case <-c.writeNotify:
			if c.snd != nil {
				c.snd.sendPending(c)
				c.updateSnapshot()
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
				// Deferred FIN: send FIN once writeBuf is fully drained.
				if c.finPending && c.writeBuf.Len() == 0 {
					c.finalizeFIN()
				}
			}

		case <-c.windowNotify:
			// Application drained readBuf — send window update only if
			// the last advertised window was 0 and now it's open.
			if c.lastWndZero && c.rcv != nil && c.rcv.wnd() > 0 {
				c.lastWndZero = false
				c.sendACK()
				c.unackedSegs = 0
			}

		case <-c.closeCh:
			c.handleClose()
			c.updateSnapshot()
			if c.snd != nil && c.snd.hasUnacked() {
				rtoTimer.Reset(c.snd.rto)
			}

		case <-c.forceCloseCh:
			c.forceCloseFromRun()
			c.updateSnapshot()
			return

		case <-c.synRcvdTimer.C:
			// SYN_RCVD timeout — client never completed handshake.
			if c.state == stateSynRcvd {
				if st := c.stats; st != nil {
					st.TimeoutSynRcvd.Add(1)
				}
				c.closeDone()
				c.updateSnapshot()
				return
			}

		case <-c.finWait2Timer.C:
			// FIN_WAIT_2 timeout — peer never sent FIN. Close connection.
			if c.state == stateFinWait2 {
				if st := c.stats; st != nil {
					st.TimeoutFinWait2.Add(1)
				}
				c.closeDone()
				c.updateSnapshot()
				return
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
// processFIN handles a FIN whose preceding data has all been delivered.
func (c *TCPConn) processFIN() {
	c.rcv.nxt++ // FIN occupies one sequence number
	c.cancelDelayedACK()
	c.sendACK()
	if !c.readShutdown {
		c.readBuf.CloseWrite()
	}
	c.state = stateCloseWait
}

func (c *TCPConn) handleClose() {
	switch c.state {
	case stateEstablished, stateCloseWait:
		// Flush pending data before sending FIN.
		if c.snd != nil {
			c.snd.sendPending(c)
		}
		if c.snd != nil && c.writeBuf.Len() > 0 {
			// Data still queued (window limited) — defer FIN.
			c.finPending = true
			return
		}
		c.finalizeFIN()
	}
}

// finalizeFIN sends FIN and transitions to the appropriate state.
func (c *TCPConn) finalizeFIN() {
	c.finPending = false
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
	c.timeWaitTimer.Reset(c.timeWaitDuration)
}

// abort sends RST and closes the connection (used when max retries exceeded).
func (c *TCPConn) abort() {
	if st := c.stats; st != nil {
		st.TotalReset.Add(1)
	}
	if c.snd != nil {
		c.sendRSTSegment(c.snd.nxt)
	}
	c.closeDone()
}

func (c *TCPConn) handleSegment(pb *packet.PacketBuffer) {
	seg := parseSeg(pb)

	// Parse timestamp option when timestamps are negotiated.
	if c.tsEnabled && len(seg.options) > 0 {
		so := header.ParseSegmentOptions(seg.options)
		if so.TSEnabled {
			seg.hasTS = true
			seg.tsVal = so.TSVal
			seg.tsEcr = so.TSecr
		}
	}

	// PAWS check (RFC 7323 §5): drop segment with stale timestamp.
	if c.tsEnabled && seg.hasTS && !seg.flags.Has(header.TCPFlagRST) {
		if int32(seg.tsVal-c.tsRecent) < 0 {
			if st := c.stats; st != nil {
				st.PAWSDrops.Add(1)
			}
			// Stale timestamp — drop silently (no ACK).
			return
		}
	}

	// RST validation (RFC 5961 + RFC 1337).
	if seg.flags.Has(header.TCPFlagRST) {
		if c.state == stateTimeWait {
			// RFC 1337: Ignore RST in TIME_WAIT.
			return
		}
		// Determine rcv.nxt and window for validation.
		var rcvNxt, rcvWnd uint32
		if c.rcv != nil {
			rcvNxt = c.rcv.nxt
			rcvWnd = c.rcv.rcvWnd()
		} else {
			// SYN_RCVD: rcv not yet initialized.
			rcvNxt = c.irs + 1
			rcvWnd = uint32(c.rcvWndSize)
		}
		if seg.seq == rcvNxt {
			// Exact match — accept RST.
			c.handleRST()
		} else if seqWithinWindow(seg.seq, rcvNxt, rcvWnd) {
			// In window but not exact — send challenge ACK (RFC 5961 §3.2).
			c.sendACK()
		}
		// Outside window — silently discard.
		return
	}

	// Common: unexpected SYN in non-SYN_RCVD state → challenge ACK.
	if seg.flags.Has(header.TCPFlagSYN) && c.state != stateSynRcvd {
		c.sendACK()
		return
	}

	// TS.Recent update rule (RFC 7323 §4.3): update tsRecent only when
	// the segment's seq is not ahead of what we've already acknowledged.
	if c.tsEnabled && seg.hasTS && c.rcv != nil {
		if !seqGreaterThan(seg.seq, c.tsLastAckSent) {
			c.tsRecent = seg.tsVal
		}
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
			c.snd.updateMaxWnd(c.snd.wnd)
			c.measureRTTM(seg)
			c.snd.handleACK(seg.ack, c)
		}
	case stateClosing:
		c.handleClosing(seg)
	case stateLastAck:
		c.handleLastAck(seg)
	case stateTimeWait:
		c.handleTimeWait(seg)
	}
}

func (c *TCPConn) cleanup() {
	if st := c.stats; st != nil {
		st.TotalClosed.Add(1)
		if c.statsActive {
			st.ActiveConns.Add(-1)
		}
	}
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
