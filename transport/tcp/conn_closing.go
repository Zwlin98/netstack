package tcp

import (
	"time"

	"github.com/Zwlin98/netstack/header"
)

// measureRTTM measures RTT from timestamp echo if timestamps are enabled.
func (c *TCPConn) measureRTTM(seg segment) {
	if c.tsEnabled && seg.hasTS && seg.tsEcr != 0 && c.snd != nil {
		rtt := time.Duration(c.handler.now()-seg.tsEcr) * time.Millisecond
		if rtt > 0 {
			c.snd.updateRTT(rtt)
		}
	}
}

// handleFinWait1 processes segments in FIN_WAIT_1 state.
// We have sent FIN and are waiting for ACK (→FIN_WAIT_2) or peer FIN (→TIME_WAIT).
func (c *TCPConn) handleFinWait1(seg segment) {
	ackOfFIN := false
	if seg.flags.Has(header.TCPFlagACK) && c.snd != nil {
		c.snd.wnd = uint32(seg.wnd) << c.sndWndScale
		c.measureRTTM(seg)
		c.snd.handleACK(seg.ack, c)
		// Check if our FIN has been ACKed (ACK covers snd.nxt which is past the FIN).
		if !c.snd.hasUnacked() {
			ackOfFIN = true
		}
	}

	// Accept data that arrives before peer's FIN.
	if len(seg.payload) > 0 && c.rcv != nil {
		c.rcv.handleData(seg.seq, seg.payload)
	}

	if seg.flags.Has(header.TCPFlagFIN) && c.rcv != nil {
		c.rcv.nxt++
		c.sendACK() // single ACK covers data + FIN
		if !c.readShutdown {
			c.readBuf.CloseWrite()
		}
		if ackOfFIN {
			// Both FINs exchanged and ours is ACKed → TIME_WAIT.
			c.enterTimeWait()
		} else {
			// Simultaneous close: got peer's FIN but our FIN not yet ACKed → CLOSING.
			c.state = stateClosing
		}
		return
	}

	// ACK for data only (no FIN in this segment).
	if len(seg.payload) > 0 {
		c.sendACK()
	}

	if ackOfFIN {
		c.state = stateFinWait2
		c.finWait2Timer.Reset(FinWait2Timeout)
	}
}

// handleFinWait2 processes segments in FIN_WAIT_2 state.
// Our FIN has been ACKed; we still accept data and wait for peer's FIN.
func (c *TCPConn) handleFinWait2(seg segment) {
	if seg.flags.Has(header.TCPFlagACK) && c.snd != nil {
		c.snd.wnd = uint32(seg.wnd) << c.sndWndScale
	}

	// Continue accepting data.
	if len(seg.payload) > 0 && c.rcv != nil {
		c.rcv.handleData(seg.seq, seg.payload)
		// Reset FIN_WAIT_2 timer — peer is still active.
		c.finWait2Timer.Reset(FinWait2Timeout)
	}

	if seg.flags.Has(header.TCPFlagFIN) && c.rcv != nil {
		c.rcv.nxt++
		c.sendACK() // single ACK covers data + FIN
		c.enterTimeWait()
		return
	}

	// ACK for data only.
	if len(seg.payload) > 0 {
		c.sendACK()
	}
}

// handleClosing processes segments in CLOSING state.
// Both sides have sent FIN; we are waiting for ACK of our FIN.
func (c *TCPConn) handleClosing(seg segment) {
	if seg.flags.Has(header.TCPFlagACK) && c.snd != nil {
		c.measureRTTM(seg)
		c.snd.handleACK(seg.ack, c)
		// Check if our FIN has been ACKed.
		if !c.snd.hasUnacked() {
			c.enterTimeWait()
			return
		}
	}
	// Re-ACK retransmitted FINs.
	if seg.flags.Has(header.TCPFlagFIN) {
		c.sendACK()
	}
}

// handleLastAck processes segments in LAST_ACK state.
// We sent FIN in response to peer's FIN; waiting for final ACK.
func (c *TCPConn) handleLastAck(seg segment) {
	if seg.flags.Has(header.TCPFlagACK) && c.snd != nil {
		// Check if our FIN is ACKed.
		if !c.snd.hasUnacked() || seqGreaterThan(seg.ack, c.snd.una) {
			c.snd.handleACK(seg.ack, c)
			c.closeDone()
		}
	}
}

// handleTimeWait processes segments in TIME_WAIT state.
// Re-ACK retransmitted FINs and reset the 2*MSL timer.
func (c *TCPConn) handleTimeWait(seg segment) {
	if seg.flags.Has(header.TCPFlagFIN) {
		c.sendACK()
		c.timeWaitTimer.Reset(timeWaitDuration)
	}
}
