package tcp

import "github.com/Zwlin98/netstack/header"

// handleEstablished processes a segment in the ESTABLISHED state.
// RST and unexpected SYN are handled by the common pipeline in handleSegment.
func (c *TCPConn) handleEstablished(seg segment) {
	// Any segment received resets keepalive.
	c.resetKeepalive()

	// ACK processing: update peer window, congestion control.
	if seg.flags.Has(header.TCPFlagACK) && c.snd != nil {
		oldWnd := c.snd.wnd
		c.snd.wnd = uint32(seg.wnd) << c.sndWndScale

		// RTTM: measure RTT from timestamp echo (RFC 7323 §4).
		c.measureRTTM(seg)

		// Process SACK blocks if negotiated.
		if c.sackPermitted && len(seg.options) > 0 {
			so := header.ParseSegmentOptions(seg.options)
			if len(so.SACKBlocks) > 0 {
				c.snd.processSACKBlocks(so.SACKBlocks)
				c.snd.sackLossDetection(c)
			}
		}

		c.snd.handleACK(seg.ack, c)
		// A pure window update (same ACK, larger window) should trigger sending.
		if seg.ack == c.snd.una && uint32(seg.wnd)<<c.sndWndScale > oldWnd {
			c.snd.sendPending(c)
		}

		// Zero window probe management.
		if c.snd.wnd > 0 && c.zeroWindowProbing {
			c.cancelZeroWindowProbe()
			c.snd.sendPending(c)
		} else if c.snd.wnd == 0 && c.writeBuf.Len() > 0 && !c.zeroWindowProbing {
			c.checkZeroWindow()
		}
	}

	// Data delivery.
	if len(seg.payload) > 0 && c.rcv != nil {
		c.rcv.handleData(seg.seq, seg.payload)
	}

	// FIN handling: peer is closing their send side.
	// Only process FIN when all preceding data has been delivered (no gaps).
	if seg.flags.Has(header.TCPFlagFIN) && c.rcv != nil {
		finSeq := seg.seq + uint32(len(seg.payload))
		if c.rcv.nxt == finSeq {
			// All data before FIN received — process immediately.
			c.processFIN()
			return
		}
		// Gap exists — defer FIN until OOO segments fill the gap.
		c.rcv.finReceived = true
		c.rcv.finSeq = finSeq
	}

	// Delayed ACK for data segments.
	if len(seg.payload) > 0 {
		c.unackedSegs++

		// Immediate ACK on out-of-order segment (for fast retransmit).
		if c.rcv != nil && seqGreaterThan(seg.seq, c.rcv.nxt) {
			c.cancelDelayedACK()
			c.sendACK()
			c.unackedSegs = 0
			return
		}

		// Every-other-segment rule: immediate ACK after 2 segments.
		if c.unackedSegs >= 2 {
			c.cancelDelayedACK()
			c.sendACK()
			c.unackedSegs = 0
			return
		}

		// Arm delayed ACK timer (200ms).
		c.delayedACKTimer.Reset(c.delayedACKTimeout)
	}
}
