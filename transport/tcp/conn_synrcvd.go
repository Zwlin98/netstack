package tcp

import "github.com/Zwlin98/netstack/header"

func (c *TCPConn) handleSynRcvd(seg segment) {
	if seg.flags.Has(header.TCPFlagACK) {
		// Sequence number validation (RFC 793 Section 3.9 step 1).
		// In SYN_RCVD, rcv.nxt = IRS+1. For a zero-length segment with
		// non-zero window: acceptable if rcv.nxt <= seg.seq < rcv.nxt + rcv.wnd.
		rcvNxt := c.irs + 1
		if seg.seq-rcvNxt >= uint32(c.rcvWndSize) {
			c.sendACK()
			return
		}

		if seg.ack != c.iss+1 {
			// Invalid ACK — send RST with SeqNum = bad AckNum.
			c.sendRSTSegment(seg.ack)
			c.handleRST()
			return
		}
		c.state = stateEstablished

		// Cancel SYN_RCVD timeout — handshake completed.
		if c.synRcvdTimer != nil {
			c.synRcvdTimer.Stop()
		}

		c.snd = newSender(c.iss, seg.wnd, c.sndWndScale, c.handler.stack.MTU(), c.peerMSS, senderConfig{
			MinRTO:          c.minRTO,
			MaxRTO:          c.maxRTO,
			InitialRTO:      c.initialRTO,
			MaxRetries:      c.maxRetries,
			InitialSSThresh: c.initialSSThresh,
		})
		if c.tsEnabled {
			c.snd.mss -= 12 // timestamp option overhead
		}
		c.rcv = newReceiver(c.irs, c.readBuf, c)

		// Initialize timestamp state now that receiver exists.
		if c.tsEnabled {
			c.tsLastAckSent = c.rcv.nxt
			// Update tsRecent from the handshake ACK's timestamp.
			if seg.hasTS {
				c.tsRecent = seg.tsVal
			}
		}

		c.resetKeepalive()

		// Deliver data piggybacked on the completing ACK (RFC 793 allows this).
		if len(seg.payload) > 0 && c.rcv != nil {
			c.rcv.handleData(seg.seq, seg.payload)
			c.sendACK()
		}

		select {
		case c.handler.listener.acceptCh <- c:
		case <-c.done:
		}
	} else if seg.flags.Has(header.TCPFlagSYN) {
		// Duplicate SYN — retransmit SYN+ACK.
		c.sendSYNACK()
	}
}
