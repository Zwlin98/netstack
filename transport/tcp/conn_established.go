package tcp

import "github.com/Zwlin98/netstack/header"

// handleEstablished processes a segment in the ESTABLISHED state.
// RST and unexpected SYN are handled by the common pipeline in handleSegment.
func (c *TCPConn) handleEstablished(seg segment) {
	// ACK processing: update peer window, congestion control.
	if seg.flags.Has(header.TCPFlagACK) && c.snd != nil {
		oldWnd := c.snd.wnd
		c.snd.wnd = seg.wnd
		c.snd.handleACK(seg.ack, c)
		// A pure window update (same ACK, larger window) should trigger sending.
		if seg.ack == c.snd.una && seg.wnd > oldWnd {
			c.snd.sendPending(c)
		}
	}

	// Data delivery.
	if len(seg.payload) > 0 && c.rcv != nil {
		c.rcv.handleData(seg.seq, seg.payload)
	}

	// FIN handling: peer is closing their send side.
	if seg.flags.Has(header.TCPFlagFIN) && c.rcv != nil {
		c.rcv.nxt++ // FIN occupies one sequence number
		c.sendACK() // single ACK covers data + FIN
		c.readBuf.CloseWrite()
		c.state = stateCloseWait
		return
	}

	// ACK for data only (no FIN in this segment).
	if len(seg.payload) > 0 {
		c.sendACK()
	}
}
