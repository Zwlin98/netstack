package tcp

import "github.com/Zwlin98/netstack/header"

// handleEstablished processes a segment in the ESTABLISHED state.
// RST and unexpected SYN are handled by the common pipeline in handleSegment.
func (c *TCPConn) handleEstablished(seg segment) {
	// ACK processing: advance snd.una, update peer window, try to send more.
	if seg.flags.Has(header.TCPFlagACK) && c.snd != nil {
		c.snd.handleACK(seg.ack)
		c.snd.wnd = seg.wnd
		c.snd.sendPending(c) // peer window may have opened
	}

	// Data delivery.
	if len(seg.payload) > 0 && c.rcv != nil {
		c.rcv.handleData(seg.seq, seg.payload)
		c.sendACK()
	}

	// P4d will add: FIN handling → CLOSE_WAIT transition.
}
