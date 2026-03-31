package tcp

// handleEstablished processes a segment in the ESTABLISHED state.
// RST and unexpected SYN are handled by the common pipeline in handleSegment.
// Data transfer logic will be added in P4b.
func (c *TCPConn) handleEstablished(seg segment) {
	// P4b will add: ACK processing, data delivery, window updates.
	// P4d will add: FIN handling → CLOSE_WAIT transition.
}
