package tcp

// SetMaxRetries overrides the sender's max retries for testing.
func SetMaxRetries(c *TCPConn, n int) {
	if c.snd != nil {
		c.snd.maxRetries = n
	}
}

// ConnState returns the current TCP state string for testing.
func ConnState(c *TCPConn) string {
	return c.state.String()
}

// ConnTableLen returns the number of entries in the handler's connection table.
func ConnTableLen(h *TCPHandler) int {
	h.mu.RLock()
	n := len(h.conns)
	h.mu.RUnlock()
	return n
}

// SenderCwnd returns the current congestion window for testing.
func SenderCwnd(c *TCPConn) uint32 {
	if c.snd != nil {
		return c.snd.cwnd
	}
	return 0
}

// SenderMSS returns the negotiated MSS for testing.
func SenderMSS(c *TCPConn) int {
	if c.snd != nil {
		return c.snd.mss
	}
	return 0
}

// SenderNxt returns the sender's next sequence number for testing.
func SenderNxt(c *TCPConn) uint32 {
	if c.snd != nil {
		return c.snd.nxt
	}
	return 0
}

// OOOCount returns the number of out-of-order segments buffered.
func OOOCount(c *TCPConn) int {
	if c.rcv != nil {
		return len(c.rcv.ooo)
	}
	return 0
}
