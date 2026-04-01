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

// SenderDSACKSeen returns whether the sender has detected a DSACK.
func SenderDSACKSeen(c *TCPConn) bool {
	if c.snd != nil {
		return c.snd.dsackSeen
	}
	return false
}

// ClearSenderDSACK clears the DSACK seen flag.
func ClearSenderDSACK(c *TCPConn) {
	if c.snd != nil {
		c.snd.dsackSeen = false
	}
}

// SenderMaxWnd returns the sender's maxWnd for testing.
func SenderMaxWnd(c *TCPConn) uint32 {
	if c.snd != nil {
		return c.snd.maxWnd
	}
	return 0
}

// SenderWnd returns the sender's current peer window for testing.
func SenderWnd(c *TCPConn) uint32 {
	if c.snd != nil {
		return c.snd.wnd
	}
	return 0
}

// ReadBufCap returns the receive buffer capacity for testing.
func ReadBufCap(c *TCPConn) int {
	if c.readBuf != nil {
		return c.readBuf.Cap()
	}
	return 0
}

// NewRingBufferExported creates a new ringBuffer for testing.
func NewRingBufferExported(size int) *ringBuffer {
	return newRingBuffer(size)
}
