package tcp

import "time"

// SetMaxRetries overrides the sender's max retries for testing.
func SetMaxRetries(c *TCPConn, n int) {
	if c.snd != nil {
		c.snd.maxRetries = n
	}
}

// ConnState returns the current TCP state string for testing.
func ConnState(c *TCPConn) string {
	return connSnapshot(c).State
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
	return connSnapshot(c).Cwnd
}

// SenderMSS returns the negotiated MSS for testing.
func SenderMSS(c *TCPConn) int {
	return connSnapshot(c).SndMSS
}

// SenderNxt returns the sender's next sequence number for testing.
func SenderNxt(c *TCPConn) uint32 {
	return connSnapshot(c).SndNxt
}

// SenderSRTT returns the sender's smoothed RTT for testing.
func SenderSRTT(c *TCPConn) time.Duration {
	return connSnapshot(c).SRTT
}

// SetSenderSRTT overrides the sender's SRTT for deterministic tests.
func SetSenderSRTT(c *TCPConn, d time.Duration) {
	if c.snd != nil {
		c.snd.srtt = d
		c.snd.rto = d
		c.updateSnapshot()
	}
}

// OOOCount returns the number of out-of-order segments buffered.
func OOOCount(c *TCPConn) int {
	return connSnapshot(c).OOO
}

// SenderDSACKSeen returns whether the sender has detected a DSACK.
func SenderDSACKSeen(c *TCPConn) bool {
	return connSnapshot(c).DSACKSeen
}

// ClearSenderDSACK clears the DSACK seen flag.
func ClearSenderDSACK(c *TCPConn) {
	if c.snd != nil {
		c.snd.dsackSeen = false
	}
}

// SenderMaxWnd returns the sender's maxWnd for testing.
func SenderMaxWnd(c *TCPConn) uint32 {
	return connSnapshot(c).SndMaxWnd
}

// SenderWnd returns the sender's current peer window for testing.
func SenderWnd(c *TCPConn) uint32 {
	return connSnapshot(c).SndWnd
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

// WriteBufCap returns the write buffer capacity for testing.
func WriteBufCap(c *TCPConn) int {
	if c.writeBuf != nil {
		return c.writeBuf.Cap()
	}
	return 0
}

// ConnReadBufSize returns the target readBufSize for testing.
func ConnReadBufSize(c *TCPConn) int {
	return c.readBufSize
}

// ConnWriteBufSize returns the target writeBufSize for testing.
func ConnWriteBufSize(c *TCPConn) int {
	return c.writeBufSize
}

// HandlerGSOEnabled returns whether the handler detected GSO support.
func HandlerGSOEnabled(h *TCPHandler) bool {
	return h.gsoWriter != nil
}

// HandlerGSOMaxSize returns the cached GSO max size.
func HandlerGSOMaxSize(h *TCPHandler) int {
	return h.gsoMaxSize
}

func connSnapshot(c *TCPConn) ConnSnapshot {
	c.snapshotMu.Lock()
	snap := c.snapshotData
	c.snapshotMu.Unlock()
	return snap
}
