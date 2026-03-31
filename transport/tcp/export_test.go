package tcp

import "time"

// SetMaxRetries overrides the sender's max retries for testing.
func SetMaxRetries(c *TCPConn, n int) {
	if c.snd != nil {
		c.snd.maxRetries = n
	}
}

// SetTimeWaitDuration overrides the TIME_WAIT duration for testing.
func SetTimeWaitDuration(d time.Duration) func() {
	old := timeWaitDuration
	timeWaitDuration = d
	return func() { timeWaitDuration = old }
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
