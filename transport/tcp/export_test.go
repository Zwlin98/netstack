package tcp

// SetMaxRetries overrides the sender's max retries for testing.
func SetMaxRetries(c *TCPConn, n int) {
	if c.snd != nil {
		c.snd.maxRetries = n
	}
}
