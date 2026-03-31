package udp

// Config holds tunable parameters for the UDP handler.
type Config struct {
	InboundQueueSize int
}

var defaultConfig = Config{
	InboundQueueSize: 256,
}

// Option configures a UDPHandler.
type Option func(*Config)

// WithInboundQueueSize sets the capacity of the inbound datagram queue.
func WithInboundQueueSize(n int) Option {
	return func(c *Config) { c.InboundQueueSize = n }
}
