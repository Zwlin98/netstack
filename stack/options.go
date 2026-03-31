package stack

// Config holds tunable parameters for the network stack.
type Config struct {
	TTL               uint8
	OutboundQueueSize int
}

var defaultConfig = Config{
	TTL:               64,
	OutboundQueueSize: 256,
}

// Option configures a Stack.
type Option func(*Config)

// WithTTL sets the default TTL for outgoing IPv4 packets.
func WithTTL(ttl uint8) Option {
	return func(c *Config) { c.TTL = ttl }
}

// WithOutboundQueueSize sets the capacity of the outbound packet queue.
func WithOutboundQueueSize(n int) Option {
	return func(c *Config) { c.OutboundQueueSize = n }
}
