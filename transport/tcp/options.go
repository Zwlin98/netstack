package tcp

import "time"

// Config holds tunable parameters for the TCP handler and its connections.
type Config struct {
	// Buffer sizes.
	ReadBufferSize  int
	WriteBufferSize int

	// Initial buffer sizes for lazy allocation. Buffers start small and
	// grow to ReadBufferSize/WriteBufferSize on demand.
	InitialReadBufferSize  int
	InitialWriteBufferSize int

	// Accept queue.
	AcceptQueueSize int

	// Per-connection inbound segment queue.
	InboundQueueSize int

	// Keepalive (RFC 1122 §4.2.3.6).
	KeepaliveIdle     time.Duration
	KeepaliveInterval time.Duration
	KeepaliveCount    int

	// Timeouts.
	SynRcvdTimeout             time.Duration
	FinWait2Timeout            time.Duration
	TimeWaitDuration           time.Duration
	DelayedACKTimeout          time.Duration
	MaxZeroWindowProbeInterval time.Duration

	// Retransmission.
	MinRTO     time.Duration
	MaxRTO     time.Duration
	InitialRTO time.Duration
	MaxRetries int

	// Congestion.
	InitialSSThresh uint32

	// Receive window advertised in SYN+ACK.
	ReceiveWindowSize uint16

	// Maximum receive buffer size for auto-tuning (0 = no auto-tuning).
	MaxReadBufferSize int
}

var defaultConfig = Config{
	ReadBufferSize:  256 * 1024,
	WriteBufferSize: 256 * 1024,

	InitialReadBufferSize:  32 * 1024,
	InitialWriteBufferSize: 32 * 1024,

	AcceptQueueSize:  16,
	InboundQueueSize: 256,

	KeepaliveIdle:     7200 * time.Second,
	KeepaliveInterval: 75 * time.Second,
	KeepaliveCount:    9,

	SynRcvdTimeout:             75 * time.Second,
	FinWait2Timeout:            60 * time.Second,
	TimeWaitDuration:           2 * time.Minute,
	DelayedACKTimeout:          200 * time.Millisecond,
	MaxZeroWindowProbeInterval: 60 * time.Second,

	MinRTO:     200 * time.Millisecond,
	MaxRTO:     60 * time.Second,
	InitialRTO: time.Second,
	MaxRetries: 15,

	InitialSSThresh: 65535,

	ReceiveWindowSize: 65535,

	MaxReadBufferSize: 4 * 1024 * 1024, // 4MB default
}

// Option configures a TCPHandler.
type Option func(*Config)

func WithReadBufferSize(n int) Option  { return func(c *Config) { c.ReadBufferSize = n } }
func WithWriteBufferSize(n int) Option { return func(c *Config) { c.WriteBufferSize = n } }
func WithAcceptQueueSize(n int) Option { return func(c *Config) { c.AcceptQueueSize = n } }
func WithInboundQueueSize(n int) Option { return func(c *Config) { c.InboundQueueSize = n } }

func WithKeepaliveIdle(d time.Duration) Option     { return func(c *Config) { c.KeepaliveIdle = d } }
func WithKeepaliveInterval(d time.Duration) Option { return func(c *Config) { c.KeepaliveInterval = d } }
func WithKeepaliveCount(n int) Option              { return func(c *Config) { c.KeepaliveCount = n } }

func WithSynRcvdTimeout(d time.Duration) Option             { return func(c *Config) { c.SynRcvdTimeout = d } }
func WithFinWait2Timeout(d time.Duration) Option             { return func(c *Config) { c.FinWait2Timeout = d } }
func WithTimeWaitDuration(d time.Duration) Option            { return func(c *Config) { c.TimeWaitDuration = d } }
func WithDelayedACKTimeout(d time.Duration) Option           { return func(c *Config) { c.DelayedACKTimeout = d } }
func WithMaxZeroWindowProbeInterval(d time.Duration) Option  { return func(c *Config) { c.MaxZeroWindowProbeInterval = d } }

func WithMinRTO(d time.Duration) Option     { return func(c *Config) { c.MinRTO = d } }
func WithMaxRTO(d time.Duration) Option     { return func(c *Config) { c.MaxRTO = d } }
func WithInitialRTO(d time.Duration) Option { return func(c *Config) { c.InitialRTO = d } }
func WithMaxRetries(n int) Option           { return func(c *Config) { c.MaxRetries = n } }

func WithInitialSSThresh(n uint32) Option   { return func(c *Config) { c.InitialSSThresh = n } }
func WithReceiveWindowSize(n uint16) Option { return func(c *Config) { c.ReceiveWindowSize = n } }
func WithMaxReadBufferSize(n int) Option      { return func(c *Config) { c.MaxReadBufferSize = n } }
func WithInitialReadBufferSize(n int) Option  { return func(c *Config) { c.InitialReadBufferSize = n } }
func WithInitialWriteBufferSize(n int) Option { return func(c *Config) { c.InitialWriteBufferSize = n } }
