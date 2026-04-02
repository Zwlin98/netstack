package stack

import "sync/atomic"

// Stats holds aggregate packet counters for the network stack.
// All fields are safe for concurrent reads via atomic loads.
type Stats struct {
	PacketsIn       atomic.Uint64
	PacketsOut      atomic.Uint64
	BytesIn         atomic.Uint64
	BytesOut        atomic.Uint64
	DroppedOutbound atomic.Uint64
	UnknownProtocol atomic.Uint64
}

// EnableStats allocates and activates the stats counters.
// Must be called before Start(). Returns the stats pointer
// so the caller can read counters at any time.
func (s *Stack) EnableStats() *Stats {
	s.stats = &Stats{}
	return s.stats
}

// OutboundQueueLen returns the current number of packets in the outbound queue.
// Does not require stats to be enabled.
func (s *Stack) OutboundQueueLen() int {
	return len(s.outboundCh)
}
