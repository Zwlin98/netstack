package udp

import "sync/atomic"

// Stats holds aggregate UDP counters.
// All fields are safe for concurrent reads via atomic loads.
type Stats struct {
	DatagramsIn    atomic.Uint64
	DatagramsOut   atomic.Uint64
	BytesIn        atomic.Uint64
	BytesOut       atomic.Uint64
	DroppedInbound atomic.Uint64
	OversizedOut   atomic.Uint64
	ChecksumErrors atomic.Uint64
}

// EnableStats allocates and activates the UDP stats counters.
// Must be called before handling packets. Returns the stats pointer
// so the caller can read counters at any time.
func (h *UDPHandler) EnableStats() *Stats {
	h.stats = &Stats{}
	return h.stats
}
