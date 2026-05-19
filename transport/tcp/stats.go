package tcp

import (
	"sync/atomic"
	"time"
)

// Stats holds aggregate TCP counters.
// All fields are safe for concurrent reads via atomic loads.
type Stats struct {
	// Connection lifecycle
	ActiveConns   atomic.Int64
	TotalAccepted atomic.Uint64
	TotalClosed   atomic.Uint64
	TotalReset    atomic.Uint64

	// Traffic
	SegmentsIn      atomic.Uint64
	SegmentsOut     atomic.Uint64
	PayloadBytesIn  atomic.Uint64
	PayloadBytesOut atomic.Uint64

	// Errors and loss
	ChecksumErrors  atomic.Uint64
	DroppedInbound  atomic.Uint64
	Retransmits     atomic.Uint64
	FastRetransmits atomic.Uint64
	DupACKsIn       atomic.Uint64

	// Protocol events
	ResetsSent       atomic.Uint64
	ResetsReceived   atomic.Uint64
	ZeroWindowProbes atomic.Uint64
	PAWSDrops        atomic.Uint64

	// Timeouts
	TimeoutKeepalive atomic.Uint64
	TimeoutFinWait2  atomic.Uint64
	TimeoutSynRcvd   atomic.Uint64
}

// EnableStats allocates and activates the TCP stats counters.
// Must be called before accepting connections. Returns the stats pointer
// so the caller can read counters at any time.
func (h *TCPHandler) EnableStats() *Stats {
	h.stats = &Stats{}
	return h.stats
}

// ConnSnapshot holds a point-in-time snapshot of a single TCP connection's state.
type ConnSnapshot struct {
	Flow         FlowID
	State        string
	SRTT         time.Duration
	RTO          time.Duration
	Cwnd         uint32
	SSThresh     uint32
	SndWnd       uint32
	SndNxt       uint32
	SndMSS       int
	SndMaxWnd    uint32
	RcvWnd       uint16
	Unacked      int
	OOO          int
	ReadBufUsed  int
	WriteBufUsed int
	BufCap       int // Deprecated: use ReadBufCap.
	ReadBufCap   int
	WriteBufCap  int
	DSACKSeen    bool
	Retries      int
	InRecovery   bool
}

// ConnSnapshots returns a snapshot of every active connection.
// Safe for concurrent use — reads each connection's mutex-protected snapshot.
func (h *TCPHandler) ConnSnapshots() []ConnSnapshot {
	h.mu.RLock()
	conns := make([]*TCPConn, 0, len(h.conns))
	for _, c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.RUnlock()

	snapshots := make([]ConnSnapshot, 0, len(conns))
	for _, c := range conns {
		c.snapshotMu.Lock()
		snap := c.snapshotData
		c.snapshotMu.Unlock()
		snapshots = append(snapshots, snap)
	}
	return snapshots
}

// ConnSnapshot returns the snapshot for a single connection, or nil if not found.
func (h *TCPHandler) ConnSnapshot(flow FlowID) *ConnSnapshot {
	h.mu.RLock()
	c, ok := h.conns[flow]
	h.mu.RUnlock()
	if !ok {
		return nil
	}
	c.snapshotMu.Lock()
	snap := c.snapshotData
	c.snapshotMu.Unlock()
	return &snap
}
