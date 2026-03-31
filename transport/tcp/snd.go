package tcp

import (
	"time"

	"github.com/Zwlin98/netstack/header"
)

const (
	minRTO     = 200 * time.Millisecond
	maxRTO     = 60 * time.Second
	initialRTO = time.Second

	defaultMaxRetries = 15
	initialSSThresh   = 65535
)

// unackedSegment holds a copy of a sent segment for possible retransmission.
type unackedSegment struct {
	seq           uint32
	data          []byte
	fin           bool // true if this is a FIN segment
	sentAt        time.Time
	retransmitted bool
}

// sender tracks the send side of a TCP connection.
type sender struct {
	iss uint32 // initial send sequence number
	nxt uint32 // next sequence to send (SND.NXT)
	una uint32 // oldest unacknowledged (SND.UNA)
	wnd uint16 // peer's advertised receive window (SND.WND)
	mss int    // maximum segment size, derived from MTU

	// Retransmission state.
	rto        time.Duration
	srtt       time.Duration
	rttvar     time.Duration
	unacked    []unackedSegment
	retries    int
	maxRetries int

	// Congestion control state.
	cwnd        uint32
	ssthresh    uint32
	dupACKCount int
}

func newSender(iss uint32, peerWnd uint16, mtu int) *sender {
	mss := mtu - header.IPv4MinHeaderSize - header.TCPMinHeaderSize
	if mss <= 0 {
		mss = 536 // RFC 879 default
	}
	return &sender{
		iss:        iss,
		nxt:        iss + 1, // SYN consumed one sequence number
		una:        iss + 1,
		wnd:        peerWnd,
		mss:        mss,
		rto:        initialRTO,
		maxRetries: defaultMaxRetries,
		cwnd:       uint32(mss),
		ssthresh:   initialSSThresh,
	}
}

// effectiveWindow returns how many bytes the sender may still have in flight.
func (s *sender) effectiveWindow() int {
	flightSize := int(s.nxt - s.una)
	return min(int(s.cwnd), int(s.wnd)) - flightSize
}

// sendPending sends as many segments as the effective window allows.
func (s *sender) sendPending(conn *TCPConn) {
	for {
		windowLeft := s.effectiveWindow()
		if windowLeft <= 0 {
			break
		}
		available := conn.writeBuf.Len()
		if available <= 0 {
			break
		}

		segSize := min(min(windowLeft, available), s.mss)
		data := make([]byte, segSize)
		n := conn.writeBuf.ReadNoBlock(data)
		if n == 0 {
			break
		}
		data = data[:n]

		conn.sendData(data, s.nxt)
		s.recordSent(s.nxt, data)
		s.nxt += uint32(n)
	}
}

// updateRTT applies the Jacobson/Karels algorithm (RFC 6298) to a new RTT measurement.
func (s *sender) updateRTT(measured time.Duration) {
	if s.srtt == 0 {
		// First measurement.
		s.srtt = measured
		s.rttvar = measured / 2
	} else {
		diff := s.srtt - measured
		if diff < 0 {
			diff = -diff
		}
		s.rttvar = (3*s.rttvar + diff) / 4
		s.srtt = (7*s.srtt + measured) / 8
	}
	s.rto = s.srtt + 4*s.rttvar
	s.rto = max(s.rto, minRTO)
	s.rto = min(s.rto, maxRTO)
}

// recordSent saves a copy of sent data for possible retransmission.
func (s *sender) recordSent(seq uint32, data []byte) {
	s.unacked = append(s.unacked, unackedSegment{
		seq:    seq,
		data:   append([]byte(nil), data...), // copy
		sentAt: time.Now(),
	})
}

// removeAcked removes segments fully acknowledged by ack and measures RTT
// from the first non-retransmitted acked segment (Karn's algorithm).
func (s *sender) removeAcked(ack uint32) {
	rttMeasured := false
	i := 0
	for i < len(s.unacked) {
		seg := &s.unacked[i]
		segEnd := seg.seq + uint32(len(seg.data))
		if seg.fin {
			segEnd = seg.seq + 1 // FIN occupies one sequence number
		}
		if !seqGreaterThan(ack, seg.seq) {
			break
		}
		// Measure RTT from the first non-retransmitted segment (Karn's algorithm).
		if !rttMeasured && !seg.retransmitted {
			s.updateRTT(time.Since(seg.sentAt))
			rttMeasured = true
		}
		if seqLessThan(segEnd, ack) || segEnd == ack {
			i++
		} else {
			break
		}
	}
	s.unacked = s.unacked[i:]
}

// recordSentFIN records a FIN segment for retransmission tracking.
func (s *sender) recordSentFIN(seq uint32) {
	s.unacked = append(s.unacked, unackedSegment{
		seq:    seq,
		fin:    true,
		sentAt: time.Now(),
	})
}

// hasUnacked returns true if there are segments awaiting acknowledgment.
func (s *sender) hasUnacked() bool {
	return len(s.unacked) > 0
}

// retransmitOldest resends the oldest unacked segment.
func (s *sender) retransmitOldest(conn *TCPConn) {
	if len(s.unacked) == 0 {
		return
	}
	seg := &s.unacked[0]
	seg.retransmitted = true
	seg.sentAt = time.Now()
	if seg.fin {
		conn.sendFINSegment(seg.seq)
	} else {
		conn.sendData(seg.data, seg.seq)
	}
}

// handleRTO is called when the retransmission timer expires.
func (s *sender) handleRTO(conn *TCPConn) {
	if len(s.unacked) == 0 {
		return
	}

	s.retries++
	if s.retries > s.maxRetries {
		conn.abort()
		return
	}

	// Congestion response: multiplicative decrease.
	s.ssthresh = max(s.cwnd/2, 2*uint32(s.mss))
	s.cwnd = uint32(s.mss)

	// Exponential backoff.
	s.rto *= 2
	s.rto = min(s.rto, maxRTO)

	s.retransmitOldest(conn)
}

// handleACK processes an incoming ACK, updating congestion control state.
func (s *sender) handleACK(ack uint32, conn *TCPConn) {
	if ack == s.una {
		// Duplicate ACK.
		s.handleDupACK(conn)
		return
	}

	if !seqGreaterThan(ack, s.una) || seqGreaterThan(ack, s.nxt) {
		return
	}

	// New ACK.
	acked := uint32(0)
	if seqGreaterThan(ack, s.una) {
		acked = ack - s.una
	}
	s.una = ack
	s.dupACKCount = 0
	s.retries = 0

	s.removeAcked(ack)

	// Congestion window update.
	if s.cwnd < s.ssthresh {
		// Slow start: increase cwnd by acked bytes, capped at ssthresh.
		s.cwnd += acked
		if s.cwnd > s.ssthresh {
			s.cwnd = s.ssthresh
		}
	} else {
		// Congestion avoidance: increase cwnd by ~1 MSS per RTT.
		// Scale by acked bytes so cumulative ACKs produce the same growth
		// as individual per-segment ACKs.
		increment := uint32(s.mss) * acked / s.cwnd
		if increment == 0 {
			increment = 1
		}
		s.cwnd += increment
	}

	s.sendPending(conn)
}

// handleDupACK processes a duplicate ACK for fast retransmit.
func (s *sender) handleDupACK(conn *TCPConn) {
	s.dupACKCount++
	if s.dupACKCount == 3 {
		// Fast retransmit.
		s.ssthresh = max(s.cwnd/2, 2*uint32(s.mss))
		s.cwnd = s.ssthresh + 3*uint32(s.mss)
		s.retransmitOldest(conn)
	}
}
