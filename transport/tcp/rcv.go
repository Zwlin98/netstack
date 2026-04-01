package tcp

import (
	"time"

	"github.com/Zwlin98/netstack/header"
)

// receiver tracks the receive side of a TCP connection.
type receiver struct {
	irs uint32 // initial receive sequence number
	nxt uint32 // next expected sequence (RCV.NXT)

	// Out-of-order segments sorted by seq.
	ooo []oooSegment

	readBuf *ringBuffer
	conn    *TCPConn

	// Deferred FIN: set when FIN arrives before all preceding data.
	finReceived bool
	finSeq      uint32 // sequence number where FIN sits (after all data)

	// DSACK (RFC 2883): pending DSACK block to include in the next ACK.
	// Cleared after being sent once (one-shot notification).
	dsackBlock    header.SACKBlock
	hasDSACKBlock bool

	// Receive buffer auto-tuning: grow readBuf based on throughput.
	autoTune struct {
		measureStart   time.Time // when current measurement window began
		bytesDelivered int       // bytes delivered in current window
		maxBufSize     int       // maximum buffer capacity (config limit)
	}
}

type oooSegment struct {
	seq  uint32
	data []byte
}

func newReceiver(irs uint32, readBuf *ringBuffer, conn *TCPConn, maxBufSize int) *receiver {
	r := &receiver{
		irs:     irs,
		nxt:     irs + 1, // SYN consumed one sequence number
		readBuf: readBuf,
		conn:    conn,
	}
	// Enable auto-tuning if maxBufSize > initial capacity.
	if maxBufSize > readBuf.Cap() {
		r.autoTune.maxBufSize = maxBufSize
	}
	return r
}

// rcvWnd returns the current receive window size in bytes (unscaled),
// used internally for segment validation and trimming.
func (r *receiver) rcvWnd() uint32 {
	free := r.readBuf.Free()
	if free <= 0 {
		return 0
	}
	return uint32(free)
}

// wnd returns the current receive window for the wire (scaled down by rcvWndScale).
// Implements Clark's algorithm (RFC 1122 §4.2.3.3) for SWS avoidance:
// advertise zero when free space is below min(MSS, bufCap/2).
func (r *receiver) wnd() uint16 {
	free := r.readBuf.Free()

	// SWS avoidance: suppress small window advertisements.
	mss := 536 // default
	if r.conn.snd != nil {
		mss = r.conn.snd.mss
	}
	threshold := min(mss, r.readBuf.Cap()/2)
	if free < threshold {
		return 0
	}

	scale := r.conn.rcvWndScale
	scaled := free >> scale
	if scaled > 0xFFFF {
		return 0xFFFF
	}
	return uint16(scaled)
}

// handleData processes incoming data at the given sequence number.
// Applies segment trimming (RFC 793 §3.9): trims bytes already received
// and bytes beyond the receive window before delivery or OOO buffering.
func (r *receiver) handleData(seq uint32, data []byte) {
	if len(data) == 0 {
		return
	}

	// Trim leading bytes already received (segment trimming).
	if seqLessThan(seq, r.nxt) {
		overlap := r.nxt - seq
		if overlap >= uint32(len(data)) {
			// Fully duplicate segment — record DSACK block (RFC 2883).
			r.dsackBlock = header.SACKBlock{Start: seq, End: seq + uint32(len(data))}
			r.hasDSACKBlock = true
			return
		}
		data = data[overlap:]
		seq = r.nxt
	}

	// Receive window boundary check (RFC 793 §3.9).
	// Trim or discard bytes beyond the receive window.
	rcvWnd := r.rcvWnd()
	if rcvWnd == 0 {
		// Zero window: discard all data.
		return
	}
	wndEnd := r.nxt + rcvWnd
	segEnd := seq + uint32(len(data))
	if !seqLessThan(seq, wndEnd) {
		// Segment entirely beyond the receive window — discard.
		return
	}
	if seqGreaterThan(segEnd, wndEnd) {
		// Trim tail beyond window.
		data = data[:wndEnd-seq]
	}

	// Discard data when read side is shut down.
	if r.conn.readShutdown {
		// Still advance sequence numbers so ACKs are correct.
		if seq == r.nxt {
			r.nxt += uint32(len(data))
		}
		return
	}

	if seq == r.nxt {
		// In order: deliver to readBuf. Only advance nxt by bytes actually written.
		n := r.deliver(data)
		r.nxt += uint32(n)
		// Drain any now-contiguous OOO segments.
		if n > 0 {
			r.deliverOOO()
		}
	} else if seqGreaterThan(seq, r.nxt) {
		// Future segment: buffer out-of-order.
		r.insertOOO(seq, data)
	}
}

func (r *receiver) deliver(data []byte) int {
	n := r.readBuf.WriteNoBlock(data)
	if n > 0 {
		r.autoTuneAccumulate(n)
	}
	return n
}

// autoTuneAccumulate tracks delivered bytes and triggers buffer growth checks
// when one SRTT measurement window completes.
func (r *receiver) autoTuneAccumulate(n int) {
	if r.autoTune.maxBufSize <= 0 {
		return // auto-tuning disabled
	}

	now := time.Now()
	if r.autoTune.measureStart.IsZero() {
		r.autoTune.measureStart = now
	}
	r.autoTune.bytesDelivered += n

	// Check if one SRTT has elapsed.
	srtt := r.senderSRTT()
	if srtt <= 0 {
		return // no RTT measurement yet
	}
	if now.Sub(r.autoTune.measureStart) < srtt {
		return // window not yet complete
	}

	// Measurement window complete — check if buffer should grow.
	r.autoTuneCheck()
}

// senderSRTT returns the sender's smoothed RTT, or 0 if unavailable.
func (r *receiver) senderSRTT() time.Duration {
	if r.conn.snd != nil {
		return r.conn.snd.srtt
	}
	return 0
}

// autoTuneCheck evaluates whether to grow the receive buffer based on throughput.
// If throughput per RTT > 50% of buffer capacity, double the buffer.
func (r *receiver) autoTuneCheck() {
	curCap := r.readBuf.Cap()
	threshold := curCap / 2

	if r.autoTune.bytesDelivered > threshold && curCap < r.autoTune.maxBufSize {
		newCap := min(curCap*2, r.autoTune.maxBufSize)
		r.readBuf.Grow(newCap)
	}

	// Reset measurement window.
	r.autoTune.measureStart = time.Now()
	r.autoTune.bytesDelivered = 0
}

func (r *receiver) insertOOO(seq uint32, data []byte) {
	// DSACK check: if the segment is entirely covered by an existing OOO entry,
	// record it as a DSACK block (RFC 2883) and discard the duplicate.
	origSeq := seq
	origEnd := seq + uint32(len(data))
	for _, entry := range r.ooo {
		entryEnd := entry.seq + uint32(len(entry.data))
		if !seqLessThan(origSeq, entry.seq) && !seqGreaterThan(origEnd, entryEnd) {
			// Fully covered by existing OOO entry — duplicate.
			r.dsackBlock = header.SACKBlock{Start: origSeq, End: origEnd}
			r.hasDSACKBlock = true
			return
		}
	}

	// Copy data since the packet buffer will be released.
	saved := make([]byte, len(data))
	copy(saved, data)

	newEnd := seq + uint32(len(saved))

	// Find insertion point (sorted by seq).
	i := 0
	for i < len(r.ooo) && seqLessThan(r.ooo[i].seq, seq) {
		i++
	}

	// Merge with preceding segment if overlapping or adjacent.
	if i > 0 {
		prev := &r.ooo[i-1]
		prevEnd := prev.seq + uint32(len(prev.data))
		if !seqLessThan(prevEnd, seq) {
			// Overlaps or adjacent — merge into prev.
			if seqGreaterThan(newEnd, prevEnd) {
				// Extend prev with new bytes beyond prevEnd.
				overlap := prevEnd - seq
				prev.data = append(prev.data, saved[overlap:]...)
			}
			// Now merged into prev; adjust i to point at prev for forward merge.
			i--
			seq = prev.seq
			saved = prev.data
			newEnd = seq + uint32(len(saved))
		}
	}

	// Insert or update at position i.
	if i < len(r.ooo) && r.ooo[i].seq == seq {
		// Update in place (from prev merge or duplicate with different len).
		r.ooo[i].data = saved
	} else {
		// Insert new entry.
		r.ooo = append(r.ooo, oooSegment{})
		copy(r.ooo[i+1:], r.ooo[i:])
		r.ooo[i] = oooSegment{seq: seq, data: saved}
	}

	// Merge with following segments if overlapping or adjacent.
	for i+1 < len(r.ooo) {
		cur := &r.ooo[i]
		curEnd := cur.seq + uint32(len(cur.data))
		next := &r.ooo[i+1]
		if seqLessThan(curEnd, next.seq) {
			break // gap — no more merging
		}
		// Overlaps or adjacent — absorb next into cur.
		nextEnd := next.seq + uint32(len(next.data))
		if seqGreaterThan(nextEnd, curEnd) {
			overlap := curEnd - next.seq
			cur.data = append(cur.data, next.data[overlap:]...)
		}
		// Remove next.
		r.ooo = append(r.ooo[:i+1], r.ooo[i+2:]...)
	}
}

// sackBlocks returns the current SACK blocks from the OOO buffer.
// If a DSACK block is pending (RFC 2883), it is prepended as the first block
// and cleared after this call (one-shot notification).
// The total number of blocks is limited to fit within the TCP options space:
// 3 blocks when timestamps are enabled, 4 blocks otherwise.
func (r *receiver) sackBlocks() []header.SACKBlock {
	hasDSACK := r.hasDSACKBlock
	if len(r.ooo) == 0 && !hasDSACK {
		return nil
	}

	// With timestamps (12 bytes), only 3 SACK blocks fit in TCP options.
	// Without timestamps, up to 4 blocks fit.
	maxBlocks := 4
	if r.conn.tsEnabled {
		maxBlocks = 3
	}

	var blocks []header.SACKBlock

	// Prepend DSACK block if pending.
	if hasDSACK {
		blocks = append(blocks, r.dsackBlock)
		r.hasDSACKBlock = false
		r.dsackBlock = header.SACKBlock{}
	}

	if len(r.ooo) > 0 {
		// Build coalesced ranges from sorted OOO segments.
		var ranges []header.SACKBlock
		cur := header.SACKBlock{
			Start: r.ooo[0].seq,
			End:   r.ooo[0].seq + uint32(len(r.ooo[0].data)),
		}
		for j := 1; j < len(r.ooo); j++ {
			seg := r.ooo[j]
			segEnd := seg.seq + uint32(len(seg.data))
			if seg.seq <= cur.End {
				// Adjacent or overlapping — extend.
				if segEnd > cur.End {
					cur.End = segEnd
				}
			} else {
				ranges = append(ranges, cur)
				cur = header.SACKBlock{Start: seg.seq, End: segEnd}
			}
		}
		ranges = append(ranges, cur)

		// Append regular blocks (most-recent-first), staying within limit.
		remaining := maxBlocks - len(blocks)
		n := min(len(ranges), remaining)
		for i := range n {
			blocks = append(blocks, ranges[len(ranges)-1-i])
		}
	}

	return blocks
}

func (r *receiver) deliverOOO() {
	for len(r.ooo) > 0 && !seqGreaterThan(r.ooo[0].seq, r.nxt) {
		seg := r.ooo[0]
		data := seg.data
		seq := seg.seq

		// Trim leading bytes already received (seq < nxt).
		if seqLessThan(seq, r.nxt) {
			overlap := r.nxt - seq
			if overlap >= uint32(len(data)) {
				// Fully consumed — discard.
				r.ooo = r.ooo[1:]
				continue
			}
			data = data[overlap:]
			seq = r.nxt
		}

		n := r.deliver(data)
		r.nxt += uint32(n)
		if n < len(data) {
			// Partial delivery: retain undelivered bytes for later.
			r.ooo[0].data = data[n:]
			r.ooo[0].seq = seq + uint32(n)
			break
		}
		r.ooo = r.ooo[1:]
	}

	// Check deferred FIN: all preceding data now delivered?
	if r.finReceived && r.nxt == r.finSeq {
		r.finReceived = false
		r.conn.processFIN()
	}
}

// seqGreaterThan returns true if a > b in sequence number space.
func seqGreaterThan(a, b uint32) bool {
	return int32(a-b) > 0
}

// seqLessThan returns true if a < b in sequence number space.
func seqLessThan(a, b uint32) bool {
	return int32(a-b) < 0
}

// seqWithinWindow returns true if seq is within [start, start+wnd) in sequence number space.
func seqWithinWindow(seq, start, wnd uint32) bool {
	return !seqLessThan(seq, start) && seqLessThan(seq, start+wnd)
}
