package tcp

import "github.com/Zwlin98/netstack/header"

// receiver tracks the receive side of a TCP connection.
type receiver struct {
	irs uint32 // initial receive sequence number
	nxt uint32 // next expected sequence (RCV.NXT)

	// Out-of-order segments sorted by seq.
	ooo []oooSegment

	readBuf *ringBuffer
	conn    *TCPConn
}

type oooSegment struct {
	seq  uint32
	data []byte
}

func newReceiver(irs uint32, readBuf *ringBuffer, conn *TCPConn) *receiver {
	return &receiver{
		irs:     irs,
		nxt:     irs + 1, // SYN consumed one sequence number
		readBuf: readBuf,
		conn:    conn,
	}
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
			// Fully duplicate segment — ignore.
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
	return r.readBuf.WriteNoBlock(data)
}

func (r *receiver) insertOOO(seq uint32, data []byte) {
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
// Returns up to 3 blocks, most-recent-first. Adjacent/overlapping
// segments are coalesced into a single block.
func (r *receiver) sackBlocks() []header.SACKBlock {
	if len(r.ooo) == 0 {
		return nil
	}

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

	// Return up to 3 blocks, most-recent-first.
	n := min(len(ranges), 3)
	blocks := make([]header.SACKBlock, n)
	for i := range n {
		blocks[i] = ranges[len(ranges)-1-i]
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
