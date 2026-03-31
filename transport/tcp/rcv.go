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
func (r *receiver) handleData(seq uint32, data []byte) {
	if len(data) == 0 {
		return
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
		// In order: deliver to readBuf.
		r.deliver(data)
		r.nxt += uint32(len(data))
		// Drain any now-contiguous OOO segments.
		r.deliverOOO()
	} else if seqGreaterThan(seq, r.nxt) {
		// Future segment: buffer out-of-order.
		r.insertOOO(seq, data)
	}
	// seq < nxt: duplicate, ignore.
}

func (r *receiver) deliver(data []byte) {
	// Best effort: write into the read buffer.
	// If the buffer is full, data is dropped (sender will retransmit in P4c).
	r.readBuf.WriteNoBlock(data)
}

func (r *receiver) insertOOO(seq uint32, data []byte) {
	// Copy data since the packet buffer will be released.
	saved := make([]byte, len(data))
	copy(saved, data)

	seg := oooSegment{seq: seq, data: saved}

	// Insert sorted by seq.
	i := 0
	for i < len(r.ooo) && seqLessThan(r.ooo[i].seq, seq) {
		i++
	}
	// Duplicate check.
	if i < len(r.ooo) && r.ooo[i].seq == seq {
		return
	}
	r.ooo = append(r.ooo, oooSegment{})
	copy(r.ooo[i+1:], r.ooo[i:])
	r.ooo[i] = seg
}

// sackBlocks returns the current SACK blocks from the OOO buffer.
// Returns up to 3 blocks, most-recent-first.
func (r *receiver) sackBlocks() []header.SACKBlock {
	n := len(r.ooo)
	if n == 0 {
		return nil
	}
	if n > 3 {
		n = 3
	}
	blocks := make([]header.SACKBlock, n)
	// Most-recent-first (OOO is sorted by seq, so last entry is most recent).
	for i := range n {
		seg := r.ooo[len(r.ooo)-1-i]
		blocks[i] = header.SACKBlock{
			Start: seg.seq,
			End:   seg.seq + uint32(len(seg.data)),
		}
	}
	return blocks
}

func (r *receiver) deliverOOO() {
	for len(r.ooo) > 0 && r.ooo[0].seq == r.nxt {
		seg := r.ooo[0]
		r.deliver(seg.data)
		r.nxt += uint32(len(seg.data))
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
