package tcp

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

// wnd returns the current receive window based on readBuf free space.
func (r *receiver) wnd() uint16 {
	free := r.readBuf.Free()
	if free > 0xFFFF {
		return 0xFFFF
	}
	return uint16(free)
}

// handleData processes incoming data at the given sequence number.
func (r *receiver) handleData(seq uint32, data []byte) {
	if len(data) == 0 {
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
