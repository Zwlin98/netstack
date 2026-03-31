package tcp

import "github.com/Zwlin98/netstack/header"

// sender tracks the send side of a TCP connection.
type sender struct {
	iss uint32 // initial send sequence number
	nxt uint32 // next sequence to send (SND.NXT)
	una uint32 // oldest unacknowledged (SND.UNA)
	wnd uint16 // peer's advertised receive window (SND.WND)
	mss int    // maximum segment size, derived from MTU
}

func newSender(iss uint32, peerWnd uint16, mtu int) *sender {
	mss := mtu - header.IPv4MinHeaderSize - header.TCPMinHeaderSize
	if mss <= 0 {
		mss = 536 // RFC 879 default
	}
	return &sender{
		iss: iss,
		nxt: iss + 1, // SYN consumed one sequence number
		una: iss + 1,
		wnd: peerWnd,
		mss: mss,
	}
}

// sendPending sends as many segments as the peer window allows.
func (s *sender) sendPending(conn *TCPConn) {
	for {
		// How much can we send?
		windowLeft := int(s.wnd) - int(s.nxt-s.una)
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
		s.nxt += uint32(n)
	}
}

// handleACK processes an incoming ACK number.
func (s *sender) handleACK(ack uint32) {
	if seqGreaterThan(ack, s.una) && !seqGreaterThan(ack, s.nxt) {
		s.una = ack
	}
}
