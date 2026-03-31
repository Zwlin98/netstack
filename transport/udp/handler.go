// Package udp implements a UDPHandler that provides a PacketConn-style API
// for reading and writing UDP datagrams through the network stack.
package udp

import (
	"errors"
	"sync"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
)

const inboundQueueSize = 256

var errClosed = errors.New("udp: handler closed")

// udpDatagram is an inbound UDP datagram queued for ReadFrom.
type udpDatagram struct {
	payload []byte
	src     tcpip.FullAddress
	dst     tcpip.FullAddress
}

// UDPHandler implements stack.TransportHandler for UDP.
// It provides a PacketConn-style ReadFrom/WriteTo API — the handler only
// parses and builds protocol headers, it does not maintain flow state or NAT.
type UDPHandler struct {
	stk     *stack.Stack
	inbound chan udpDatagram
	done    chan struct{}
	once    sync.Once
}

// NewUDPHandler creates a UDPHandler.
func NewUDPHandler(s *stack.Stack) *UDPHandler {
	return &UDPHandler{
		stk:     s,
		inbound: make(chan udpDatagram, inboundQueueSize),
		done:    make(chan struct{}),
	}
}

// HandlePacket processes an inbound UDP packet from the stack.
func (h *UDPHandler) HandlePacket(pb *packet.PacketBuffer) {
	defer pb.Release()

	if len(pb.Data) < header.UDPHeaderSize {
		return
	}

	ipHdr := header.IPv4(pb.NetworkHeader)
	udpHdr := header.UDP(pb.Data[:header.UDPHeaderSize])
	payload := pb.Data[header.UDPHeaderSize:]

	// Copy payload — PacketBuffer is released after this function returns.
	buf := make([]byte, len(payload))
	copy(buf, payload)

	dg := udpDatagram{
		payload: buf,
		src: tcpip.FullAddress{
			Addr: ipHdr.SourceAddress(),
			Port: udpHdr.SourcePort(),
		},
		dst: tcpip.FullAddress{
			Addr: ipHdr.DestinationAddress(),
			Port: udpHdr.DestinationPort(),
		},
	}

	// Non-blocking enqueue; drop if full (UDP semantics).
	select {
	case h.inbound <- dg:
	default:
	}
}

// ReadFrom reads the next inbound UDP datagram. It blocks until a datagram
// arrives or the handler is closed. Returns the payload length copied into b,
// the source (client) address, and the original destination address.
// If b is smaller than the datagram payload, the excess bytes are discarded.
func (h *UDPHandler) ReadFrom(b []byte) (n int, src, dst tcpip.FullAddress, err error) {
	select {
	case dg := <-h.inbound:
		n = copy(b, dg.payload)
		return n, dg.src, dg.dst, nil
	case <-h.done:
		return 0, tcpip.FullAddress{}, tcpip.FullAddress{}, errClosed
	}
}

// WriteTo sends a UDP datagram back through the stack. b is the pure payload
// (no headers). src is the source address for the outgoing packet, dst is the
// destination address. The handler builds UDP and IPv4 headers automatically.
func (h *UDPHandler) WriteTo(b []byte, src, dst tcpip.FullAddress) (int, error) {
	select {
	case <-h.done:
		return 0, errClosed
	default:
	}

	headroom := header.IPv4MinHeaderSize + header.UDPHeaderSize
	pb := packet.NewPacketBuffer(headroom)

	// Write payload.
	pb.Data = pb.Buf()[:len(b)]
	copy(pb.Data, b)

	// Prepend UDP header.
	udpTotalLen := uint16(header.UDPHeaderSize + len(b))
	udpSlice := pb.Prepend(header.UDPHeaderSize)
	udpHdr := header.UDP(udpSlice)
	udpHdr.Encode(&header.UDPFields{
		SrcPort: src.Port,
		DstPort: dst.Port,
		Length:  udpTotalLen,
	})

	// Compute UDP checksum with pseudo-header.
	udpHdr.SetChecksum(0)
	fullUDP := pb.AsSlice()
	phc := header.PseudoHeaderChecksum(
		tcpip.UDPProtocolNumber,
		src.Addr, dst.Addr,
		udpTotalLen,
	)
	udpHdr.SetChecksum(header.Checksum(fullUDP, phc))

	h.stk.SendPacket(pb, src.Addr, dst.Addr, tcpip.UDPProtocolNumber)
	return len(b), nil
}

// Close shuts down the handler. Blocked ReadFrom calls return immediately
// with an error. Close is idempotent.
func (h *UDPHandler) Close() {
	h.once.Do(func() {
		close(h.done)
	})
}
