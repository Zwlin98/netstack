package tcp

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/tcpip"
)

// TCPConn represents a single TCP connection.
type TCPConn struct {
	flow    FlowID
	handler *TCPHandler

	state tcpState

	iss uint32 // our initial sequence number
	irs uint32 // peer's initial sequence number

	inbound chan *packet.PacketBuffer

	done      chan struct{}
	closeOnce sync.Once
}

// OriginalDst returns the original destination address of the connection.
func (c *TCPConn) OriginalDst() tcpip.FullAddress {
	return tcpip.FullAddress{Addr: c.flow.DstAddr, Port: c.flow.DstPort}
}

func (c *TCPConn) closeDone() {
	c.closeOnce.Do(func() { close(c.done) })
}

// Close shuts down the connection, sending RST to the remote peer.
func (c *TCPConn) Close() {
	if c.state == stateEstablished {
		c.sendRSTSegment(c.iss + 1)
	}
	c.closeDone()
	c.handler.removeConn(c.flow)
}

func (c *TCPConn) handleRST() {
	c.state = stateClosed
	c.closeDone()
}

func (c *TCPConn) run() {
	defer c.cleanup()

	for {
		select {
		case pb := <-c.inbound:
			c.handleSegment(pb)
			pb.Release()
		case <-c.done:
			return
		}
	}
}

func (c *TCPConn) handleSegment(pb *packet.PacketBuffer) {
	seg := parseSeg(pb)

	// Common: RST handling applies to all states.
	if seg.flags.Has(header.TCPFlagRST) {
		c.handleRST()
		return
	}

	// Common: unexpected SYN in non-SYN_RCVD state → challenge ACK.
	if seg.flags.Has(header.TCPFlagSYN) && c.state != stateSynRcvd {
		c.sendACK()
		return
	}

	switch c.state {
	case stateSynRcvd:
		c.handleSynRcvd(seg)
	case stateEstablished:
		c.handleEstablished(seg)
	}
}

func (c *TCPConn) cleanup() {
	c.handler.removeConn(c.flow)
	for {
		select {
		case pb := <-c.inbound:
			pb.Release()
		default:
			return
		}
	}
}

func generateISN() uint32 {
	var buf [4]byte
	rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}
