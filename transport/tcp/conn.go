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

// Close shuts down the connection.
func (c *TCPConn) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
	})
	c.handler.removeConn(c.flow)
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
	tcpHdr := header.TCP(pb.Data)
	flags := tcpHdr.Flags()

	switch c.state {
	case stateSynRcvd:
		if flags.Has(header.TCPFlagACK) {
			c.state = stateEstablished
			select {
			case c.handler.listener.acceptCh <- c:
			case <-c.done:
			}
		}

	case stateEstablished:
		if flags.Has(header.TCPFlagRST) {
			c.state = stateClosed
			c.closeOnce.Do(func() {
				close(c.done)
			})
		}
	}
}

func (c *TCPConn) cleanup() {
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
