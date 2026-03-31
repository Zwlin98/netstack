package stack

import (
	"sync"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/tcpip"
)

// TransportHandler receives dispatched packets from the network layer.
type TransportHandler interface {
	HandlePacket(pb *packet.PacketBuffer)
}

// Stack is the central network stack that reads packets from a Channel,
// processes IPv4, and dispatches to transport handlers.
type Stack struct {
	channel    channel.Channel
	outboundCh chan *packet.PacketBuffer

	handlers map[tcpip.TransportProtocolNumber]TransportHandler

	wg   sync.WaitGroup
	done chan struct{}
}

// New creates a new Stack using the given Channel.
func New(ch channel.Channel) *Stack {
	return &Stack{
		channel:    ch,
		outboundCh: make(chan *packet.PacketBuffer, 256),
		handlers:   make(map[tcpip.TransportProtocolNumber]TransportHandler),
		done:       make(chan struct{}),
	}
}

// RegisterHandler registers a transport protocol handler.
func (s *Stack) RegisterHandler(proto tcpip.TransportProtocolNumber, h TransportHandler) {
	s.handlers[proto] = h
}

// Start launches the read and write loop goroutines.
func (s *Stack) Start() {
	s.wg.Add(2)
	go s.readLoop()
	go s.writeLoop()
}

// Stop shuts down the stack, waiting for goroutines to exit.
func (s *Stack) Stop() {
	close(s.done)
	s.channel.Close()
	s.wg.Wait()
}

// MTU returns the channel's maximum transmission unit.
func (s *Stack) MTU() int {
	return s.channel.MTU()
}

// SendPacket prepends an IPv4 header and enqueues the packet for sending.
func (s *Stack) SendPacket(pb *packet.PacketBuffer, src, dst tcpip.Address, proto tcpip.TransportProtocolNumber) {
	ipSlice := pb.Prepend(header.IPv4MinHeaderSize)
	ip := header.IPv4(ipSlice)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pb.AsSlice())),
		TTL:         64,
		Protocol:    proto,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(header.Checksum(ipSlice, 0))

	pb.NetworkHeader = ipSlice

	select {
	case s.outboundCh <- pb:
	case <-s.done:
		pb.Release()
	}
}

func (s *Stack) readLoop() {
	defer s.wg.Done()
	for {
		pb := packet.NewPacketBuffer(0)
		n, err := s.channel.ReadPacket(pb.Buf())
		if err != nil {
			pb.Release()
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		raw := pb.Buf()[:n]

		// Validate minimum length.
		if len(raw) < header.IPv4MinHeaderSize {
			pb.Release()
			continue
		}

		ipHdr := header.IPv4(raw)
		hdrLen := ipHdr.HeaderLength()
		if hdrLen < header.IPv4MinHeaderSize || hdrLen > len(raw) {
			pb.Release()
			continue
		}

		// Validate IP header checksum.
		if header.Checksum(raw[:hdrLen], 0) != 0 {
			pb.Release()
			continue
		}

		pb.NetworkHeader = raw[:hdrLen]
		pb.Data = raw[hdrLen:]

		proto := ipHdr.Protocol()

		switch proto {
		case tcpip.ICMPv4ProtocolNumber:
			s.handleICMP(pb, ipHdr)
		default:
			if h, ok := s.handlers[proto]; ok {
				h.HandlePacket(pb)
			} else {
				pb.Release()
			}
		}
	}
}

func (s *Stack) writeLoop() {
	defer s.wg.Done()
	for {
		select {
		case pb := <-s.outboundCh:
			s.channel.WritePacket(pb.AsSlice())
			pb.Release()
		case <-s.done:
			return
		}
	}
}
