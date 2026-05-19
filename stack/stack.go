package stack

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/tcpip"
)

const maxSupportedMTU = 1500

// TransportHandler receives dispatched packets from the network layer.
type TransportHandler interface {
	HandlePacket(pb *packet.PacketBuffer)
}

// outboundItem carries either a normal PacketBuffer or a GSO buffer through the outbound queue.
type outboundItem struct {
	pb         *packet.PacketBuffer  // non-nil for normal packets
	gsoBuf     []byte                // packet view for GSO writes
	gsoPoolBuf []byte                // original buffer to return to the GSO pool
	gsoOpts    channel.PacketOptions // meaningful when gsoBuf != nil
}

// Stack is the central network stack that reads packets from a Channel,
// processes IPv4, and dispatches to transport handlers.
type Stack struct {
	channel    channel.Channel
	outboundCh chan outboundItem

	handlers map[tcpip.TransportProtocolNumber]TransportHandler

	fragments *ipv4Reassembler
	ipv4ID    atomic.Uint32

	ttl uint8

	stats *Stats

	wg   sync.WaitGroup
	done chan struct{}
}

// New creates a new Stack using the given Channel.
// Panics if the channel's MTU exceeds 1500, which is the maximum supported
// by the internal packet buffer pools.
func New(ch channel.Channel, opts ...Option) *Stack {
	if mtu := ch.MTU(); mtu > maxSupportedMTU {
		panic(fmt.Sprintf("channel MTU %d exceeds maximum supported MTU %d", mtu, maxSupportedMTU))
	}
	cfg := defaultConfig
	for _, o := range opts {
		o(&cfg)
	}
	return &Stack{
		channel:    ch,
		outboundCh: make(chan outboundItem, cfg.OutboundQueueSize),
		handlers:   make(map[tcpip.TransportProtocolNumber]TransportHandler),
		fragments:  newIPv4Reassembler(),
		ttl:        cfg.TTL,
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

// Channel returns the underlying channel.Channel.
func (s *Stack) Channel() channel.Channel {
	return s.channel
}

// MTU returns the channel's maximum transmission unit.
func (s *Stack) MTU() int {
	return s.channel.MTU()
}

func (s *Stack) nextIPv4ID() uint16 {
	return uint16(s.ipv4ID.Add(1))
}

// SendPacket prepends an IPv4 header and enqueues the packet for sending.
func (s *Stack) SendPacket(pb *packet.PacketBuffer, src, dst tcpip.Address, proto tcpip.TransportProtocolNumber) {
	ipSlice := pb.Prepend(header.IPv4MinHeaderSize)
	totalLen := len(pb.AsSlice())
	if totalLen > 0xffff {
		if st := s.stats; st != nil {
			st.DroppedOutbound.Add(1)
		}
		pb.Release()
		return
	}

	ip := header.IPv4(ipSlice)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		ID:          s.nextIPv4ID(),
		TTL:         s.ttl,
		Protocol:    proto,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(header.Checksum(ipSlice, 0))

	pb.NetworkHeader = ipSlice

	select {
	case s.outboundCh <- outboundItem{pb: pb}:
	case <-s.done:
		pb.Release()
	}
}

// SendPacketGSO prepends an IPv4 header to the GSO buffer and enqueues it
// with PacketOptions for the write loop. The buffer must have at least
// header.IPv4MinHeaderSize bytes of headroom before the data at buf[ipOffset:].
func (s *Stack) SendPacketGSO(buf []byte, ipOffset int, totalLen int, src, dst tcpip.Address, proto tcpip.TransportProtocolNumber, opts channel.PacketOptions) {
	if totalLen > 0xffff {
		if st := s.stats; st != nil {
			st.DroppedOutbound.Add(1)
		}
		packet.PutGSOBuf(buf)
		return
	}

	ipSlice := buf[ipOffset : ipOffset+header.IPv4MinHeaderSize]
	ip := header.IPv4(ipSlice)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		ID:          s.nextIPv4ID(),
		TTL:         s.ttl,
		Protocol:    proto,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(header.Checksum(ipSlice, 0))

	pkt := buf[ipOffset : ipOffset+totalLen]
	select {
	case s.outboundCh <- outboundItem{gsoBuf: pkt, gsoPoolBuf: buf, gsoOpts: opts}:
	case <-s.done:
		packet.PutGSOBuf(buf)
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
		totalLen := int(ipHdr.TotalLength())
		if totalLen < hdrLen || totalLen > len(raw) {
			pb.Release()
			continue
		}
		raw = raw[:totalLen]
		ipHdr = header.IPv4(raw)

		// Validate IP header checksum.
		if header.Checksum(raw[:hdrLen], 0) != 0 {
			pb.Release()
			continue
		}

		if st := s.stats; st != nil {
			st.PacketsIn.Add(1)
			st.BytesIn.Add(uint64(totalLen))
		}

		pb.NetworkHeader = raw[:hdrLen]
		pb.Data = raw[hdrLen:]

		if ipHdr.More() || ipHdr.FragmentOffset() != 0 {
			complete, ok := s.fragments.process(pb, ipHdr)
			if !ok {
				continue
			}
			pb = complete
			ipHdr = header.IPv4(pb.NetworkHeader)
		}

		proto := ipHdr.Protocol()

		switch proto {
		case tcpip.ICMPv4ProtocolNumber:
			s.handleICMP(pb, ipHdr)
		default:
			if h, ok := s.handlers[proto]; ok {
				h.HandlePacket(pb)
			} else {
				if st := s.stats; st != nil {
					st.UnknownProtocol.Add(1)
				}
				pb.Release()
			}
		}
	}
}

func (s *Stack) writeLoop() {
	defer s.wg.Done()
	gw, gsoOK := s.channel.(channel.GSOWriter)
	for {
		select {
		case item := <-s.outboundCh:
			if item.gsoBuf != nil {
				s.writeGSOItem(item, gw, gsoOK)
				continue
			}
			s.writePacket(item.pb.AsSlice(), gw, gsoOK)
			item.pb.Release()
		case <-s.done:
			return
		}
	}
}

func (s *Stack) writeGSOItem(item outboundItem, gw channel.GSOWriter, gsoOK bool) {
	defer packet.PutGSOBuf(item.gsoPoolBuf)
	if !gsoOK {
		if st := s.stats; st != nil {
			st.DroppedOutbound.Add(1)
		}
		return
	}
	s.countPacketOut(len(item.gsoBuf))
	_ = gw.WritePacketGSO(item.gsoBuf, item.gsoOpts)
}

func (s *Stack) writePacket(data []byte, gw channel.GSOWriter, gsoOK bool) {
	mtu := s.channel.MTU()
	if mtu <= 0 || len(data) <= mtu {
		s.writeWirePacket(data, gw, gsoOK)
		return
	}

	fragments, ok := fragmentIPv4Packet(data, mtu)
	if !ok {
		if st := s.stats; st != nil {
			st.DroppedOutbound.Add(1)
		}
		return
	}
	for _, frag := range fragments {
		s.writeWirePacket(frag, gw, gsoOK)
	}
}

func (s *Stack) writeWirePacket(data []byte, gw channel.GSOWriter, gsoOK bool) {
	s.countPacketOut(len(data))
	if gsoOK {
		_ = gw.WritePacketGSO(data, channel.PacketOptions{})
		return
	}
	_ = s.channel.WritePacket(data)
}

func (s *Stack) countPacketOut(n int) {
	if st := s.stats; st != nil {
		st.PacketsOut.Add(1)
		st.BytesOut.Add(uint64(n))
	}
}
