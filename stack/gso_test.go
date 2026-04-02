package stack

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/tcpip"
)

// gsoMemoryChannel is a MemoryChannel that also implements GSOWriter for testing.
type gsoMemoryChannel struct {
	*channel.MemoryChannel
	gsoCh chan gsoCapture
}

type gsoCapture struct {
	data []byte
	opts channel.PacketOptions
}

func newGSOMemoryChannel(mtu int) *gsoMemoryChannel {
	return &gsoMemoryChannel{
		MemoryChannel: channel.NewMemory(mtu),
		gsoCh:         make(chan gsoCapture, 16),
	}
}

func (g *gsoMemoryChannel) WritePacketGSO(data []byte, opts channel.PacketOptions) error {
	pkt := make([]byte, len(data))
	copy(pkt, data)
	g.gsoCh <- gsoCapture{data: pkt, opts: opts}
	return nil
}

func (g *gsoMemoryChannel) GSOEnabled() bool { return true }
func (g *gsoMemoryChannel) GSOMaxSize() int  { return 65535 - 40 }

func (g *gsoMemoryChannel) readGSO(timeout time.Duration) *gsoCapture {
	select {
	case c := <-g.gsoCh:
		return &c
	case <-time.After(timeout):
		return nil
	}
}

func TestWriteLoopDispatchesGSOItem(t *testing.T) {
	gch := newGSOMemoryChannel(1500)
	s := New(gch)
	s.Start()
	defer s.Stop()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(10, 0, 0, 2)

	// Send a GSO packet via SendPacketGSO.
	buf := packet.GetGSOBuf()
	ipHdrSize := header.IPv4MinHeaderSize
	tcpHdrSize := header.TCPMinHeaderSize
	dataSize := 5000
	totalLen := ipHdrSize + tcpHdrSize + dataSize

	// Fill TCP header area with a minimal header.
	tcpBuf := buf[ipHdrSize : ipHdrSize+tcpHdrSize]
	hdr := header.TCP(tcpBuf)
	hdr.Encode(&header.TCPFields{
		SrcPort:    80,
		DstPort:    12345,
		SeqNum:     100,
		AckNum:     200,
		DataOffset: uint8(tcpHdrSize / 4),
		Flags:      header.TCPFlagACK,
		WindowSize: 65535,
	})

	// Fill payload.
	for i := 0; i < dataSize; i++ {
		buf[ipHdrSize+tcpHdrSize+i] = byte(i % 256)
	}

	opts := channel.PacketOptions{
		GSOType:    channel.GSOTCPv4,
		GSOSize:    1460,
		HdrLen:     uint16(ipHdrSize + tcpHdrSize),
		CsumStart:  uint16(ipHdrSize),
		CsumOffset: 16,
	}

	s.SendPacketGSO(buf, 0, totalLen, src, dst, tcpip.TCPProtocolNumber, opts)

	cap := gch.readGSO(time.Second)
	if cap == nil {
		t.Fatal("expected GSO packet, got nil")
	}

	// Verify the GSO options were passed through.
	if cap.opts.GSOType != channel.GSOTCPv4 {
		t.Errorf("GSOType = 0x%02x, want 0x%02x", cap.opts.GSOType, channel.GSOTCPv4)
	}
	if cap.opts.GSOSize != 1460 {
		t.Errorf("GSOSize = %d, want 1460", cap.opts.GSOSize)
	}

	// Verify the packet has an IP header.
	if len(cap.data) != totalLen {
		t.Fatalf("packet len = %d, want %d", len(cap.data), totalLen)
	}
	ip := header.IPv4(cap.data)
	if ip.SourceAddress() != src {
		t.Errorf("src = %s, want %s", ip.SourceAddress(), src)
	}
	if ip.TotalLength() != uint16(totalLen) {
		t.Errorf("total length = %d, want %d", ip.TotalLength(), totalLen)
	}
}

func TestWriteLoopDispatchesNormalViaGSOWriter(t *testing.T) {
	gch := newGSOMemoryChannel(1500)
	s := New(gch)
	s.Start()
	defer s.Stop()

	// Send a normal packet — should go through WritePacketGSO with zero opts.
	pb := packet.NewPacketBuffer(header.IPv4MinHeaderSize)
	payload := []byte("hello")
	pb.Data = pb.Buf()[:len(payload)]
	copy(pb.Data, payload)

	s.SendPacket(pb, tcpip.From4(1, 1, 1, 1), tcpip.From4(2, 2, 2, 2), tcpip.UDPProtocolNumber)

	cap := gch.readGSO(time.Second)
	if cap == nil {
		t.Fatal("expected normal packet via GSO writer, got nil")
	}

	// Normal packets should have zero GSOType.
	if cap.opts.GSOType != channel.GSONone {
		t.Errorf("GSOType = 0x%02x, want 0x%02x (GSONone)", cap.opts.GSOType, channel.GSONone)
	}
}

func TestWriteLoopNonGSOChannel(t *testing.T) {
	// MemoryChannel does not implement GSOWriter.
	ch := channel.NewMemory(1500)
	s := New(ch)
	s.Start()
	defer s.Stop()

	pb := packet.NewPacketBuffer(header.IPv4MinHeaderSize)
	payload := []byte("test")
	pb.Data = pb.Buf()[:len(payload)]
	copy(pb.Data, payload)

	s.SendPacket(pb, tcpip.From4(1, 1, 1, 1), tcpip.From4(2, 2, 2, 2), tcpip.UDPProtocolNumber)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected packet via WritePacket, got nil")
	}
}

func TestChannelAccessor(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := New(ch)
	if s.Channel() != ch {
		t.Error("Channel() should return the underlying channel")
	}
}
