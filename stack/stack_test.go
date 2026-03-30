package stack

import (
	"encoding/binary"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/tcpip"
)

// buildICMPEchoRequest constructs a complete IPv4+ICMP echo request packet.
func buildICMPEchoRequest(src, dst tcpip.Address, ident, seq uint16) []byte {
	icmpLen := header.ICMPv4HeaderSize
	totalLen := header.IPv4MinHeaderSize + icmpLen
	buf := make([]byte, totalLen)

	// IPv4 header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    tcpip.ICMPv4ProtocolNumber,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(header.Checksum(buf[:header.IPv4MinHeaderSize], 0))

	// ICMP header.
	icmp := header.ICMPv4(buf[header.IPv4MinHeaderSize:])
	icmp.Encode(&header.ICMPv4Fields{
		Type:     header.ICMPv4Echo,
		Code:     0,
		Ident:    ident,
		Sequence: seq,
	})
	icmp.SetChecksum(0)
	icmp.SetChecksum(header.Checksum(buf[header.IPv4MinHeaderSize:], 0))

	return buf
}

// buildIPv4Packet constructs a minimal valid IPv4 packet with the given protocol and payload.
func buildIPv4Packet(src, dst tcpip.Address, proto tcpip.TransportProtocolNumber, payload []byte) []byte {
	totalLen := header.IPv4MinHeaderSize + len(payload)
	buf := make([]byte, totalLen)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    proto,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(header.Checksum(buf[:header.IPv4MinHeaderSize], 0))

	copy(buf[header.IPv4MinHeaderSize:], payload)
	return buf
}

func TestICMPEchoReply(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := New(ch)
	s.Start()
	defer s.Stop()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(10, 0, 0, 2)

	pkt := buildICMPEchoRequest(src, dst, 0x1234, 1)
	ch.Inject(pkt)

	reply := ch.Read(time.Second)
	if reply == nil {
		t.Fatal("expected ICMP echo reply, got nil")
	}

	// Parse reply.
	if len(reply) < header.IPv4MinHeaderSize+header.ICMPv4HeaderSize {
		t.Fatalf("reply too short: %d bytes", len(reply))
	}

	ip := header.IPv4(reply)

	// Verify addresses are swapped.
	if ip.SourceAddress() != dst {
		t.Errorf("reply src = %s, want %s", ip.SourceAddress(), dst)
	}
	if ip.DestinationAddress() != src {
		t.Errorf("reply dst = %s, want %s", ip.DestinationAddress(), src)
	}

	// Verify IP checksum.
	hdrLen := ip.HeaderLength()
	if header.Checksum(reply[:hdrLen], 0) != 0 {
		t.Error("reply IP checksum invalid")
	}

	// Verify ICMP.
	icmp := header.ICMPv4(reply[hdrLen:])
	if icmp.Type() != header.ICMPv4EchoReply {
		t.Errorf("ICMP type = %d, want %d (EchoReply)", icmp.Type(), header.ICMPv4EchoReply)
	}
	if icmp.Ident() != 0x1234 {
		t.Errorf("ICMP ident = 0x%04x, want 0x1234", icmp.Ident())
	}
	if icmp.Sequence() != 1 {
		t.Errorf("ICMP seq = %d, want 1", icmp.Sequence())
	}

	// Verify ICMP checksum.
	if header.Checksum(reply[hdrLen:], 0) != 0 {
		t.Error("reply ICMP checksum invalid")
	}
}

func TestStackLifecycle(t *testing.T) {
	// Get baseline goroutine count.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	ch := channel.NewMemory(1500)
	s := New(ch)
	s.Start()

	// Stack should have spawned goroutines.
	time.Sleep(50 * time.Millisecond)
	during := runtime.NumGoroutine()
	if during <= before {
		t.Error("Start() should spawn goroutines")
	}

	s.Stop()

	// Allow goroutines to exit.
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()

	// Allow some tolerance (other test goroutines may exist).
	if after > before+1 {
		t.Errorf("goroutine leak: before=%d, after=%d", before, after)
	}
}

func TestMalformedPacketsDropped(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := New(ch)
	s.Start()
	defer s.Stop()

	// Packet too short.
	ch.Inject([]byte{0x45, 0x00})

	// Packet with bad checksum.
	badPkt := buildICMPEchoRequest(tcpip.From4(1, 1, 1, 1), tcpip.From4(2, 2, 2, 2), 1, 1)
	badPkt[10] ^= 0xFF // corrupt IP checksum
	ch.Inject(badPkt)

	// Packet with invalid IHL (IHL=1, less than minimum).
	shortHdr := make([]byte, 20)
	shortHdr[0] = 0x41 // version=4, IHL=1 (4 bytes, less than minimum 20)
	ch.Inject(shortHdr)

	// Now send a valid ICMP echo to prove the stack is still alive.
	validPkt := buildICMPEchoRequest(tcpip.From4(10, 0, 0, 1), tcpip.From4(10, 0, 0, 2), 0xAAAA, 99)
	ch.Inject(validPkt)

	reply := ch.Read(time.Second)
	if reply == nil {
		t.Fatal("stack should still process valid packets after malformed ones")
	}

	icmp := header.ICMPv4(reply[header.IPv4(reply).HeaderLength():])
	if icmp.Ident() != 0xAAAA {
		t.Errorf("expected ident 0xAAAA, got 0x%04x", icmp.Ident())
	}

	// Verify no extra packets leaked out from malformed ones.
	extra := ch.Read(100 * time.Millisecond)
	if extra != nil {
		t.Error("malformed packets should have been dropped silently")
	}
}

// mockHandler is a test TransportHandler that records received packets.
type mockHandler struct {
	mu      sync.Mutex
	packets []*packet.PacketBuffer
	ch      chan struct{} // signals when a packet is received
}

func newMockHandler() *mockHandler {
	return &mockHandler{ch: make(chan struct{}, 16)}
}

func (m *mockHandler) HandlePacket(pb *packet.PacketBuffer) {
	m.mu.Lock()
	m.packets = append(m.packets, pb)
	m.mu.Unlock()
	m.ch <- struct{}{}
}

func (m *mockHandler) waitPacket(timeout time.Duration) bool {
	select {
	case <-m.ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (m *mockHandler) getPackets() []*packet.PacketBuffer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.packets
}

func TestTransportHandlerDispatch(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := New(ch)

	handler := newMockHandler()
	s.RegisterHandler(tcpip.TCPProtocolNumber, handler)
	s.Start()
	defer s.Stop()

	// Build a minimal TCP packet (20-byte TCP header, no payload).
	tcpHdr := make([]byte, header.TCPMinHeaderSize)
	tcp := header.TCP(tcpHdr)
	tcp.Encode(&header.TCPFields{
		SrcPort:    12345,
		DstPort:    80,
		SeqNum:     1,
		DataOffset: 5,
		Flags:      header.TCPFlagSYN,
		WindowSize: 65535,
	})

	pkt := buildIPv4Packet(tcpip.From4(10, 0, 0, 1), tcpip.From4(10, 0, 0, 2), tcpip.TCPProtocolNumber, tcpHdr)
	ch.Inject(pkt)

	if !handler.waitPacket(time.Second) {
		t.Fatal("handler did not receive dispatched packet")
	}

	pkts := handler.getPackets()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}

	pb := pkts[0]
	defer pb.Release()

	// Verify NetworkHeader is the IPv4 header.
	if len(pb.NetworkHeader) != header.IPv4MinHeaderSize {
		t.Errorf("NetworkHeader len = %d, want %d", len(pb.NetworkHeader), header.IPv4MinHeaderSize)
	}

	// Verify Data contains the TCP segment.
	if len(pb.Data) != header.TCPMinHeaderSize {
		t.Errorf("Data len = %d, want %d", len(pb.Data), header.TCPMinHeaderSize)
	}

	// Verify TCP source port from the dispatched data.
	dispatchedTCP := header.TCP(pb.Data)
	if dispatchedTCP.SourcePort() != 12345 {
		t.Errorf("TCP SrcPort = %d, want 12345", dispatchedTCP.SourcePort())
	}
}

func TestSendPacket(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := New(ch)
	s.Start()
	defer s.Stop()

	src := tcpip.From4(10, 0, 0, 2)
	dst := tcpip.From4(10, 0, 0, 1)

	// Build a UDP payload.
	udpData := make([]byte, header.UDPHeaderSize+5)
	udp := header.UDP(udpData)
	udp.Encode(&header.UDPFields{
		SrcPort: 5678,
		DstPort: 53,
		Length:  uint16(len(udpData)),
	})
	copy(udpData[header.UDPHeaderSize:], "hello")

	pb := packet.NewPacketBuffer(header.IPv4MinHeaderSize)
	pb.Data = pb.Buf()[:len(udpData)]
	copy(pb.Data, udpData)

	s.SendPacket(pb, src, dst, tcpip.UDPProtocolNumber)

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected outbound packet, got nil")
	}

	// Verify IPv4 header.
	ip := header.IPv4(raw)
	if ip.SourceAddress() != src {
		t.Errorf("src = %s, want %s", ip.SourceAddress(), src)
	}
	if ip.DestinationAddress() != dst {
		t.Errorf("dst = %s, want %s", ip.DestinationAddress(), dst)
	}
	if ip.Protocol() != tcpip.UDPProtocolNumber {
		t.Errorf("proto = %d, want %d", ip.Protocol(), tcpip.UDPProtocolNumber)
	}
	if ip.TotalLength() != uint16(len(raw)) {
		t.Errorf("total length = %d, want %d", ip.TotalLength(), len(raw))
	}

	// Verify IP checksum.
	hdrLen := ip.HeaderLength()
	if header.Checksum(raw[:hdrLen], 0) != 0 {
		t.Error("IP checksum invalid")
	}

	// Verify UDP payload.
	payload := raw[hdrLen:]
	gotUDP := header.UDP(payload)
	if gotUDP.SourcePort() != 5678 {
		t.Errorf("UDP src port = %d, want 5678", gotUDP.SourcePort())
	}
	if binary.BigEndian.Uint16(payload[header.UDPHeaderSize:header.UDPHeaderSize+2]) != uint16('h')<<8|uint16('e') {
		t.Error("UDP payload mismatch")
	}
}
