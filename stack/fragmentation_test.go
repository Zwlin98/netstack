package stack

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/tcpip"
)

type captureHandler struct {
	ch chan []byte
}

func (h *captureHandler) HandlePacket(pb *packet.PacketBuffer) {
	defer pb.Release()
	data := make([]byte, len(pb.Data))
	copy(data, pb.Data)
	h.ch <- data
}

func buildIPv4Fragment(src, dst tcpip.Address, id uint16, proto tcpip.TransportProtocolNumber, offset int, more bool, payload []byte) []byte {
	totalLen := header.IPv4MinHeaderSize + len(payload)
	buf := make([]byte, totalLen)

	flags := uint8(0)
	if more {
		flags |= header.IPv4FlagMoreFragments
	}

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength:    uint16(totalLen),
		ID:             id,
		Flags:          flags,
		FragmentOffset: uint16(offset / 8),
		TTL:            64,
		Protocol:       proto,
		SrcAddr:        src,
		DstAddr:        dst,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(header.Checksum(buf[:header.IPv4MinHeaderSize], 0))

	copy(buf[header.IPv4MinHeaderSize:], payload)
	return buf
}

func buildUDPDatagram(srcPort, dstPort uint16, src, dst tcpip.Address, payload []byte) []byte {
	buf := make([]byte, header.UDPHeaderSize+len(payload))
	udp := header.UDP(buf[:header.UDPHeaderSize])
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(len(buf)),
	})
	copy(buf[header.UDPHeaderSize:], payload)
	udp.SetChecksum(0)
	udp.SetChecksum(header.Checksum(buf, header.PseudoHeaderChecksum(tcpip.UDPProtocolNumber, src, dst, uint16(len(buf)))))
	return buf
}

func TestIPv4FragmentReassemblyOutOfOrder(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := New(ch)
	h := &captureHandler{ch: make(chan []byte, 1)}
	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()
	defer s.Stop()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(30, 1, 2, 3)
	payload := make([]byte, 2000)
	for i := range payload {
		payload[i] = byte(i)
	}
	udp := buildUDPDatagram(12345, 443, src, dst, payload)

	firstLen := 1480
	first := buildIPv4Fragment(src, dst, 0x4444, tcpip.UDPProtocolNumber, 0, true, udp[:firstLen])
	second := buildIPv4Fragment(src, dst, 0x4444, tcpip.UDPProtocolNumber, firstLen, false, udp[firstLen:])

	ch.Inject(second)
	ch.Inject(first)

	select {
	case got := <-h.ch:
		if string(got) != string(udp) {
			t.Fatalf("reassembled payload mismatch: got %d bytes want %d", len(got), len(udp))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reassembled datagram")
	}
}

func TestIPv4FragmentReassemblyDropsOverlap(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := New(ch)
	h := &captureHandler{ch: make(chan []byte, 1)}
	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()
	defer s.Stop()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(30, 1, 2, 3)
	payload := make([]byte, 2000)
	udp := buildUDPDatagram(12345, 443, src, dst, payload)

	first := buildIPv4Fragment(src, dst, 0x5555, tcpip.UDPProtocolNumber, 0, true, udp[:1480])
	overlap := buildIPv4Fragment(src, dst, 0x5555, tcpip.UDPProtocolNumber, 8, true, udp[8:1488])
	final := buildIPv4Fragment(src, dst, 0x5555, tcpip.UDPProtocolNumber, 1480, false, udp[1480:])

	ch.Inject(first)
	ch.Inject(overlap)
	ch.Inject(final)

	select {
	case got := <-h.ch:
		t.Fatalf("unexpected reassembled datagram after overlap: %d bytes", len(got))
	case <-time.After(100 * time.Millisecond):
	}
}

func TestIPv4TotalLengthTrimsTrailingBytes(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	pkt := buildIPv4Packet(tcpip.From4(1, 1, 1, 1), tcpip.From4(2, 2, 2, 2), tcpip.TransportProtocolNumber(99), payload)
	pkt = append(pkt, 9, 9, 9)
	if total := binary.BigEndian.Uint16(pkt[2:4]); int(total) != header.IPv4MinHeaderSize+len(payload) {
		t.Fatalf("bad test packet total length: %d", total)
	}

	ch := channel.NewMemory(1500)
	s := New(ch)
	h := &captureHandler{ch: make(chan []byte, 1)}
	s.RegisterHandler(tcpip.TransportProtocolNumber(99), h)
	s.Start()
	defer s.Stop()

	ch.Inject(pkt)

	select {
	case got := <-h.ch:
		if string(got) != string(payload) {
			t.Fatalf("payload was not trimmed to IPv4 total length: got %v want %v", got, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for packet")
	}
}
