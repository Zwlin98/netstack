package udp

import (
	"testing"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
)

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

func TestReadFromReceivesLargeReassembledIPv4Datagram(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := stack.New(ch)
	h := NewUDPHandler(s)
	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()
	defer s.Stop()
	defer h.Close()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(30, 1, 2, 3)
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(255 - i)
	}
	udpPacket := buildUDPDatagram(12345, 443, src, dst, payload)

	const fragPayloadLen = 1480
	for offset := 0; offset < len(udpPacket); offset += fragPayloadLen {
		end := offset + fragPayloadLen
		if end > len(udpPacket) {
			end = len(udpPacket)
		}
		ch.Inject(buildIPv4Fragment(src, dst, 0x5757, tcpip.UDPProtocolNumber, offset, end < len(udpPacket), udpPacket[offset:end]))
	}

	got := make([]byte, len(payload))
	n, gotSrc, gotDst, err := h.ReadFrom(got)
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if n != len(payload) || string(got[:n]) != string(payload) {
		t.Fatalf("UDP payload mismatch: got %d bytes want %d", n, len(payload))
	}
	if gotSrc.Addr != src || gotSrc.Port != 12345 {
		t.Fatalf("bad source: got %+v", gotSrc)
	}
	if gotDst.Addr != dst || gotDst.Port != 443 {
		t.Fatalf("bad destination: got %+v", gotDst)
	}
}
