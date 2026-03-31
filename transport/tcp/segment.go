package tcp

import (
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/tcpip"
)

// segment holds pre-parsed fields from an incoming TCP segment.
type segment struct {
	flags   header.TCPFlags
	seq     uint32
	ack     uint32
	wnd     uint16
	payload []byte
}

func parseSeg(pb *packet.PacketBuffer) segment {
	tcpHdr := header.TCP(pb.Data)
	dataOffset := int(tcpHdr.DataOffset())
	var payload []byte
	if dataOffset < len(pb.Data) {
		payload = pb.Data[dataOffset:]
	}
	return segment{
		flags:   tcpHdr.Flags(),
		seq:     tcpHdr.SequenceNumber(),
		ack:     tcpHdr.AckNumber(),
		wnd:     tcpHdr.WindowSize(),
		payload: payload,
	}
}

func setTCPChecksum(hdr header.TCP, src, dst tcpip.Address, tcpLen uint16) {
	hdr.SetChecksum(0)
	partial := header.PseudoHeaderChecksum(tcpip.TCPProtocolNumber, src, dst, tcpLen)
	hdr.SetChecksum(header.Checksum(hdr[:tcpLen], partial))
}

func (c *TCPConn) sendSYNACK() {
	pb := packet.NewPacketBuffer(packet.MaxHeadroom)
	tcpBuf := pb.Prepend(header.TCPMinHeaderSize)
	hdr := header.TCP(tcpBuf)
	hdr.Encode(&header.TCPFields{
		SrcPort:    c.flow.DstPort,
		DstPort:    c.flow.SrcPort,
		SeqNum:     c.iss,
		AckNum:     c.irs + 1,
		DataOffset: header.TCPMinHeaderSize / 4,
		Flags:      header.TCPFlagSYN | header.TCPFlagACK,
		WindowSize: 65535,
	})
	setTCPChecksum(hdr, c.flow.DstAddr, c.flow.SrcAddr, header.TCPMinHeaderSize)
	c.handler.stack.SendPacket(pb, c.flow.DstAddr, c.flow.SrcAddr, tcpip.TCPProtocolNumber)
}

func (c *TCPConn) sendACK() {
	pb := packet.NewPacketBuffer(packet.MaxHeadroom)
	tcpBuf := pb.Prepend(header.TCPMinHeaderSize)
	hdr := header.TCP(tcpBuf)
	hdr.Encode(&header.TCPFields{
		SrcPort:    c.flow.DstPort,
		DstPort:    c.flow.SrcPort,
		SeqNum:     c.iss + 1,
		AckNum:     c.irs + 1,
		DataOffset: header.TCPMinHeaderSize / 4,
		Flags:      header.TCPFlagACK,
		WindowSize: 65535,
	})
	setTCPChecksum(hdr, c.flow.DstAddr, c.flow.SrcAddr, header.TCPMinHeaderSize)
	c.handler.stack.SendPacket(pb, c.flow.DstAddr, c.flow.SrcAddr, tcpip.TCPProtocolNumber)
}

// sendRSTSegment sends a RST from a connection context with a specific SeqNum.
func (c *TCPConn) sendRSTSegment(seqNum uint32) {
	pb := packet.NewPacketBuffer(packet.MaxHeadroom)
	tcpBuf := pb.Prepend(header.TCPMinHeaderSize)
	hdr := header.TCP(tcpBuf)
	hdr.Encode(&header.TCPFields{
		SrcPort:    c.flow.DstPort,
		DstPort:    c.flow.SrcPort,
		SeqNum:     seqNum,
		DataOffset: header.TCPMinHeaderSize / 4,
		Flags:      header.TCPFlagRST,
		WindowSize: 0,
	})
	setTCPChecksum(hdr, c.flow.DstAddr, c.flow.SrcAddr, header.TCPMinHeaderSize)
	c.handler.stack.SendPacket(pb, c.flow.DstAddr, c.flow.SrcAddr, tcpip.TCPProtocolNumber)
}

// sendRST sends a RST in response to an unexpected segment.
func (h *TCPHandler) sendRST(pb *packet.PacketBuffer) {
	ipHdr := header.IPv4(pb.NetworkHeader)
	tcpHdr := header.TCP(pb.Data)

	srcAddr := ipHdr.DestinationAddress()
	dstAddr := ipHdr.SourceAddress()

	var seqNum, ackNum uint32
	var flags header.TCPFlags

	if tcpHdr.Flags().Has(header.TCPFlagACK) {
		seqNum = tcpHdr.AckNumber()
		flags = header.TCPFlagRST
	} else {
		seqNum = 0
		segLen := uint32(len(pb.Data)) - uint32(tcpHdr.DataOffset())
		if tcpHdr.Flags().Has(header.TCPFlagSYN) {
			segLen++
		}
		ackNum = tcpHdr.SequenceNumber() + segLen
		flags = header.TCPFlagRST | header.TCPFlagACK
	}

	rstPB := packet.NewPacketBuffer(packet.MaxHeadroom)
	tcpBuf := rstPB.Prepend(header.TCPMinHeaderSize)
	hdr := header.TCP(tcpBuf)
	hdr.Encode(&header.TCPFields{
		SrcPort:    tcpHdr.DestinationPort(),
		DstPort:    tcpHdr.SourcePort(),
		SeqNum:     seqNum,
		AckNum:     ackNum,
		DataOffset: header.TCPMinHeaderSize / 4,
		Flags:      flags,
		WindowSize: 0,
	})
	setTCPChecksum(hdr, srcAddr, dstAddr, header.TCPMinHeaderSize)
	h.stack.SendPacket(rstPB, srcAddr, dstAddr, tcpip.TCPProtocolNumber)
}
