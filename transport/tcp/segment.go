package tcp

import (
	"github.com/Zwlin98/netstack/channel"
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
	options []byte // raw TCP options bytes
	payload []byte

	// Timestamp fields (populated by handleSegment when tsEnabled).
	tsVal  uint32
	tsEcr  uint32
	hasTS  bool
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
		options: tcpHdr.Options(),
		payload: payload,
	}
}

func setTCPChecksum(hdr header.TCP, src, dst tcpip.Address, tcpLen uint16) {
	hdr.SetChecksum(0)
	partial := header.PseudoHeaderChecksum(tcpip.TCPProtocolNumber, src, dst, tcpLen)
	hdr.SetChecksum(header.Checksum(hdr[:tcpLen], partial))
}

// setTCPPartialChecksum writes only the pseudo-header checksum into the TCP
// checksum field. Used for GSO segments where the kernel completes the
// per-segment checksum after splitting.
func setTCPPartialChecksum(hdr header.TCP, src, dst tcpip.Address, tcpLen uint16) {
	partial := header.PseudoHeaderChecksum(tcpip.TCPProtocolNumber, src, dst, tcpLen)
	hdr.SetChecksum(partial)
}

func (c *TCPConn) sendSYNACK() {
	// Build options: MSS + NOP + WS + SACK-Permitted + Timestamp (if negotiated).
	var optBuf [24]byte // max: 4(MSS) + 1(NOP) + 3(WS) + 2(SACK) + 12(TS) + padding = 24
	optLen := 0
	mss := uint16(c.handler.stack.MTU() - header.IPv4MinHeaderSize - header.TCPMinHeaderSize)
	optLen += header.EncodeMSSOption(optBuf[optLen:], mss)
	if c.rcvWndScale > 0 {
		optBuf[optLen] = header.TCPOptionNOP
		optLen++
		optLen += header.EncodeWSOption(optBuf[optLen:], int(c.rcvWndScale))
	}
	if c.sackPermitted {
		optLen += header.EncodeSACKPermittedOption(optBuf[optLen:])
	}
	if c.tsEnabled {
		optLen += header.EncodeTimestampOption(optBuf[optLen:], c.handler.now(), c.tsRecent)
	}
	// Pad to 4-byte alignment.
	for optLen%4 != 0 {
		optBuf[optLen] = header.TCPOptionNOP
		optLen++
	}

	hdrSize := header.TCPMinHeaderSize + optLen
	pb := packet.NewPacketBuffer(packet.MaxHeadroom)
	tcpBuf := pb.Prepend(hdrSize)
	hdr := header.TCP(tcpBuf)
	hdr.Encode(&header.TCPFields{
		SrcPort:    c.flow.DstPort,
		DstPort:    c.flow.SrcPort,
		SeqNum:     c.iss,
		AckNum:     c.irs + 1,
		DataOffset: uint8(hdrSize / 4),
		Flags:      header.TCPFlagSYN | header.TCPFlagACK,
		WindowSize: c.rcvWndSize,
	})
	copy(tcpBuf[header.TCPMinHeaderSize:], optBuf[:optLen])
	setTCPChecksum(hdr, c.flow.DstAddr, c.flow.SrcAddr, uint16(hdrSize))
	if st := c.stats; st != nil {
		st.SegmentsOut.Add(1)
	}
	c.handler.stack.SendPacket(pb, c.flow.DstAddr, c.flow.SrcAddr, tcpip.TCPProtocolNumber)
}

func (c *TCPConn) sendACK() {
	seqNum := c.iss + 1
	ackNum := c.irs + 1
	wnd := uint16(c.rcvWndSize)

	if c.snd != nil {
		seqNum = c.snd.nxt
	}
	if c.rcv != nil {
		ackNum = c.rcv.nxt
		wnd = c.rcv.wnd()
	}

	// Build options: Timestamp + SACK blocks.
	// Max: 12(TS) + 2+4*8(DSACK+3 regular) + 2(pad) = 48
	var optBuf [48]byte
	optLen := 0
	if c.tsEnabled {
		optLen += header.EncodeTimestampOption(optBuf[optLen:], c.handler.now(), c.tsRecent)
	}
	if c.sackPermitted && c.rcv != nil {
		if blocks := c.rcv.sackBlocks(); len(blocks) > 0 {
			optLen += header.EncodeSACKBlocks(optBuf[optLen:], blocks)
		}
	}
	for optLen%4 != 0 {
		optBuf[optLen] = header.TCPOptionNOP
		optLen++
	}

	hdrSize := header.TCPMinHeaderSize + optLen
	pb := packet.NewPacketBuffer(packet.MaxHeadroom)
	tcpBuf := pb.Prepend(hdrSize)
	hdr := header.TCP(tcpBuf)
	hdr.Encode(&header.TCPFields{
		SrcPort:    c.flow.DstPort,
		DstPort:    c.flow.SrcPort,
		SeqNum:     seqNum,
		AckNum:     ackNum,
		DataOffset: uint8(hdrSize / 4),
		Flags:      header.TCPFlagACK,
		WindowSize: wnd,
	})
	if optLen > 0 {
		copy(tcpBuf[header.TCPMinHeaderSize:], optBuf[:optLen])
	}
	setTCPChecksum(hdr, c.flow.DstAddr, c.flow.SrcAddr, uint16(hdrSize))
	if st := c.stats; st != nil {
		st.SegmentsOut.Add(1)
	}
	c.handler.stack.SendPacket(pb, c.flow.DstAddr, c.flow.SrcAddr, tcpip.TCPProtocolNumber)
	c.updateTSLastAckSent()
	c.lastWndZero = (wnd == 0)
}

// sendData sends a data segment with the given payload and sequence number.
func (c *TCPConn) sendData(data []byte, seq uint32) {
	var optBuf [12]byte
	optLen := 0
	if c.tsEnabled {
		optLen += header.EncodeTimestampOption(optBuf[optLen:], c.handler.now(), c.tsRecent)
	}

	hdrSize := header.TCPMinHeaderSize + optLen
	tcpLen := uint16(hdrSize + len(data))
	pb := packet.NewPacketBuffer(packet.MaxHeadroom)
	pb.AppendData(data)
	tcpBuf := pb.Prepend(hdrSize)
	hdr := header.TCP(tcpBuf)
	wnd := c.rcv.wnd()
	hdr.Encode(&header.TCPFields{
		SrcPort:    c.flow.DstPort,
		DstPort:    c.flow.SrcPort,
		SeqNum:     seq,
		AckNum:     c.rcv.nxt,
		DataOffset: uint8(hdrSize / 4),
		Flags:      header.TCPFlagACK,
		WindowSize: wnd,
	})
	if optLen > 0 {
		copy(tcpBuf[header.TCPMinHeaderSize:], optBuf[:optLen])
	}
	setTCPChecksum(hdr, c.flow.DstAddr, c.flow.SrcAddr, tcpLen)
	if st := c.stats; st != nil {
		st.SegmentsOut.Add(1)
		st.PayloadBytesOut.Add(uint64(len(data)))
	}
	c.handler.stack.SendPacket(pb, c.flow.DstAddr, c.flow.SrcAddr, tcpip.TCPProtocolNumber)
	c.updateTSLastAckSent()
	c.lastWndZero = (wnd == 0)
}

// gsoDataOffset returns the byte offset within a GSO buffer where payload data starts.
// Layout: [IP header][TCP header + options][payload...]
func (c *TCPConn) gsoDataOffset() int {
	optLen := 0
	if c.tsEnabled {
		optLen = 12 // timestamp option
	}
	return header.IPv4MinHeaderSize + header.TCPMinHeaderSize + optLen
}

// sendDataGSO sends a large GSO segment. The payload must already be placed
// at buf[c.gsoDataOffset():c.gsoDataOffset()+dataLen]. The GSO buffer is
// handed off to the stack and must not be reused by the caller.
func (c *TCPConn) sendDataGSO(buf []byte, dataLen int, seq uint32) {
	var optBuf [12]byte
	optLen := 0
	if c.tsEnabled {
		optLen += header.EncodeTimestampOption(optBuf[optLen:], c.handler.now(), c.tsRecent)
	}

	tcpHdrSize := header.TCPMinHeaderSize + optLen
	ipHdrSize := header.IPv4MinHeaderSize
	totalLen := ipHdrSize + tcpHdrSize + dataLen
	tcpLen := uint16(tcpHdrSize + dataLen)

	// Build TCP header.
	tcpBuf := buf[ipHdrSize : ipHdrSize+tcpHdrSize]
	hdr := header.TCP(tcpBuf)
	wnd := c.rcv.wnd()
	hdr.Encode(&header.TCPFields{
		SrcPort:    c.flow.DstPort,
		DstPort:    c.flow.SrcPort,
		SeqNum:     seq,
		AckNum:     c.rcv.nxt,
		DataOffset: uint8(tcpHdrSize / 4),
		Flags:      header.TCPFlagACK,
		WindowSize: wnd,
	})
	if optLen > 0 {
		copy(tcpBuf[header.TCPMinHeaderSize:], optBuf[:optLen])
	}
	setTCPPartialChecksum(hdr, c.flow.DstAddr, c.flow.SrcAddr, tcpLen)

	opts := channel.PacketOptions{
		GSOType:    channel.GSOTCPv4,
		GSOSize:    uint16(c.snd.mss),
		HdrLen:     uint16(ipHdrSize + tcpHdrSize),
		CsumStart:  uint16(ipHdrSize),
		CsumOffset: 16, // TCP checksum field offset within transport header
	}

	if st := c.stats; st != nil {
		st.SegmentsOut.Add(1)
		st.PayloadBytesOut.Add(uint64(dataLen))
	}
	c.handler.stack.SendPacketGSO(buf, 0, totalLen, c.flow.DstAddr, c.flow.SrcAddr, tcpip.TCPProtocolNumber, opts)
	c.updateTSLastAckSent()
	c.lastWndZero = (wnd == 0)
}

// sendFINSegment sends a FIN+ACK segment with the given sequence number.
func (c *TCPConn) sendFINSegment(seq uint32) {
	ackNum := c.irs + 1
	wnd := uint16(c.rcvWndSize)
	if c.rcv != nil {
		ackNum = c.rcv.nxt
		wnd = c.rcv.wnd()
	}

	var optBuf [12]byte
	optLen := 0
	if c.tsEnabled {
		optLen += header.EncodeTimestampOption(optBuf[optLen:], c.handler.now(), c.tsRecent)
	}

	hdrSize := header.TCPMinHeaderSize + optLen
	pb := packet.NewPacketBuffer(packet.MaxHeadroom)
	tcpBuf := pb.Prepend(hdrSize)
	hdr := header.TCP(tcpBuf)
	hdr.Encode(&header.TCPFields{
		SrcPort:    c.flow.DstPort,
		DstPort:    c.flow.SrcPort,
		SeqNum:     seq,
		AckNum:     ackNum,
		DataOffset: uint8(hdrSize / 4),
		Flags:      header.TCPFlagFIN | header.TCPFlagACK,
		WindowSize: wnd,
	})
	if optLen > 0 {
		copy(tcpBuf[header.TCPMinHeaderSize:], optBuf[:optLen])
	}
	setTCPChecksum(hdr, c.flow.DstAddr, c.flow.SrcAddr, uint16(hdrSize))
	if st := c.stats; st != nil {
		st.SegmentsOut.Add(1)
	}
	c.handler.stack.SendPacket(pb, c.flow.DstAddr, c.flow.SrcAddr, tcpip.TCPProtocolNumber)
	c.updateTSLastAckSent()
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
	if st := c.stats; st != nil {
		st.SegmentsOut.Add(1)
		st.ResetsSent.Add(1)
	}
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
	if st := h.stats; st != nil {
		st.SegmentsOut.Add(1)
	}
	h.stack.SendPacket(rstPB, srcAddr, dstAddr, tcpip.TCPProtocolNumber)
}
