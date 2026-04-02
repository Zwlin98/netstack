package stack

import (
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
)

func (s *Stack) handleICMP(pb *packet.PacketBuffer, ipHdr header.IPv4) {
	defer pb.Release()

	icmpData := pb.Data
	if len(icmpData) < header.ICMPv4HeaderSize {
		return
	}

	icmpHdr := header.ICMPv4(icmpData)
	if icmpHdr.Type() != header.ICMPv4Echo {
		return // only handle echo requests
	}

	// Swap src/dst in IP header.
	src := ipHdr.SourceAddress()
	dst := ipHdr.DestinationAddress()
	ipHdr.SetSourceAddress(dst)
	ipHdr.SetDestinationAddress(src)
	ipHdr.SetTTL(64)
	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(header.Checksum(pb.NetworkHeader, 0))

	// Change ICMP type to EchoReply, recalculate checksum.
	icmpHdr.SetType(header.ICMPv4EchoReply)
	icmpHdr.SetChecksum(0)
	icmpHdr.SetChecksum(header.Checksum(icmpData, 0))

	// Send directly — packet is already complete in the buffer.
	// NetworkHeader and Data are contiguous in the backing buffer.
	totalLen := len(pb.NetworkHeader) + len(icmpData)
	if st := s.stats; st != nil {
		st.PacketsOut.Add(1)
		st.BytesOut.Add(uint64(totalLen))
	}
	s.channel.WritePacket(pb.NetworkHeader[:totalLen])
}
