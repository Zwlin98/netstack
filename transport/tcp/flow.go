package tcp

import "github.com/Zwlin98/netstack/tcpip"

// FlowID identifies a TCP connection by 4-tuple.
type FlowID struct {
	SrcAddr tcpip.Address
	DstAddr tcpip.Address
	SrcPort uint16
	DstPort uint16
}

func (f FlowID) reverse() FlowID {
	return FlowID{
		SrcAddr: f.DstAddr,
		DstAddr: f.SrcAddr,
		SrcPort: f.DstPort,
		DstPort: f.SrcPort,
	}
}
