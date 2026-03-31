package udp

import "github.com/Zwlin98/netstack/tcpip"

// FlowID identifies a unique UDP flow by its full 4-tuple.
// Exported for use by upper-layer NAT implementations.
type FlowID struct {
	SrcAddr tcpip.Address
	SrcPort uint16
	DstAddr tcpip.Address
	DstPort uint16
}
