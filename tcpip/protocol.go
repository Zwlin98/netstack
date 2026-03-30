package tcpip

// NetworkProtocolNumber is the EtherType identifying a network-layer protocol.
type NetworkProtocolNumber uint16

// TransportProtocolNumber is the IP protocol number identifying a transport-layer protocol.
type TransportProtocolNumber uint8

const (
	// IPv4ProtocolNumber is the EtherType for IPv4.
	IPv4ProtocolNumber NetworkProtocolNumber = 0x0800
)

const (
	// ICMPv4ProtocolNumber is the IP protocol number for ICMPv4.
	ICMPv4ProtocolNumber TransportProtocolNumber = 1
	// TCPProtocolNumber is the IP protocol number for TCP.
	TCPProtocolNumber TransportProtocolNumber = 6
	// UDPProtocolNumber is the IP protocol number for UDP.
	UDPProtocolNumber TransportProtocolNumber = 17
)
