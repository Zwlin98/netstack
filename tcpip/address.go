package tcpip

import "fmt"

// Address is an IPv4 address stored as uint32 in network byte order.
type Address uint32

// From4 creates an Address from four octets.
func From4(a, b, c, d byte) Address {
	return Address(uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d))
}

// To4 returns the four octets of the address.
func (a Address) To4() [4]byte {
	return [4]byte{
		byte(a >> 24),
		byte(a >> 16),
		byte(a >> 8),
		byte(a),
	}
}

// String returns the dotted-decimal representation.
func (a Address) String() string {
	b := a.To4()
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// FullAddress includes IP and port, used to identify endpoints.
type FullAddress struct {
	Addr Address
	Port uint16
}

// String returns "ip:port" representation.
func (fa FullAddress) String() string {
	return fmt.Sprintf("%s:%d", fa.Addr, fa.Port)
}
