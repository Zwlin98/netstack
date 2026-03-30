// Package channel definition for reading and writing IP packets.
package channel

// Channel is the abstraction for packet I/O.
type Channel interface {
	// ReadPacket reads one IP packet into the provided buffer.
	// Returns the number of bytes read.
	ReadPacket(buf []byte) (int, error)

	// WritePacket writes one complete IP packet.
	WritePacket(data []byte) error

	// Close shuts down the channel.
	Close() error

	// MTU returns the maximum transmission unit.
	MTU() int
}
