package channel

// GSO type constants matching linux/virtio_net.h.
const (
	GSONone  = 0x00 // VIRTIO_NET_HDR_GSO_NONE
	GSOTCPv4 = 0x01 // VIRTIO_NET_HDR_GSO_TCPV4
	GSOTCPv6 = 0x04 // VIRTIO_NET_HDR_GSO_TCPV6
	GSOUDP   = 0x05 // VIRTIO_NET_HDR_GSO_UDP_L4
)

// PacketOptions carries GSO/checksum offload metadata for a single packet.
// A zero-value PacketOptions (GSOType=GSONone) means no offload.
type PacketOptions struct {
	GSOType    uint8  // GSO segmentation type
	GSOSize    uint16 // segment size (MSS for TCP)
	HdrLen     uint16 // IP + transport header total length
	CsumStart  uint16 // offset from packet start to transport header
	CsumOffset uint16 // offset within transport header to checksum field
}

// GSOWriter is an optional interface for channels that support
// GSO (Generic Segmentation Offload) and checksum offload.
// Callers detect support via type assertion: gw, ok := ch.(GSOWriter).
type GSOWriter interface {
	// WritePacketGSO writes an IP packet with GSO/checksum offload metadata.
	// When opts is zero-value, behavior is identical to WritePacket.
	WritePacketGSO(data []byte, opts PacketOptions) error

	// GSOEnabled reports whether this channel supports GSO.
	GSOEnabled() bool

	// GSOMaxSize returns the maximum payload size for a GSO segment.
	// Returns 0 when GSO is not supported.
	GSOMaxSize() int
}
