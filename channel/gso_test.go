package channel

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestGSOConstantsMatchKernel(t *testing.T) {
	tests := []struct {
		name   string
		got    uint8
		want   int
	}{
		{"GSONone", GSONone, unix.VIRTIO_NET_HDR_GSO_NONE},
		{"GSOTCPv4", GSOTCPv4, unix.VIRTIO_NET_HDR_GSO_TCPV4},
		{"GSOTCPv6", GSOTCPv6, unix.VIRTIO_NET_HDR_GSO_TCPV6},
		{"GSOUDP", GSOUDP, unix.VIRTIO_NET_HDR_GSO_UDP_L4},
	}
	for _, tt := range tests {
		if int(tt.got) != tt.want {
			t.Errorf("%s = 0x%02x, want 0x%02x", tt.name, tt.got, tt.want)
		}
	}
}

func TestMemoryChannelNotGSOWriter(t *testing.T) {
	ch := NewMemory(1500)
	var c Channel = ch
	if _, ok := c.(GSOWriter); ok {
		t.Error("MemoryChannel should not implement GSOWriter")
	}
}
