package tun

import (
	"testing"

	"github.com/Zwlin98/netstack/channel"
	"golang.org/x/sys/unix"
)

func TestGSOEnabledWithVnetHdr(t *testing.T) {
	c := &TUNChannel{tun: &nativeTun{vnetHdr: true}}
	if !c.GSOEnabled() {
		t.Error("GSOEnabled() = false, want true when vnetHdr is set")
	}
	if c.GSOMaxSize() != 65535-40 {
		t.Errorf("GSOMaxSize() = %d, want %d", c.GSOMaxSize(), 65535-40)
	}
}

func TestGSODisabledWithoutVnetHdr(t *testing.T) {
	c := &TUNChannel{tun: &nativeTun{vnetHdr: false}}
	if c.GSOEnabled() {
		t.Error("GSOEnabled() = true, want false when vnetHdr is not set")
	}
	if c.GSOMaxSize() != 0 {
		t.Errorf("GSOMaxSize() = %d, want 0", c.GSOMaxSize())
	}
}

func TestVirtioHeaderEncodeGSONone(t *testing.T) {
	opts := channel.PacketOptions{} // GSOType = GSONone
	var hdr virtioNetHdr
	if opts.GSOType != channel.GSONone {
		hdr.flags = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
		hdr.gsoType = opts.GSOType
		hdr.gsoSize = opts.GSOSize
		hdr.hdrLen = opts.HdrLen
		hdr.csumStart = opts.CsumStart
		hdr.csumOffset = opts.CsumOffset
	}
	var buf [virtioNetHdrLen]byte
	hdr.encode(buf[:])
	for i, b := range buf {
		if b != 0 {
			t.Errorf("virtio header byte[%d] = 0x%02x, want 0x00 for GSONone", i, b)
		}
	}
}

func TestVirtioHeaderEncodeGSOTCPv4(t *testing.T) {
	opts := channel.PacketOptions{
		GSOType:    channel.GSOTCPv4,
		GSOSize:    1460,
		HdrLen:     52,
		CsumStart:  20,
		CsumOffset: 16,
	}
	var hdr virtioNetHdr
	hdr.flags = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
	hdr.gsoType = opts.GSOType
	hdr.gsoSize = opts.GSOSize
	hdr.hdrLen = opts.HdrLen
	hdr.csumStart = opts.CsumStart
	hdr.csumOffset = opts.CsumOffset

	if hdr.flags != unix.VIRTIO_NET_HDR_F_NEEDS_CSUM {
		t.Errorf("flags = 0x%02x, want 0x%02x", hdr.flags, unix.VIRTIO_NET_HDR_F_NEEDS_CSUM)
	}
	if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 {
		t.Errorf("gsoType = 0x%02x, want 0x%02x", hdr.gsoType, unix.VIRTIO_NET_HDR_GSO_TCPV4)
	}
	if hdr.gsoSize != 1460 {
		t.Errorf("gsoSize = %d, want 1460", hdr.gsoSize)
	}
	if hdr.hdrLen != 52 {
		t.Errorf("hdrLen = %d, want 52", hdr.hdrLen)
	}
	if hdr.csumStart != 20 {
		t.Errorf("csumStart = %d, want 20", hdr.csumStart)
	}
	if hdr.csumOffset != 16 {
		t.Errorf("csumOffset = %d, want 16", hdr.csumOffset)
	}

	// Verify encode/decode roundtrip.
	var buf [virtioNetHdrLen]byte
	hdr.encode(buf[:])
	var decoded virtioNetHdr
	decoded.decode(buf[:])
	if decoded != hdr {
		t.Errorf("encode/decode roundtrip mismatch: got %+v, want %+v", decoded, hdr)
	}
}

func TestTUNChannelImplementsGSOWriter(t *testing.T) {
	c := &TUNChannel{tun: &nativeTun{}}
	var ch interface{} = c
	if _, ok := ch.(channel.GSOWriter); !ok {
		t.Error("TUNChannel should implement channel.GSOWriter")
	}
}
