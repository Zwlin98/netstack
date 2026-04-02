package tcp_test

import (
	"testing"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// gsoMemoryChannel wraps MemoryChannel with GSOWriter support for testing.
type gsoMemoryChannel struct {
	*channel.MemoryChannel
}

func (g *gsoMemoryChannel) WritePacketGSO(data []byte, opts channel.PacketOptions) error {
	return g.MemoryChannel.WritePacket(data)
}
func (g *gsoMemoryChannel) GSOEnabled() bool { return true }
func (g *gsoMemoryChannel) GSOMaxSize() int  { return 65535 - 40 }

func TestHandlerDetectsGSOFromChannel(t *testing.T) {
	gch := &gsoMemoryChannel{MemoryChannel: channel.NewMemory(1500)}
	s := stack.New(gch)
	defer s.Stop()
	s.Start()

	h := tcp.NewTCPHandler(s)
	if !tcp.HandlerGSOEnabled(h) {
		t.Error("handler should detect GSO when channel implements GSOWriter")
	}
	if tcp.HandlerGSOMaxSize(h) != 65535-40 {
		t.Errorf("gsoMaxSize = %d, want %d", tcp.HandlerGSOMaxSize(h), 65535-40)
	}
}

func TestHandlerNoGSOFromMemoryChannel(t *testing.T) {
	ch := channel.NewMemory(1500)
	s := stack.New(ch)
	defer s.Stop()
	s.Start()

	h := tcp.NewTCPHandler(s)
	if tcp.HandlerGSOEnabled(h) {
		t.Error("handler should not detect GSO on MemoryChannel")
	}
	if tcp.HandlerGSOMaxSize(h) != 0 {
		t.Errorf("gsoMaxSize = %d, want 0", tcp.HandlerGSOMaxSize(h))
	}
}

// gsoDisabledChannel implements GSOWriter but returns GSOEnabled=false.
type gsoDisabledChannel struct {
	*channel.MemoryChannel
}

func (g *gsoDisabledChannel) WritePacketGSO(data []byte, opts channel.PacketOptions) error {
	return g.MemoryChannel.WritePacket(data)
}
func (g *gsoDisabledChannel) GSOEnabled() bool { return false }
func (g *gsoDisabledChannel) GSOMaxSize() int  { return 0 }

func TestHandlerNoGSOWhenDisabled(t *testing.T) {
	gch := &gsoDisabledChannel{MemoryChannel: channel.NewMemory(1500)}
	s := stack.New(gch)
	defer s.Stop()
	s.Start()

	h := tcp.NewTCPHandler(s)
	if tcp.HandlerGSOEnabled(h) {
		t.Error("handler should not detect GSO when GSOEnabled() returns false")
	}
}
