// Package udp implements a UDPHandler that manages a NAT table for forwarding UDP flows to the real network.
package udp

import (
	"net"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
)

// UDPHandler implements stack.TransportHandler for UDP.
// It manages a NAT table for forwarding UDP flows to the real network.
type UDPHandler struct {
	nat           *NATTable
	stk           *stack.Stack
	onNewSession  func(FlowID) bool
	cleanInterval time.Duration
}

// Option configures UDPHandler.
type Option func(*UDPHandler)

// WithCleanInterval sets the NAT table cleanup interval.
func WithCleanInterval(d time.Duration) Option {
	return func(h *UDPHandler) {
		h.cleanInterval = d
	}
}

// NewUDPHandler creates a UDPHandler and starts the NAT cleaner goroutine.
func NewUDPHandler(s *stack.Stack, opts ...Option) *UDPHandler {
	h := &UDPHandler{
		stk:           s,
		onNewSession:  func(FlowID) bool { return true }, // accept all by default
		cleanInterval: CleanInterval,
	}
	for _, opt := range opts {
		opt(h)
	}
	h.nat = newNATTable(s)
	go h.nat.cleanerLoop(h.cleanInterval)
	return h
}

// SetNewSessionCallback sets the callback invoked when a new UDP flow is seen.
// If the callback returns false, the flow is rejected and no NAT entry is created.
func (h *UDPHandler) SetNewSessionCallback(fn func(FlowID) bool) {
	h.onNewSession = fn
}

// HandlePacket processes an inbound UDP packet from the stack.
func (h *UDPHandler) HandlePacket(pb *packet.PacketBuffer) {
	defer pb.Release()

	if len(pb.Data) < header.UDPHeaderSize {
		return
	}

	// Parse headers.
	ipHdr := header.IPv4(pb.NetworkHeader)
	udpHdr := header.UDP(pb.Data[:header.UDPHeaderSize])
	payload := pb.Data[header.UDPHeaderSize:]

	flow := FlowID{
		SrcAddr: ipHdr.SourceAddress(),
		SrcPort: udpHdr.SourcePort(),
		DstAddr: ipHdr.DestinationAddress(),
		DstPort: udpHdr.DestinationPort(),
	}

	// Lookup or create NAT entry.
	entry := h.nat.Lookup(flow)
	if entry == nil {
		if !h.onNewSession(flow) {
			return // rejected
		}
		var err error
		entry, err = h.nat.CreateEntry(flow)
		if err != nil {
			return
		}
	}

	// Forward payload to real network.
	dst := &net.UDPAddr{
		IP:   addrToIP(flow.DstAddr),
		Port: int(flow.DstPort),
	}
	entry.realConn.WriteTo(payload, dst)
	entry.lastActive.Store(time.Now().Unix())
}

// Close stops the NAT table and all active sessions.
func (h *UDPHandler) Close() {
	h.nat.Stop()
}

func addrToIP(addr tcpip.Address) net.IP {
	b := addr.To4()
	return net.IP(b[:])
}
