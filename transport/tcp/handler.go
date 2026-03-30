package tcp

import (
	"sync"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/stack"
)

// TCPHandler implements stack.TransportHandler for TCP.
type TCPHandler struct {
	mu       sync.RWMutex
	conns    map[FlowID]*TCPConn
	listener *TCPListener
	stack    *stack.Stack

	wg sync.WaitGroup
}

// NewTCPHandler creates a new TCPHandler.
func NewTCPHandler(s *stack.Stack) *TCPHandler {
	return &TCPHandler{
		conns: make(map[FlowID]*TCPConn),
		listener: &TCPListener{
			acceptCh: make(chan *TCPConn, 16),
			done:     make(chan struct{}),
		},
		stack: s,
	}
}

// Listener returns the TCPListener for accepting connections.
func (h *TCPHandler) Listener() *TCPListener {
	return h.listener
}

// HandlePacket dispatches an incoming TCP segment.
func (h *TCPHandler) HandlePacket(pb *packet.PacketBuffer) {
	if len(pb.Data) < header.TCPMinHeaderSize {
		pb.Release()
		return
	}

	tcpHdr := header.TCP(pb.Data)
	ipHdr := header.IPv4(pb.NetworkHeader)

	flow := FlowID{
		SrcAddr: ipHdr.SourceAddress(),
		DstAddr: ipHdr.DestinationAddress(),
		SrcPort: tcpHdr.SourcePort(),
		DstPort: tcpHdr.DestinationPort(),
	}

	h.mu.RLock()
	conn, exists := h.conns[flow]
	h.mu.RUnlock()

	if exists {
		select {
		case conn.inbound <- pb:
		default:
			pb.Release()
		}
		return
	}

	if tcpHdr.Flags().Has(header.TCPFlagSYN) {
		h.handleSYN(pb, flow)
		return
	}

	h.sendRST(pb)
	pb.Release()
}

func (h *TCPHandler) handleSYN(pb *packet.PacketBuffer, flow FlowID) {
	tcpHdr := header.TCP(pb.Data)

	conn := &TCPConn{
		flow:    flow,
		handler: h,
		state:   stateSynRcvd,
		irs:     tcpHdr.SequenceNumber(),
		iss:     generateISN(),
		inbound: make(chan *packet.PacketBuffer, 16),
		done:    make(chan struct{}),
	}

	h.mu.Lock()
	h.conns[flow] = conn
	h.mu.Unlock()

	conn.sendSYNACK()

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		conn.run()
	}()

	pb.Release()
}

func (h *TCPHandler) removeConn(flow FlowID) {
	h.mu.Lock()
	delete(h.conns, flow)
	h.mu.Unlock()
}

// Close shuts down the handler and all connections.
func (h *TCPHandler) Close() error {
	h.listener.Close()

	h.mu.Lock()
	conns := make([]*TCPConn, 0, len(h.conns))
	for _, c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()

	for _, c := range conns {
		c.closeOnce.Do(func() {
			close(c.done)
		})
	}

	h.wg.Wait()
	return nil
}
