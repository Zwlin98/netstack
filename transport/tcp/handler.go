// Package tcp implements TCP handler for the netstack
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

	// Only a pure SYN (without ACK) initiates a new connection.
	// SYN+ACK to a non-existent flow is invalid and falls through to sendRST.
	if tcpHdr.Flags().Has(header.TCPFlagSYN) && !tcpHdr.Flags().Has(header.TCPFlagACK) {
		h.handleSYN(pb, flow)
		return
	}

	// Never send RST in response to RST (RFC 793).
	if tcpHdr.Flags().Has(header.TCPFlagRST) {
		pb.Release()
		return
	}

	h.sendRST(pb)
	pb.Release()
}

func (h *TCPHandler) handleSYN(pb *packet.PacketBuffer, flow FlowID) {
	tcpHdr := header.TCP(pb.Data)
	irs := tcpHdr.SequenceNumber()
	iss := generateISN()

	readBuf := newRingBuffer(defaultBufSize)
	writeBuf := newRingBuffer(defaultBufSize)

	conn := &TCPConn{
		flow:        flow,
		handler:     h,
		state:       stateSynRcvd,
		irs:         irs,
		iss:         iss,
		readBuf:     readBuf,
		writeBuf:    writeBuf,
		writeNotify: make(chan struct{}, 1),
		inbound:     make(chan *packet.PacketBuffer, 16),
		done:        make(chan struct{}),
		closeCh:     make(chan struct{}, 1),
	}

	h.mu.Lock()
	h.conns[flow] = conn
	h.mu.Unlock()

	conn.sendSYNACK()

	h.wg.Go(func() {
		conn.run()
	})

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
		c.ForceClose()
	}

	h.wg.Wait()
	return nil
}
