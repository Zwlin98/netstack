// Package tcp implements TCP handler for the netstack
package tcp

import (
	"sync"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
)

// TCPHandler implements stack.TransportHandler for TCP.
type TCPHandler struct {
	mu       sync.RWMutex
	conns    map[FlowID]*TCPConn
	listener *TCPListener
	stack    *stack.Stack
	cfg      Config

	wg sync.WaitGroup

	// Timestamp clock (RFC 7323).
	tsOffset uint32    // random offset to prevent leaking uptime
	tsEpoch  time.Time // monotonic reference point

	// GSO support (cached from channel at init time).
	gsoWriter  channel.GSOWriter // nil when GSO unavailable
	gsoMaxSize int               // 0 when GSO unavailable

	stats *Stats // nil when stats not enabled
}

// NewTCPHandler creates a new TCPHandler.
func NewTCPHandler(s *stack.Stack, opts ...Option) *TCPHandler {
	cfg := defaultConfig
	for _, o := range opts {
		o(&cfg)
	}
	// Clamp initial buffer sizes to their target sizes.
	if cfg.InitialReadBufferSize > cfg.ReadBufferSize {
		cfg.InitialReadBufferSize = cfg.ReadBufferSize
	}
	if cfg.InitialWriteBufferSize > cfg.WriteBufferSize {
		cfg.InitialWriteBufferSize = cfg.WriteBufferSize
	}
	h := &TCPHandler{
		conns: make(map[FlowID]*TCPConn),
		listener: &TCPListener{
			acceptCh: make(chan *TCPConn, cfg.AcceptQueueSize),
			done:     make(chan struct{}),
		},
		stack:    s,
		cfg:      cfg,
		tsOffset: generateISN(), // random offset
		tsEpoch:  time.Now(),
	}
	if gw, ok := s.Channel().(channel.GSOWriter); ok && gw.GSOEnabled() {
		h.gsoWriter = gw
		h.gsoMaxSize = gw.GSOMaxSize()
	}
	return h
}

// now returns the current TSval for outgoing timestamps.
func (h *TCPHandler) now() uint32 {
	return uint32(time.Since(h.tsEpoch).Milliseconds()) + h.tsOffset
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

	// Verify TCP checksum (RFC 793 §3.1).
	tcpLen := min(ipHdr.TotalLength()-uint16(ipHdr.HeaderLength()), uint16(len(pb.Data)))
	partial := header.PseudoHeaderChecksum(tcpip.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), tcpLen)
	if header.Checksum(pb.Data[:tcpLen], partial) != 0 {
		if st := h.stats; st != nil {
			st.ChecksumErrors.Add(1)
		}
		pb.Release()
		return
	}

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
		if st := h.stats; st != nil {
			st.SegmentsIn.Add(1)
		}
		select {
		case conn.inbound <- pb:
		default:
			if st := h.stats; st != nil {
				st.DroppedInbound.Add(1)
			}
			pb.Release()
		}
		return
	}

	// Only a pure SYN (without ACK) initiates a new connection.
	// SYN+ACK to a non-existent flow is invalid and falls through to sendRST.
	if tcpHdr.Flags().Has(header.TCPFlagSYN) && !tcpHdr.Flags().Has(header.TCPFlagACK) {
		if st := h.stats; st != nil {
			st.SegmentsIn.Add(1)
		}
		h.handleSYN(pb, flow)
		return
	}

	// Never send RST in response to RST (RFC 793).
	if tcpHdr.Flags().Has(header.TCPFlagRST) {
		if st := h.stats; st != nil {
			st.ResetsReceived.Add(1)
		}
		pb.Release()
		return
	}

	if st := h.stats; st != nil {
		st.ResetsSent.Add(1)
	}
	h.sendRST(pb)
	pb.Release()
}

func (h *TCPHandler) handleSYN(pb *packet.PacketBuffer, flow FlowID) {
	tcpHdr := header.TCP(pb.Data)
	irs := tcpHdr.SequenceNumber()
	iss := generateISN()

	// Parse SYN options.
	synOpts := header.ParseSynOptions(tcpHdr.Options())

	cfg := &h.cfg
	readBuf := newRingBuffer(cfg.InitialReadBufferSize)
	writeBuf := newRingBuffer(cfg.InitialWriteBufferSize)

	conn := &TCPConn{
		flow:        flow,
		handler:     h,
		state:       stateSynRcvd,
		irs:         irs,
		iss:         iss,
		readBuf:     readBuf,
		writeBuf:    writeBuf,
		writeNotify:  make(chan struct{}, 1),
		windowNotify: make(chan struct{}, 1),
		inbound:     make(chan *packet.PacketBuffer, cfg.InboundQueueSize),
		done:        make(chan struct{}),
		closeCh:     make(chan struct{}, 1),

		// Config snapshot.
		keepaliveIdle:     cfg.KeepaliveIdle,
		keepaliveInterval: cfg.KeepaliveInterval,
		keepaliveCount:    cfg.KeepaliveCount,
		finWait2Timeout:   cfg.FinWait2Timeout,
		synRcvdTimeout:    cfg.SynRcvdTimeout,
		timeWaitDuration:  cfg.TimeWaitDuration,
		delayedACKTimeout: cfg.DelayedACKTimeout,
		maxZWPInterval:    cfg.MaxZeroWindowProbeInterval,
		rcvWndSize:        cfg.ReceiveWindowSize,
		minRTO:            cfg.MinRTO,
		maxRTO:            cfg.MaxRTO,
		initialRTO:        cfg.InitialRTO,
		maxRetries:        cfg.MaxRetries,
		initialSSThresh:   cfg.InitialSSThresh,
		maxReadBufSize:    cfg.MaxReadBufferSize,
		readBufSize:       cfg.ReadBufferSize,
		writeBufSize:      cfg.WriteBufferSize,
	}

	// Window scaling: only enable if peer offered it.
	// Use max buffer size (not initial) so the window can grow with auto-tuning.
	if synOpts.WS >= 0 {
		conn.sndWndScale = uint8(synOpts.WS)
		wndScaleBasis := cfg.ReadBufferSize
		if cfg.MaxReadBufferSize > wndScaleBasis {
			wndScaleBasis = cfg.MaxReadBufferSize
		}
		conn.rcvWndScale = calculateWindowScale(wndScaleBasis)
	}

	// SACK: only enable if peer offered it.
	conn.sackPermitted = synOpts.SACKPermit

	// Timestamps: only enable if peer offered it.
	if synOpts.TSEnabled {
		conn.tsEnabled = true
		conn.tsRecent = synOpts.TSVal
		conn.tsOffset = h.tsOffset
	}

	// MSS: store peer's MSS from SYN.
	conn.peerMSS = synOpts.MSS

	// Propagate stats pointer from handler.
	conn.stats = h.stats

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
