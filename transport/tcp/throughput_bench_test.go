package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// BenchmarkTCPInbound measures the inbound data path:
//
//	client inject → stack readLoop → TCP rcv → readBuf → conn.Read
//
// Copy hotspots: payload→readBuf (ringbuf.go:101), readBuf→user (ringbuf.go:165)
func BenchmarkTCPInbound(b *testing.B) {
	for _, tc := range []struct {
		name    string
		segSize int
	}{
		{"1460B", 1460},
		{"256B", 256},
	} {
		b.Run(tc.name, func(b *testing.B) {
			ch := channel.NewMemory(1500)
			s := stack.New(ch)
			h := tcp.NewTCPHandler(s,
				tcp.WithReadBufferSize(256*1024),
				tcp.WithWriteBufferSize(256*1024),
			)
			s.RegisterHandler(tcpip.TCPProtocolNumber, h)
			s.Start()
			defer s.Stop()
			defer h.Close()

			clientAddr := tcpip.From4(10, 0, 0, 1)
			serverAddr := tcpip.From4(10, 0, 0, 2)
			clientPort := uint16(50000)
			serverPort := uint16(80)
			clientISN := uint32(1000)

			serverISN := benchHandshake(b, ch, clientAddr, serverAddr, clientPort, serverPort, clientISN)
			conn := benchAccept(b, h)

			payload := make([]byte, tc.segSize)
			for i := range payload {
				payload[i] = byte(i)
			}
			readBuf := make([]byte, 32*1024)

			b.SetBytes(int64(tc.segSize))
			b.ResetTimer()

			clientSeq := clientISN + 1
			for range b.N {
				pkt := buildTCPPacketWithData(
					clientAddr, serverAddr, clientPort, serverPort,
					header.TCPFlagACK, clientSeq, serverISN+1, 65535,
					payload,
				)
				ch.Inject(pkt)
				clientSeq += uint32(tc.segSize)

				// Read from conn (exercises readBuf→user copy).
				remaining := tc.segSize
				for remaining > 0 {
					n, err := conn.Read(readBuf)
					if err != nil {
						b.Fatal(err)
					}
					remaining -= n
				}

				// Drain any outbound ACKs (non-blocking).
				drainOutbound(ch)
			}
		})
	}
}

// BenchmarkTCPOutbound measures the outbound data path:
//
//	conn.Write → writeBuf → sender → RefBuf → PacketBuffer → channel.WritePacket
//
// Copy hotspots: user→writeBuf (ringbuf.go:101), writeBuf→RefBuf (ringbuf.go:165),
// RefBuf→PacketBuffer (packet.go:89)
func BenchmarkTCPOutbound(b *testing.B) {
	for _, tc := range []struct {
		name    string
		segSize int
	}{
		{"1460B", 1460},
		{"256B", 256},
	} {
		b.Run(tc.name, func(b *testing.B) {
			ch := channel.NewMemory(1500)
			s := stack.New(ch)
			h := tcp.NewTCPHandler(s,
				tcp.WithReadBufferSize(256*1024),
				tcp.WithWriteBufferSize(256*1024),
			)
			s.RegisterHandler(tcpip.TCPProtocolNumber, h)
			s.Start()
			defer s.Stop()
			defer h.Close()

			clientAddr := tcpip.From4(10, 0, 0, 1)
			serverAddr := tcpip.From4(10, 0, 0, 2)
			clientPort := uint16(50000)
			serverPort := uint16(80)
			clientISN := uint32(1000)

			benchHandshake(b, ch, clientAddr, serverAddr, clientPort, serverPort, clientISN)
			conn := benchAccept(b, h)

			payload := make([]byte, tc.segSize)
			for i := range payload {
				payload[i] = byte(i)
			}

			b.SetBytes(int64(tc.segSize))
			b.ResetTimer()

			clientSeq := clientISN + 1
			for range b.N {
				// Write data (exercises user→writeBuf→RefBuf→PacketBuffer copies).
				_, err := conn.Write(payload)
				if err != nil {
					b.Fatal(err)
				}

				// Drain ALL outbound packets and ACK them to keep window open.
				// The sender may batch multiple segments in sendPending, so we
				// must drain everything to prevent the outbound channel from filling.
				drainAndACK(ch, clientAddr, serverAddr, clientPort, serverPort, &clientSeq)
			}
		})
	}
}

// BenchmarkTCPRoundtrip measures both paths: inject data → Read → Write → drain.
func BenchmarkTCPRoundtrip(b *testing.B) {
	ch := channel.NewMemory(1500)
	s := stack.New(ch)
	h := tcp.NewTCPHandler(s,
		tcp.WithReadBufferSize(256*1024),
		tcp.WithWriteBufferSize(256*1024),
	)
	s.RegisterHandler(tcpip.TCPProtocolNumber, h)
	s.Start()
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50000)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN := benchHandshake(b, ch, clientAddr, serverAddr, clientPort, serverPort, clientISN)
	conn := benchAccept(b, h)

	const segSize = 1460
	payload := make([]byte, segSize)
	readBuf := make([]byte, 2048)

	b.SetBytes(segSize * 2) // in + out
	b.ResetTimer()

	clientSeq := clientISN + 1
	for range b.N {
		// Inject inbound data.
		pkt := buildTCPPacketWithData(
			clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientSeq, serverISN+1, 65535,
			payload,
		)
		ch.Inject(pkt)
		clientSeq += segSize

		// Read from conn.
		remaining := segSize
		for remaining > 0 {
			n, err := conn.Read(readBuf)
			if err != nil {
				b.Fatal(err)
			}
			remaining -= n
		}

		// Drain inbound ACKs.
		drainOutbound(ch)

		// Write echo back.
		conn.Write(payload)

		// Drain echo data and ACK.
		drainAndACK(ch, clientAddr, serverAddr, clientPort, serverPort, &clientSeq)
	}
}

// drainOutbound reads all immediately available packets from the outbound channel.
func drainOutbound(ch *channel.MemoryChannel) {
	for ch.TryRead() != nil {
	}
}

// drainAndACK reads all available outbound packets, ACKs any data segments.
func drainAndACK(
	ch *channel.MemoryChannel,
	clientAddr, serverAddr tcpip.Address,
	clientPort, serverPort uint16,
	clientSeq *uint32,
) {
	// First, wait for at least one packet with a reasonable timeout.
	raw := ch.Read(time.Second)
	if raw == nil {
		return
	}

	for raw != nil {
		if len(raw) >= header.IPv4MinHeaderSize+header.TCPMinHeaderSize {
			ip := header.IPv4(raw)
			tcpHdr := header.TCP(raw[ip.HeaderLength():])
			payloadLen := int(ip.TotalLength()) - int(ip.HeaderLength()) - int(tcpHdr.DataOffset())
			if payloadLen > 0 {
				ack := buildTCPPacket(
					clientAddr, serverAddr, clientPort, serverPort,
					header.TCPFlagACK, *clientSeq,
					tcpHdr.SequenceNumber()+uint32(payloadLen),
				)
				ch.Inject(ack)
			}
		}
		// Try to read more (non-blocking).
		raw = ch.TryRead()
	}
}

// benchHandshake performs TCP 3-way handshake for benchmarks.
func benchHandshake(
	b *testing.B,
	ch *channel.MemoryChannel,
	clientAddr, serverAddr tcpip.Address,
	clientPort, serverPort uint16,
	clientISN uint32,
) uint32 {
	b.Helper()

	syn := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagSYN, clientISN, 0)
	ch.Inject(syn)

	raw := ch.Read(time.Second)
	if raw == nil {
		b.Fatal("expected SYN+ACK")
	}
	ip := header.IPv4(raw)
	tcpHdr := header.TCP(raw[ip.HeaderLength():])
	serverISN := tcpHdr.SequenceNumber()

	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort, header.TCPFlagACK, clientISN+1, serverISN+1)
	ch.Inject(ack)

	return serverISN
}

// benchAccept waits for a connection on the listener.
func benchAccept(b *testing.B, h *tcp.TCPHandler) *tcp.TCPConn {
	b.Helper()
	done := make(chan *tcp.TCPConn, 1)
	go func() {
		conn, _ := h.Listener().Accept()
		done <- conn
	}()
	select {
	case conn := <-done:
		return conn
	case <-time.After(time.Second):
		b.Fatal("Accept timed out")
		return nil
	}
}
