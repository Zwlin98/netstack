package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// TestLazyBuffer_InitialAllocation verifies connections are created with small
// initial buffers, not the full ReadBufferSize/WriteBufferSize.
func TestLazyBuffer_InitialAllocation(t *testing.T) {
	ch, s, h := setupStack(t,
		tcp.WithReadBufferSize(256*1024),
		tcp.WithWriteBufferSize(256*1024),
		tcp.WithInitialReadBufferSize(32*1024),
		tcp.WithInitialWriteBufferSize(32*1024),
	)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60010)
	serverPort := uint16(80)
	clientISN := uint32(5000)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	readCap := tcp.ReadBufCap(conn)
	writeCap := tcp.WriteBufCap(conn)

	if readCap != 32*1024 {
		t.Errorf("readBuf cap = %d, want %d", readCap, 32*1024)
	}
	if writeCap != 32*1024 {
		t.Errorf("writeBuf cap = %d, want %d", writeCap, 32*1024)
	}
	if tcp.ConnReadBufSize(conn) != 256*1024 {
		t.Errorf("readBufSize = %d, want %d", tcp.ConnReadBufSize(conn), 256*1024)
	}
	if tcp.ConnWriteBufSize(conn) != 256*1024 {
		t.Errorf("writeBufSize = %d, want %d", tcp.ConnWriteBufSize(conn), 256*1024)
	}
}

// TestLazyBuffer_DefaultInitialSize verifies the default initial size is 32KB.
func TestLazyBuffer_DefaultInitialSize(t *testing.T) {
	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60011)
	serverPort := uint16(80)
	clientISN := uint32(5100)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	readCap := tcp.ReadBufCap(conn)
	if readCap != 32*1024 {
		t.Errorf("default readBuf cap = %d, want %d", readCap, 32*1024)
	}
}

// TestLazyBuffer_Phase1Growth verifies that readBuf grows aggressively
// (on any data delivery) when below ReadBufferSize.
func TestLazyBuffer_Phase1Growth(t *testing.T) {
	initial := 4096
	target := 16384
	maxBuf := 32768

	ch, s, h := setupStack(t,
		tcp.WithInitialReadBufferSize(initial),
		tcp.WithReadBufferSize(target),
		tcp.WithMaxReadBufferSize(maxBuf),
	)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60012)
	serverPort := uint16(80)
	clientISN := uint32(5200)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	if tcp.ReadBufCap(conn) != initial {
		t.Fatalf("initial cap = %d, want %d", tcp.ReadBufCap(conn), initial)
	}

	// Establish RTT.
	go func() { conn.Write([]byte("hi")) }()
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected server data")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	dataEnd := dataHdr.SequenceNumber() + 2
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, dataEnd, 65535, nil)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond)

	// Continuous reader.
	stopReader := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-stopReader:
				return
			default:
			}
			_, err := conn.Read(buf)
			if err != nil {
				return
			}
		}
	}()
	defer close(stopReader)

	// Send small amounts of data — in phase 1, any positive delivery triggers doubling.
	clientSeq := clientISN + 1
	for round := 0; round < 4; round++ {
		smallData := make([]byte, 100)
		pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientSeq, dataEnd, 65535, smallData)
		ch.Inject(pkt)
		clientSeq += uint32(len(smallData))
		for {
			r := ch.Read(50 * time.Millisecond)
			if r == nil {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	cap := tcp.ReadBufCap(conn)
	// Should have grown from 4096 toward target (16384), but not beyond.
	if cap <= initial {
		t.Errorf("phase-1: buffer should have grown: cap=%d, initial=%d", cap, initial)
	}
	if cap > target {
		t.Errorf("phase-1: buffer should not exceed ReadBufferSize: cap=%d, target=%d", cap, target)
	}
}

// TestLazyBuffer_Phase2ThresholdApplies verifies that once readBuf reaches
// ReadBufferSize, the standard 50% utilization threshold applies.
func TestLazyBuffer_Phase2ThresholdApplies(t *testing.T) {
	// Set initial == target so phase-1 is skipped entirely.
	bufSize := 4096
	maxBuf := 16384

	ch, s, h := setupStack(t,
		tcp.WithInitialReadBufferSize(bufSize),
		tcp.WithReadBufferSize(bufSize),
		tcp.WithMaxReadBufferSize(maxBuf),
	)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60013)
	serverPort := uint16(80)
	clientISN := uint32(5300)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Establish RTT.
	go func() { conn.Write([]byte("hi")) }()
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected server data")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	dataEnd := dataHdr.SequenceNumber() + 2
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, dataEnd, 65535, nil)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond)

	// Send small data — below 50% threshold (2048).
	clientSeq := clientISN + 1
	for round := 0; round < 3; round++ {
		smallData := make([]byte, 100) // 100 << 2048
		pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientSeq, dataEnd, 65535, smallData)
		ch.Inject(pkt)
		clientSeq += uint32(len(smallData))
		time.Sleep(200 * time.Millisecond)
	}

	cap := tcp.ReadBufCap(conn)
	if cap != bufSize {
		t.Errorf("phase-2: buffer should NOT have grown with low utilization: cap=%d, want=%d", cap, bufSize)
	}
}

// TestLazyBuffer_WriteBufGrowsOnWrite verifies that writeBuf grows to
// WriteBufferSize on first Write().
func TestLazyBuffer_WriteBufGrowsOnWrite(t *testing.T) {
	initial := 4096
	target := 32768

	ch, s, h := setupStack(t,
		tcp.WithInitialWriteBufferSize(initial),
		tcp.WithWriteBufferSize(target),
	)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60014)
	serverPort := uint16(80)
	clientISN := uint32(5400)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	if tcp.WriteBufCap(conn) != initial {
		t.Fatalf("initial writeBuf cap = %d, want %d", tcp.WriteBufCap(conn), initial)
	}

	// Write triggers growth.
	go func() { conn.Write([]byte("hello")) }()
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected server data")
	}

	cap := tcp.WriteBufCap(conn)
	if cap != target {
		t.Errorf("writeBuf cap after write = %d, want %d", cap, target)
	}
}

// TestLazyBuffer_ClampInitialSize verifies that InitialReadBufferSize is
// clamped to ReadBufferSize when configured larger.
func TestLazyBuffer_ClampInitialSize(t *testing.T) {
	ch, s, h := setupStack(t,
		tcp.WithReadBufferSize(8192),
		tcp.WithInitialReadBufferSize(65536), // larger than ReadBufferSize
		tcp.WithWriteBufferSize(8192),
		tcp.WithInitialWriteBufferSize(65536),
	)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60015)
	serverPort := uint16(80)
	clientISN := uint32(5500)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	readCap := tcp.ReadBufCap(conn)
	writeCap := tcp.WriteBufCap(conn)

	if readCap != 8192 {
		t.Errorf("readBuf cap = %d, want 8192 (clamped to ReadBufferSize)", readCap)
	}
	if writeCap != 8192 {
		t.Errorf("writeBuf cap = %d, want 8192 (clamped to WriteBufferSize)", writeCap)
	}
}
