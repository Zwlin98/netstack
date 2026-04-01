package tcp_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// TestAutoTune_GrowthTrigger verifies that the receive buffer grows when
// throughput per RTT exceeds 50% of buffer capacity.
func TestAutoTune_GrowthTrigger(t *testing.T) {
	initialBuf := 4096
	maxBuf := 32768

	ch, s, h := setupStack(t,
		tcp.WithReadBufferSize(initialBuf),
		tcp.WithMaxReadBufferSize(maxBuf),
	)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60001)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	initialCap := tcp.ReadBufCap(conn)
	if initialCap != initialBuf {
		t.Fatalf("initial buffer capacity = %d, want %d", initialCap, initialBuf)
	}

	// Establish RTT by having the server send data and receiving an ACK.
	go func() { conn.Write([]byte("ping")) }()
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected server data")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	dataEnd := dataHdr.SequenceNumber() + 4
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, dataEnd, 65535, nil)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond) // let RTT measurement propagate

	// Start a goroutine to continuously drain the read buffer.
	var totalRead atomic.Int64
	stopReader := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-stopReader:
				return
			default:
			}
			n, err := conn.Read(buf)
			if n > 0 {
				totalRead.Add(int64(n))
			}
			if err != nil {
				return
			}
		}
	}()
	defer close(stopReader)

	// Send data in bursts with pauses to allow measurement windows to complete.
	// Each burst exceeds 50% of current buffer capacity.
	clientSeq := clientISN + 1
	for round := 0; round < 4; round++ {
		// Send a burst of data.
		for i := 0; i < 8; i++ {
			chunk := make([]byte, 512)
			pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
				header.TCPFlagACK, clientSeq, dataEnd, 65535, chunk)
			ch.Inject(pkt)
			clientSeq += 512
		}
		// Drain any ACKs.
		for {
			r := ch.Read(50 * time.Millisecond)
			if r == nil {
				break
			}
		}
		// Wait for measurement window (SRTT) to elapse.
		time.Sleep(200 * time.Millisecond)
	}

	newCap := tcp.ReadBufCap(conn)
	if newCap <= initialCap {
		t.Errorf("buffer should have grown: cap=%d, initial=%d", newCap, initialCap)
	}
	if newCap > maxBuf {
		t.Errorf("buffer exceeded max: cap=%d, max=%d", newCap, maxBuf)
	}
	_ = serverISN
}

// TestAutoTune_MaxCap verifies that buffer growth respects the configured max.
func TestAutoTune_MaxCap(t *testing.T) {
	initialBuf := 2048
	maxBuf := 4096 // only allows one doubling

	ch, s, h := setupStack(t,
		tcp.WithReadBufferSize(initialBuf),
		tcp.WithMaxReadBufferSize(maxBuf),
	)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60002)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Establish RTT.
	go func() { conn.Write([]byte("ping")) }()
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected server data")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	dataEnd := dataHdr.SequenceNumber() + 4
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, dataEnd, 65535, nil)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond)

	// Continuous reader to prevent buffer saturation.
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

	// Send multiple rounds of data to trigger repeated growth attempts.
	clientSeq := clientISN + 1
	for round := 0; round < 5; round++ {
		for i := 0; i < 8; i++ {
			chunk := make([]byte, 512)
			pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
				header.TCPFlagACK, clientSeq, dataEnd, 65535, chunk)
			ch.Inject(pkt)
			clientSeq += 512
		}
		for {
			r := ch.Read(50 * time.Millisecond)
			if r == nil {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	cap := tcp.ReadBufCap(conn)
	if cap > maxBuf {
		t.Errorf("buffer exceeded max: cap=%d, max=%d", cap, maxBuf)
	}
	_ = serverISN
}

// TestAutoTune_NoGrowthOnLowUtilization verifies that the buffer does not
// grow when throughput is below the 50% threshold.
func TestAutoTune_NoGrowthOnLowUtilization(t *testing.T) {
	initialBuf := 4096
	maxBuf := 16384

	ch, s, h := setupStack(t,
		tcp.WithReadBufferSize(initialBuf),
		tcp.WithMaxReadBufferSize(maxBuf),
	)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(60003)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Establish RTT.
	go func() { conn.Write([]byte("ping")) }()
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected server data")
	}
	_, dataHdr := parseTCPResponse(t, raw)
	dataEnd := dataHdr.SequenceNumber() + 4
	ack := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, dataEnd, 65535, nil)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond)

	// Send only a small amount of data (< 50% of 4096 = 2048) per window.
	clientSeq := clientISN + 1
	for round := 0; round < 3; round++ {
		// Send 100 bytes — well below 50% threshold.
		smallData := make([]byte, 100)
		pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientSeq, dataEnd, 65535, smallData)
		ch.Inject(pkt)
		clientSeq += uint32(len(smallData))
		// Wait for measurement window + buffer to be processed.
		time.Sleep(200 * time.Millisecond)
	}

	cap := tcp.ReadBufCap(conn)
	if cap != initialBuf {
		t.Errorf("buffer should not have grown: cap=%d, initial=%d", cap, initialBuf)
	}
	_ = serverISN
}

// TestRingBuffer_Grow verifies that ringBuffer.Grow preserves unread data.
func TestRingBuffer_Grow(t *testing.T) {
	rb := tcp.NewRingBufferExported(8)

	// Write some data.
	data := []byte("hello")
	n := rb.WriteNoBlock(data)
	if n != 5 {
		t.Fatalf("wrote %d, want 5", n)
	}

	// Read 2 bytes (advance read pointer).
	buf := make([]byte, 2)
	n = rb.ReadNoBlock(buf)
	if n != 2 || string(buf) != "he" {
		t.Fatalf("read %d bytes %q, want 2 'he'", n, buf)
	}

	// Now buffer has "llo" (3 bytes unread), capacity 8.
	if rb.Len() != 3 {
		t.Fatalf("len = %d, want 3", rb.Len())
	}

	// Grow to 16.
	rb.Grow(16)

	if rb.Cap() != 16 {
		t.Errorf("cap = %d, want 16", rb.Cap())
	}
	if rb.Len() != 3 {
		t.Errorf("len after grow = %d, want 3 (data preserved)", rb.Len())
	}

	// Read remaining data — should be "llo".
	buf = make([]byte, 10)
	n = rb.ReadNoBlock(buf)
	if n != 3 || string(buf[:n]) != "llo" {
		t.Errorf("after grow, read %d bytes %q, want 3 'llo'", n, buf[:n])
	}
}

// TestRingBuffer_GrowWraparound verifies Grow works when data wraps around.
func TestRingBuffer_GrowWraparound(t *testing.T) {
	rb := tcp.NewRingBufferExported(8)

	// Fill buffer completely.
	data := []byte("12345678")
	n := rb.WriteNoBlock(data)
	if n != 8 {
		t.Fatalf("wrote %d, want 8", n)
	}

	// Read 5 bytes (advances r to 5).
	buf := make([]byte, 5)
	n = rb.ReadNoBlock(buf)
	if n != 5 || string(buf) != "12345" {
		t.Fatalf("read %q, want '12345'", buf[:n])
	}

	// Write 3 more bytes (wraps around).
	n = rb.WriteNoBlock([]byte("abc"))
	if n != 3 {
		t.Fatalf("wrote %d after read, want 3", n)
	}

	// Buffer now has "678abc" (6 bytes), with wrap-around.
	if rb.Len() != 6 {
		t.Fatalf("len = %d, want 6", rb.Len())
	}

	// Grow to 16.
	rb.Grow(16)

	if rb.Cap() != 16 {
		t.Errorf("cap = %d, want 16", rb.Cap())
	}
	if rb.Len() != 6 {
		t.Errorf("len = %d, want 6", rb.Len())
	}

	// Read all data.
	buf = make([]byte, 16)
	n = rb.ReadNoBlock(buf)
	if n != 6 || string(buf[:n]) != "678abc" {
		t.Errorf("after grow, read %q, want '678abc'", buf[:n])
	}
}

// TestRingBuffer_GrowNoOp verifies Grow is a no-op when newCap <= current capacity.
func TestRingBuffer_GrowNoOp(t *testing.T) {
	rb := tcp.NewRingBufferExported(16)
	rb.WriteNoBlock([]byte("test"))

	rb.Grow(8) // smaller — should be no-op
	if rb.Cap() != 16 {
		t.Errorf("cap = %d, want 16 (no-op)", rb.Cap())
	}
	if rb.Len() != 4 {
		t.Errorf("len = %d, want 4", rb.Len())
	}
}
