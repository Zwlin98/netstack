package tcp_test

import (
	"sync"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
)

// TestLimitedTransmitSendsOnFirstTwoDupACKs verifies that 1st and 2nd dup ACKs
// each trigger sending one new segment (RFC 3042).
func TestLimitedTransmitSendsOnFirstTwoDupACKs(t *testing.T) {
	// Use small MTU so segments are small and cwnd fills up quickly.
	const maxPayload = 100
	mtu := header.IPv4MinHeaderSize + header.TCPMinHeaderSize + maxPayload
	ch, s, h := setupStackWithMTU(t, mtu)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(58000)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// IW = min(10*100, max(2*100, 14600)) = min(1000, 14600) = 1000 = 10 segments.
	// Write more than IW to have unsent data available for limited transmit.
	data := make([]byte, 2000) // 20 segments worth
	for i := range data {
		data[i] = byte(i)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		conn.Write(data)
	})

	// Read all initial segments (IW=10 segments).
	var firstEnd uint32
	segCount := 0
	for {
		raw := ch.Read(500 * time.Millisecond)
		if raw == nil {
			break
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		payload := raw[header.IPv4MinHeaderSize+tcpHdr.DataOffset():]
		if segCount == 0 {
			firstEnd = tcpHdr.SequenceNumber() + uint32(len(payload))
		}
		segCount++
	}

	if segCount < 10 {
		t.Fatalf("expected at least 10 initial segments, got %d", segCount)
	}

	// ACK first segment (advances UNA).
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, firstEnd)
	ch.Inject(ack)
	time.Sleep(50 * time.Millisecond)
	// Drain any new segments sent due to window opening.
	for {
		r := ch.Read(100 * time.Millisecond)
		if r == nil {
			break
		}
	}

	// 1st dup ACK → should trigger limited transmit (1 new segment).
	dupACK := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, firstEnd)
	ch.Inject(dupACK)
	time.Sleep(50 * time.Millisecond)

	lt1 := ch.Read(200 * time.Millisecond)
	if lt1 == nil {
		t.Fatal("expected limited transmit segment after 1st dup ACK")
	}

	// 2nd dup ACK → should trigger limited transmit (1 more new segment).
	ch.Inject(dupACK)
	time.Sleep(50 * time.Millisecond)

	lt2 := ch.Read(200 * time.Millisecond)
	if lt2 == nil {
		t.Fatal("expected limited transmit segment after 2nd dup ACK")
	}

	// Clean up.
	finalAck := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1+uint32(len(data)))
	ch.Inject(finalAck)
	drainPackets(ch, 200*time.Millisecond)

	wg.Wait()
	conn.ForceClose()
}
