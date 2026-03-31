package tcp_test

import (
	"testing"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
)

// setKeepaliveTestParams overrides keepalive timing for fast tests
// and returns a cleanup function to restore defaults.
func setKeepaliveTestParams(idle, interval time.Duration, count int) func() {
	origIdle := tcp.KeepaliveIdle
	origInterval := tcp.KeepaliveInterval
	origCount := tcp.KeepaliveCount
	tcp.KeepaliveIdle = idle
	tcp.KeepaliveInterval = interval
	tcp.KeepaliveCount = count
	return func() {
		tcp.KeepaliveIdle = origIdle
		tcp.KeepaliveInterval = origInterval
		tcp.KeepaliveCount = origCount
	}
}

// TestKeepalive_IdleTimeoutTriggersProbe verifies that after the idle
// timeout, a keepalive probe is sent.
func TestKeepalive_IdleTimeoutTriggersProbe(t *testing.T) {
	restore := setKeepaliveTestParams(500*time.Millisecond, 200*time.Millisecond, 3)
	defer restore()

	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50030)
	serverPort := uint16(80)
	clientISN := uint32(1000)

	serverISN, _ := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Wait for keepalive probe (idle=500ms).
	probe := ch.Read(time.Second)
	if probe == nil {
		t.Fatal("expected keepalive probe after idle timeout, got nil")
	}
	_, probeHdr := parseTCPResponse(t, probe)
	if !probeHdr.Flags().Has(header.TCPFlagACK) {
		t.Errorf("probe should have ACK flag, got %s", probeHdr.Flags())
	}
	// Keepalive probe uses seq = snd.una - 1.
	expectedSeq := serverISN // snd.una = iss+1, probe seq = iss+1 - 1 = iss
	if probeHdr.SequenceNumber() != expectedSeq {
		t.Errorf("probe seq = %d, want %d (snd.una - 1)", probeHdr.SequenceNumber(), expectedSeq)
	}
	// Should have no data.
	dataLen := len(probe) - int(header.IPv4(probe).HeaderLength()) - int(probeHdr.DataOffset())
	if dataLen != 0 {
		t.Errorf("probe data length = %d, want 0", dataLen)
	}
}

// TestKeepalive_PeerResponseResetsProbes verifies that when the peer
// responds to a keepalive probe, the probe count is reset.
func TestKeepalive_PeerResponseResetsProbes(t *testing.T) {
	restore := setKeepaliveTestParams(300*time.Millisecond, 200*time.Millisecond, 3)
	defer restore()

	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50031)
	serverPort := uint16(80)
	clientISN := uint32(2000)

	serverISN, _ := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Wait for first probe.
	probe := ch.Read(time.Second)
	if probe == nil {
		t.Fatal("expected first keepalive probe")
	}

	// Respond with ACK.
	ack := buildTCPPacket(clientAddr, serverAddr, clientPort, serverPort,
		header.TCPFlagACK, clientISN+1, serverISN+1)
	ch.Inject(ack)

	// After the response, idle timer restarts. Wait for next probe.
	probe2 := ch.Read(time.Second)
	if probe2 == nil {
		t.Fatal("expected second keepalive probe after idle reset")
	}
	// Connection should still be alive.
}

// TestKeepalive_DeadPeerDetected verifies that after keepaliveCount
// unanswered probes, the connection is aborted with RST.
func TestKeepalive_DeadPeerDetected(t *testing.T) {
	restore := setKeepaliveTestParams(200*time.Millisecond, 100*time.Millisecond, 3)
	defer restore()

	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50032)
	serverPort := uint16(80)
	clientISN := uint32(3000)

	_, conn := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Don't respond to any probes. Drain all packets until we see RST.
	foundRST := false
	for i := 0; i < 10; i++ {
		raw := ch.Read(time.Second)
		if raw == nil {
			break
		}
		_, tcpHdr := parseTCPResponse(t, raw)
		if tcpHdr.Flags().Has(header.TCPFlagRST) {
			foundRST = true
			break
		}
	}
	if !foundRST {
		t.Fatal("expected RST after dead peer detection, but none received")
	}

	// Connection should be closed. Read should fail.
	buf := make([]byte, 10)
	_, err := conn.Read(buf)
	if err == nil {
		t.Error("expected Read to return error after keepalive abort")
	}
}

// TestKeepalive_ActivityResetsIdleTimer verifies that data transfer
// resets the keepalive idle timer.
func TestKeepalive_ActivityResetsIdleTimer(t *testing.T) {
	restore := setKeepaliveTestParams(500*time.Millisecond, 200*time.Millisecond, 3)
	defer restore()

	ch, s, h := setupStack(t)
	defer s.Stop()
	defer h.Close()

	clientAddr := tcpip.From4(10, 0, 0, 1)
	serverAddr := tcpip.From4(10, 0, 0, 2)
	clientPort := uint16(50033)
	serverPort := uint16(80)
	clientISN := uint32(4000)

	serverISN, _ := completeHandshake(t, ch, h, clientAddr, serverAddr, clientPort, serverPort, clientISN)

	// Send data at 300ms intervals (before 500ms idle timeout).
	for i := 0; i < 3; i++ {
		time.Sleep(300 * time.Millisecond)
		data := []byte("keepalive reset")
		pkt := buildTCPPacketWithData(clientAddr, serverAddr, clientPort, serverPort,
			header.TCPFlagACK, clientISN+1+uint32(i*len(data)), serverISN+1, 65535, data)
		ch.Inject(pkt)
		// Drain the ACK response.
		ch.Read(500 * time.Millisecond)
	}

	// After the last data, wait for idle timeout to fire.
	probe := ch.Read(time.Second)
	if probe == nil {
		t.Fatal("expected keepalive probe after data stopped")
	}
	_, probeHdr := parseTCPResponse(t, probe)
	if !probeHdr.Flags().Has(header.TCPFlagACK) {
		t.Errorf("expected ACK flag, got %s", probeHdr.Flags())
	}
}
