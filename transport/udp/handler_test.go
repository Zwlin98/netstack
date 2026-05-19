package udp

import (
	"bytes"
	"runtime"
	"testing"
	"time"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
)

// buildUDPPacket constructs a valid IPv4+UDP packet.
func buildUDPPacket(src, dst tcpip.Address, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := uint16(header.UDPHeaderSize + len(payload))
	totalLen := header.IPv4MinHeaderSize + int(udpLen)
	buf := make([]byte, totalLen)

	// IPv4 header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    tcpip.UDPProtocolNumber,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(header.Checksum(buf[:header.IPv4MinHeaderSize], 0))

	// UDP header.
	udpBuf := buf[header.IPv4MinHeaderSize:]
	udpHdr := header.UDP(udpBuf)
	udpHdr.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  udpLen,
	})
	copy(udpBuf[header.UDPHeaderSize:], payload)

	// UDP checksum.
	udpHdr.SetChecksum(0)
	phc := header.PseudoHeaderChecksum(tcpip.UDPProtocolNumber, src, dst, udpLen)
	udpHdr.SetChecksum(header.Checksum(udpBuf[:udpLen], phc))

	return buf
}

func setupStack() (*stack.Stack, *channel.MemoryChannel, *UDPHandler) {
	ch := channel.NewMemory(1500)
	s := stack.New(ch)
	h := NewUDPHandler(s)
	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()
	return s, ch, h
}

func TestReadFrom(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)
	payload := []byte("hello udp")
	pkt := buildUDPPacket(src, dst, 12345, 53, payload)
	ch.Inject(pkt)

	buf := make([]byte, 1500)
	n, gotSrc, gotDst, err := h.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}

	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("payload = %q, want %q", buf[:n], payload)
	}
	if gotSrc.Addr != src || gotSrc.Port != 12345 {
		t.Errorf("src = %s:%d, want %s:12345", gotSrc.Addr, gotSrc.Port, src)
	}
	if gotDst.Addr != dst || gotDst.Port != 53 {
		t.Errorf("dst = %s:%d, want %s:53", gotDst.Addr, gotDst.Port, dst)
	}
}

func TestWriteTo(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.FullAddress{Addr: tcpip.From4(8, 8, 8, 8), Port: 53}
	dst := tcpip.FullAddress{Addr: tcpip.From4(10, 0, 0, 1), Port: 12345}
	payload := []byte("dns response")

	n, err := h.WriteTo(payload, src, dst)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo returned %d, want %d", n, len(payload))
	}

	// Read the packet from channel.
	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected packet on channel")
	}

	// Validate IPv4 header.
	ip := header.IPv4(raw)
	if ip.SourceAddress() != src.Addr {
		t.Errorf("IP src = %s, want %s", ip.SourceAddress(), src.Addr)
	}
	if ip.DestinationAddress() != dst.Addr {
		t.Errorf("IP dst = %s, want %s", ip.DestinationAddress(), dst.Addr)
	}

	// Validate UDP header.
	udpHdr := header.UDP(raw[ip.HeaderLength():])
	if udpHdr.SourcePort() != src.Port {
		t.Errorf("UDP src port = %d, want %d", udpHdr.SourcePort(), src.Port)
	}
	if udpHdr.DestinationPort() != dst.Port {
		t.Errorf("UDP dst port = %d, want %d", udpHdr.DestinationPort(), dst.Port)
	}

	// Validate payload.
	got := udpHdr.Payload()
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

func TestReadFromBlocksUntilPacket(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	done := make(chan struct{})
	var n int
	var err error
	buf := make([]byte, 1500)

	go func() {
		n, _, _, err = h.ReadFrom(buf)
		close(done)
	}()

	// Ensure ReadFrom is blocking.
	select {
	case <-done:
		t.Fatal("ReadFrom should block when no data")
	case <-time.After(50 * time.Millisecond):
	}

	// Inject a packet to unblock.
	payload := []byte("wake up")
	pkt := buildUDPPacket(tcpip.From4(10, 0, 0, 1), tcpip.From4(8, 8, 8, 8), 1000, 53, payload)
	ch.Inject(pkt)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ReadFrom did not unblock after packet injection")
	}

	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("payload = %q, want %q", buf[:n], payload)
	}
}

func TestReadFromUnblocksOnClose(t *testing.T) {
	s, ch, _ := setupStack()
	_ = ch
	defer s.Stop()

	h := NewUDPHandler(s)
	errCh := make(chan error, 1)

	go func() {
		buf := make([]byte, 1500)
		_, _, _, err := h.ReadFrom(buf)
		errCh <- err
	}()

	// Let ReadFrom block.
	time.Sleep(50 * time.Millisecond)
	h.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReadFrom should return error after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFrom did not unblock after Close")
	}
}

func TestQueueBackpressure(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)

	// Fill the queue beyond capacity.
	for i := 0; i < defaultConfig.InboundQueueSize+10; i++ {
		pkt := buildUDPPacket(src, dst, uint16(1000+i), 53, []byte("x"))
		ch.Inject(pkt)
	}

	// Wait for processing.
	time.Sleep(200 * time.Millisecond)

	// Should be able to drain exactly defaultConfig.InboundQueueSize items.
	count := 0
	for {
		buf := make([]byte, 1500)
		done := make(chan struct{})
		var err error
		go func() {
			_, _, _, err = h.ReadFrom(buf)
			close(done)
		}()

		select {
		case <-done:
			if err != nil {
				break
			}
			count++
		case <-time.After(100 * time.Millisecond):
			goto out
		}
	}
out:
	if count != defaultConfig.InboundQueueSize {
		t.Errorf("drained %d datagrams, want %d", count, defaultConfig.InboundQueueSize)
	}
}

func TestWriteToAfterClose(t *testing.T) {
	s, _, h := setupStack()
	defer s.Stop()

	h.Close()

	_, err := h.WriteTo([]byte("data"), tcpip.FullAddress{}, tcpip.FullAddress{})
	if err == nil {
		t.Fatal("WriteTo should return error after Close")
	}
}

func TestNoGoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	ch := channel.NewMemory(1500)
	s := stack.New(ch)
	h := NewUDPHandler(s)
	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()

	// Inject a packet and read it.
	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)
	pkt := buildUDPPacket(src, dst, 12345, 53, []byte("test"))
	ch.Inject(pkt)

	buf := make([]byte, 1500)
	h.ReadFrom(buf)

	// Shut down.
	h.Close()
	s.Stop()

	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	after := runtime.NumGoroutine()
	if after > before+1 {
		t.Errorf("goroutine leak: before=%d, after=%d", before, after)
	}
}

func TestWriteToMTUSizedPayload(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.FullAddress{Addr: tcpip.From4(8, 8, 8, 8), Port: 53}
	dst := tcpip.FullAddress{Addr: tcpip.From4(10, 0, 0, 1), Port: 12345}

	// Exactly one MTU-sized UDP payload: MTU(1500) - IPv4(20) - UDP(8) = 1472.
	payload := make([]byte, 1472)
	for i := range payload {
		payload[i] = byte(i)
	}

	n, err := h.WriteTo(payload, src, dst)
	if err != nil {
		t.Fatalf("WriteTo with MTU-sized payload: %v", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo returned %d, want %d", n, len(payload))
	}

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected packet on channel")
	}

	ip := header.IPv4(raw)
	udpHdr := header.UDP(raw[ip.HeaderLength():])
	got := udpHdr.Payload()
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestWriteToMaxIPv4Payload(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.FullAddress{Addr: tcpip.From4(8, 8, 8, 8), Port: 53}
	dst := tcpip.FullAddress{Addr: tcpip.From4(10, 0, 0, 1), Port: 12345}
	payload := make([]byte, maxIPv4UDPPayload)
	for i := range payload {
		payload[i] = byte(i)
	}

	n, err := h.WriteTo(payload, src, dst)
	if err != nil {
		t.Fatalf("WriteTo with max IPv4 UDP payload: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo returned %d, want %d", n, len(payload))
	}

	udpPacket := readFragmentedUDPFromMemory(t, ch)
	validateOutboundUDPPacket(t, udpPacket, src, dst, payload)
}

func TestWriteToOversized(t *testing.T) {
	s, _, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.FullAddress{Addr: tcpip.From4(8, 8, 8, 8), Port: 53}
	dst := tcpip.FullAddress{Addr: tcpip.From4(10, 0, 0, 1), Port: 12345}

	// One byte over the IPv4 UDP payload limit.
	payload := make([]byte, maxIPv4UDPPayload+1)
	n, err := h.WriteTo(payload, src, dst)
	if err != ErrMessageTooLong {
		t.Fatalf("WriteTo returned error %v, want ErrMessageTooLong", err)
	}
	if n != 0 {
		t.Errorf("WriteTo returned n=%d, want 0", n)
	}
}

func TestWriteToLargeFragmentsWithoutGSO(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.FullAddress{Addr: tcpip.From4(8, 8, 8, 8), Port: 53}
	dst := tcpip.FullAddress{Addr: tcpip.From4(10, 0, 0, 1), Port: 12345}
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}

	n, err := h.WriteTo(payload, src, dst)
	if err != nil {
		t.Fatalf("WriteTo large payload: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo returned %d, want %d", n, len(payload))
	}

	udpPacket := readFragmentedUDPFromMemory(t, ch)
	validateOutboundUDPPacket(t, udpPacket, src, dst, payload)
}

func readFragmentedUDPFromMemory(t *testing.T, ch *channel.MemoryChannel) []byte {
	t.Helper()

	var udpPacket []byte
	var id uint16
	for i := 0; ; i++ {
		frag := ch.Read(time.Second)
		if frag == nil {
			t.Fatalf("timed out waiting for fragment %d", i)
		}
		if len(frag) > 1500 {
			t.Fatalf("fragment %d len = %d, want <= MTU", i, len(frag))
		}

		ip := header.IPv4(frag)
		hdrLen := ip.HeaderLength()
		if header.Checksum(frag[:hdrLen], 0) != 0 {
			t.Fatalf("fragment %d IPv4 checksum invalid", i)
		}
		if i == 0 {
			id = ip.ID()
		} else if ip.ID() != id {
			t.Fatalf("fragment %d ID = 0x%04x, want 0x%04x", i, ip.ID(), id)
		}
		if got, want := int(ip.FragmentOffset())*8, len(udpPacket); got != want {
			t.Fatalf("fragment %d offset = %d, want %d", i, got, want)
		}

		udpPacket = append(udpPacket, frag[hdrLen:]...)
		if !ip.More() {
			break
		}
	}
	return udpPacket
}

func validateOutboundUDPPacket(t *testing.T, udpPacket []byte, src, dst tcpip.FullAddress, payload []byte) {
	t.Helper()

	udpHdr := header.UDP(udpPacket)
	if udpHdr.SourcePort() != src.Port || udpHdr.DestinationPort() != dst.Port {
		t.Fatalf("UDP ports = %d -> %d, want %d -> %d", udpHdr.SourcePort(), udpHdr.DestinationPort(), src.Port, dst.Port)
	}
	if got, want := int(udpHdr.Length()), header.UDPHeaderSize+len(payload); got != want {
		t.Fatalf("UDP length = %d, want %d", got, want)
	}
	if !bytes.Equal(udpHdr.Payload(), payload) {
		t.Fatalf("UDP payload mismatch: got %d bytes want %d", len(udpHdr.Payload()), len(payload))
	}
	phc := header.PseudoHeaderChecksum(tcpip.UDPProtocolNumber, src.Addr, dst.Addr, uint16(len(udpPacket)))
	if header.Checksum(udpPacket, phc) != 0 {
		t.Fatal("UDP checksum invalid after reassembly")
	}
}

type udpGSOWriterTestChannel struct {
	*channel.MemoryChannel
	gsoCh chan udpGSOCapture
}

type udpGSOCapture struct {
	data []byte
	opts channel.PacketOptions
}

func newUDPGSOWriterTestChannel(mtu int) *udpGSOWriterTestChannel {
	return &udpGSOWriterTestChannel{
		MemoryChannel: channel.NewMemory(mtu),
		gsoCh:         make(chan udpGSOCapture, 16),
	}
}

func (c *udpGSOWriterTestChannel) WritePacketGSO(data []byte, opts channel.PacketOptions) error {
	pkt := make([]byte, len(data))
	copy(pkt, data)
	c.gsoCh <- udpGSOCapture{data: pkt, opts: opts}
	return nil
}

func (c *udpGSOWriterTestChannel) GSOEnabled() bool { return true }
func (c *udpGSOWriterTestChannel) GSOMaxSize() int  { return maxIPv4UDPPayload }

func (c *udpGSOWriterTestChannel) readGSO(timeout time.Duration) *udpGSOCapture {
	select {
	case cap := <-c.gsoCh:
		return &cap
	case <-time.After(timeout):
		return nil
	}
}

func TestWriteToLargeFragmentsWithGSOWriter(t *testing.T) {
	ch := newUDPGSOWriterTestChannel(1500)
	s := stack.New(ch)
	h := NewUDPHandler(s)
	s.RegisterHandler(tcpip.UDPProtocolNumber, h)
	s.Start()
	defer s.Stop()
	defer h.Close()

	src := tcpip.FullAddress{Addr: tcpip.From4(8, 8, 8, 8), Port: 53}
	dst := tcpip.FullAddress{Addr: tcpip.From4(10, 0, 0, 1), Port: 12345}
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(255 - i)
	}

	n, err := h.WriteTo(payload, src, dst)
	if err != nil {
		t.Fatalf("WriteTo large payload: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo returned %d, want %d", n, len(payload))
	}

	var udpPacket []byte
	var id uint16
	for i := 0; ; i++ {
		cap := ch.readGSO(time.Second)
		if cap == nil {
			t.Fatalf("timed out waiting for fragment %d", i)
		}
		if cap.opts.GSOType != channel.GSONone {
			t.Fatalf("fragment %d GSOType = 0x%02x, want GSONone", i, cap.opts.GSOType)
		}
		if len(cap.data) > 1500 {
			t.Fatalf("fragment %d len = %d, want <= MTU", i, len(cap.data))
		}

		ip := header.IPv4(cap.data)
		hdrLen := ip.HeaderLength()
		if i == 0 {
			id = ip.ID()
		} else if ip.ID() != id {
			t.Fatalf("fragment %d ID = 0x%04x, want 0x%04x", i, ip.ID(), id)
		}
		if got, want := int(ip.FragmentOffset())*8, len(udpPacket); got != want {
			t.Fatalf("fragment %d offset = %d, want %d", i, got, want)
		}

		udpPacket = append(udpPacket, cap.data[hdrLen:]...)
		if !ip.More() {
			break
		}
	}

	udpHdr := header.UDP(udpPacket)
	if udpHdr.SourcePort() != src.Port || udpHdr.DestinationPort() != dst.Port {
		t.Fatalf("UDP ports = %d -> %d, want %d -> %d", udpHdr.SourcePort(), udpHdr.DestinationPort(), src.Port, dst.Port)
	}
	if got, want := int(udpHdr.Length()), header.UDPHeaderSize+len(payload); got != want {
		t.Fatalf("UDP length = %d, want %d", got, want)
	}
	if !bytes.Equal(udpHdr.Payload(), payload) {
		t.Fatalf("UDP payload mismatch: got %d bytes want %d", len(udpHdr.Payload()), len(payload))
	}
	phc := header.PseudoHeaderChecksum(tcpip.UDPProtocolNumber, src.Addr, dst.Addr, uint16(len(udpPacket)))
	if header.Checksum(udpPacket, phc) != 0 {
		t.Fatal("UDP checksum invalid after reassembly")
	}
}

func TestWriteToEmptyPayload(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.FullAddress{Addr: tcpip.From4(8, 8, 8, 8), Port: 53}
	dst := tcpip.FullAddress{Addr: tcpip.From4(10, 0, 0, 1), Port: 12345}

	n, err := h.WriteTo([]byte{}, src, dst)
	if err != nil {
		t.Fatalf("WriteTo with empty payload: %v", err)
	}
	if n != 0 {
		t.Errorf("WriteTo returned %d, want 0", n)
	}

	raw := ch.Read(time.Second)
	if raw == nil {
		t.Fatal("expected packet on channel")
	}
}

func TestWriteToOversizedStats(t *testing.T) {
	s, _, h := setupStack()
	defer s.Stop()
	defer h.Close()

	st := h.EnableStats()

	src := tcpip.FullAddress{Addr: tcpip.From4(8, 8, 8, 8), Port: 53}
	dst := tcpip.FullAddress{Addr: tcpip.From4(10, 0, 0, 1), Port: 12345}

	payload := make([]byte, maxIPv4UDPPayload+1)
	h.WriteTo(payload, src, dst)
	h.WriteTo(payload, src, dst)

	if got := st.OversizedOut.Load(); got != 2 {
		t.Errorf("OversizedOut = %d, want 2", got)
	}
	if got := st.DatagramsOut.Load(); got != 0 {
		t.Errorf("DatagramsOut = %d, want 0", got)
	}
}

func TestMultipleDatagrams(t *testing.T) {
	s, ch, h := setupStack()
	defer s.Stop()
	defer h.Close()

	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(8, 8, 8, 8)

	payloads := []string{"first", "second", "third"}
	for _, p := range payloads {
		pkt := buildUDPPacket(src, dst, 12345, 53, []byte(p))
		ch.Inject(pkt)
	}

	// Wait for all packets to be processed.
	time.Sleep(100 * time.Millisecond)

	for _, want := range payloads {
		buf := make([]byte, 1500)
		n, _, _, err := h.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		if string(buf[:n]) != want {
			t.Errorf("payload = %q, want %q", string(buf[:n]), want)
		}
	}
}
