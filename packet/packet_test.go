package packet

import (
	"testing"
)

// --- Receive path tests ---

func TestNewPacketBufferWithData(t *testing.T) {
	raw := []byte{
		// Fake IPv4 header (20 bytes)
		0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
		0xc0, 0xa8, 0x01, 0x02,
		// Fake TCP header (20 bytes)
		0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00,
		// Payload
		'H', 'e', 'l', 'l', 'o',
	}

	pb := NewPacketBufferWithData(raw)
	defer pb.Release()

	// Manually slice out headers (simulating what a network layer would do).
	pb.NetworkHeader = pb.Data[:20]
	pb.TransportHeader = pb.Data[20:40]
	pb.Data = pb.Data[40:]

	// Verify data content.
	if string(pb.Data) != "Hello" {
		t.Errorf("Data = %q, want %q", pb.Data, "Hello")
	}

	// Verify headers.
	if len(pb.NetworkHeader) != 20 {
		t.Errorf("NetworkHeader len = %d, want 20", len(pb.NetworkHeader))
	}
	if len(pb.TransportHeader) != 20 {
		t.Errorf("TransportHeader len = %d, want 20", len(pb.TransportHeader))
	}
}

func TestReceivePathZeroCopy(t *testing.T) {
	raw := make([]byte, 45)
	for i := range raw {
		raw[i] = byte(i)
	}

	pb := NewPacketBufferWithData(raw)
	defer pb.Release()

	pb.NetworkHeader = pb.Data[:20]
	pb.TransportHeader = pb.Data[20:40]
	pb.Data = pb.Data[40:]

	// Verify all views share the same backing array by modifying through one
	// and checking through another.
	pb.NetworkHeader[0] = 0xFF
	if pb.Buf()[0] != 0xFF {
		t.Error("NetworkHeader should share backing array with buf")
	}

	pb.TransportHeader[0] = 0xAA
	if pb.Buf()[20] != 0xAA {
		t.Error("TransportHeader should share backing array with buf")
	}

	pb.Data[0] = 0xBB
	if pb.Buf()[40] != 0xBB {
		t.Error("Data should share backing array with buf")
	}
}

// --- Send path tests ---

func TestSendPathPrepend(t *testing.T) {
	ipHdrSize := 20
	tcpHdrSize := 20
	headroom := ipHdrSize

	pb := NewPacketBuffer(headroom)
	defer pb.Release()

	// Write payload into the data area.
	payload := []byte("Hello, World!")
	pb.Data = pb.buf[headroom : headroom+len(payload)]
	copy(pb.Data, payload)

	// Prepend IP header.
	ipSlice := pb.Prepend(ipHdrSize)
	for i := range ipSlice {
		ipSlice[i] = byte(0x40 + i) // fake IP header bytes
	}
	pb.NetworkHeader = ipSlice

	// Verify AsSlice contains IP header + payload.
	result := pb.AsSlice()
	if len(result) != ipHdrSize+len(payload) {
		t.Fatalf("AsSlice() len = %d, want %d", len(result), ipHdrSize+len(payload))
	}

	// First bytes should be IP header.
	if result[0] != 0x40 {
		t.Errorf("first byte = 0x%02x, want 0x40", result[0])
	}

	// Payload should follow.
	gotPayload := string(result[ipHdrSize:])
	if gotPayload != "Hello, World!" {
		t.Errorf("payload = %q, want %q", gotPayload, "Hello, World!")
	}

	_ = tcpHdrSize // used in concept; for this test we only prepend IP
}

func TestSendPathMultiplePrepend(t *testing.T) {
	ipHdrSize := 20
	tcpHdrSize := 20
	headroom := ipHdrSize + tcpHdrSize

	pb := NewPacketBuffer(headroom)
	defer pb.Release()

	// Write payload.
	payload := []byte("data")
	pb.Data = pb.buf[headroom : headroom+len(payload)]
	copy(pb.Data, payload)

	// Prepend TCP header first (inner).
	tcpSlice := pb.Prepend(tcpHdrSize)
	for i := range tcpSlice {
		tcpSlice[i] = byte(0xA0 + i)
	}
	pb.TransportHeader = tcpSlice

	// Prepend IP header (outer).
	ipSlice := pb.Prepend(ipHdrSize)
	for i := range ipSlice {
		ipSlice[i] = byte(0x40 + i)
	}
	pb.NetworkHeader = ipSlice

	result := pb.AsSlice()
	expectedLen := ipHdrSize + tcpHdrSize + len(payload)
	if len(result) != expectedLen {
		t.Fatalf("AsSlice() len = %d, want %d", len(result), expectedLen)
	}

	// Verify ordering: IP header, TCP header, payload.
	if result[0] != 0x40 {
		t.Errorf("IP hdr first byte = 0x%02x, want 0x40", result[0])
	}
	if result[ipHdrSize] != 0xA0 {
		t.Errorf("TCP hdr first byte = 0x%02x, want 0xA0", result[ipHdrSize])
	}
	if string(result[ipHdrSize+tcpHdrSize:]) != "data" {
		t.Errorf("payload = %q, want %q", result[ipHdrSize+tcpHdrSize:], "data")
	}
}

func TestAsSliceContiguous(t *testing.T) {
	headroom := 20
	pb := NewPacketBuffer(headroom)
	defer pb.Release()

	payload := []byte{0x01, 0x02, 0x03}
	pb.Data = pb.buf[headroom : headroom+len(payload)]
	copy(pb.Data, payload)

	hdr := pb.Prepend(headroom)
	for i := range hdr {
		hdr[i] = byte(0xF0 + i)
	}

	result := pb.AsSlice()

	// Should be contiguous from header start to data end.
	if len(result) != headroom+len(payload) {
		t.Fatalf("len = %d, want %d", len(result), headroom+len(payload))
	}

	// Modify through AsSlice and verify it affects the same memory.
	result[0] = 0xFF
	if hdr[0] != 0xFF {
		t.Error("AsSlice should share memory with Prepend result")
	}
}

// --- Pool tests ---

func TestPoolGetRelease(t *testing.T) {
	pb1 := NewPacketBuffer(20)
	pb1.NetworkHeader = pb1.buf[:20]
	pb1.TransportHeader = pb1.buf[20:40]
	pb1.Data = pb1.buf[40:50]

	// Save the buffer pointer for comparison.
	bufPtr := &pb1.buf[0]

	pb1.Release()

	// Get another buffer — it should reuse the released one.
	pb2 := NewPacketBuffer(20)
	defer pb2.Release()

	if &pb2.buf[0] != bufPtr {
		// This is expected behavior with sync.Pool but not guaranteed.
		// The pool may or may not reuse. We just verify the contract.
		t.Log("pool did not reuse buffer (this is acceptable with sync.Pool)")
	}
}

func TestReleaseClearsFields(t *testing.T) {
	pb := NewPacketBuffer(20)
	pb.NetworkHeader = pb.buf[:20]
	pb.TransportHeader = pb.buf[20:40]
	pb.Data = pb.buf[40:50]

	pb.Release()

	// Get the buffer back.
	pb2 := NewPacketBuffer(0)
	defer pb2.Release()

	// Fields should be cleared after reset.
	if pb2.NetworkHeader != nil {
		t.Error("NetworkHeader should be nil after reset")
	}
	if pb2.TransportHeader != nil {
		t.Error("TransportHeader should be nil after reset")
	}
	if pb2.Data != nil {
		t.Error("Data should be nil after reset")
	}
}

func TestPoolMultipleGetRelease(t *testing.T) {
	// Exercise several Get/Release cycles.
	for i := 0; i < 100; i++ {
		pb := NewPacketBuffer(20)
		pb.Data = pb.buf[20:30]
		copy(pb.Data, []byte("test"))
		pb.Release()
	}

	// Should not panic or leak.
	pb := NewPacketBuffer(0)
	defer pb.Release()
	if pb.Data != nil {
		t.Error("Data should be nil after fresh Get")
	}
}

func TestBuf(t *testing.T) {
	pb := NewPacketBuffer(20)
	defer pb.Release()

	buf := pb.Buf()
	if len(buf) != MaxPacketSize-20 {
		t.Errorf("Buf() len = %d, want %d", len(buf), MaxPacketSize-20)
	}
}
