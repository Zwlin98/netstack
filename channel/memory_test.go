package channel

import (
	"testing"
	"time"
)

func TestMemoryInjectReadPacket(t *testing.T) {
	ch := NewMemory(1500)
	defer ch.Close()

	data := []byte{0x45, 0x00, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04}
	ch.Inject(data)

	buf := make([]byte, 1500)
	n, err := ch.ReadPacket(buf)
	if err != nil {
		t.Fatalf("ReadPacket error: %v", err)
	}
	if n != len(data) {
		t.Fatalf("ReadPacket n = %d, want %d", n, len(data))
	}
	for i := range data {
		if buf[i] != data[i] {
			t.Fatalf("byte %d: got 0x%02x, want 0x%02x", i, buf[i], data[i])
		}
	}
}

func TestMemoryWritePacketRead(t *testing.T) {
	ch := NewMemory(1500)
	defer ch.Close()

	data := []byte{0xAA, 0xBB, 0xCC}
	if err := ch.WritePacket(data); err != nil {
		t.Fatalf("WritePacket error: %v", err)
	}

	got := ch.Read(time.Second)
	if got == nil {
		t.Fatal("Read returned nil, expected packet")
	}
	if len(got) != len(data) {
		t.Fatalf("Read len = %d, want %d", len(got), len(data))
	}
	for i := range data {
		if got[i] != data[i] {
			t.Fatalf("byte %d: got 0x%02x, want 0x%02x", i, got[i], data[i])
		}
	}
}

func TestMemoryWritePacketCopiesData(t *testing.T) {
	ch := NewMemory(1500)
	defer ch.Close()

	data := []byte{0x01, 0x02, 0x03}
	if err := ch.WritePacket(data); err != nil {
		t.Fatal(err)
	}

	// Modify original data.
	data[0] = 0xFF

	got := ch.Read(time.Second)
	if got[0] != 0x01 {
		t.Error("WritePacket should copy data, not reference original")
	}
}

func TestMemoryInjectCopiesData(t *testing.T) {
	ch := NewMemory(1500)
	defer ch.Close()

	data := []byte{0x01, 0x02}
	ch.Inject(data)

	// Modify original.
	data[0] = 0xFF

	buf := make([]byte, 1500)
	n, _ := ch.ReadPacket(buf)
	if buf[0] != 0x01 {
		t.Errorf("Inject should copy data; got 0x%02x after modification", buf[:n][0])
	}
}

func TestMemoryCloseUnblocksReadPacket(t *testing.T) {
	ch := NewMemory(1500)

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		_, err := ch.ReadPacket(buf)
		done <- err
	}()

	// Give goroutine time to block.
	time.Sleep(50 * time.Millisecond)
	ch.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Error("ReadPacket should return error after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("ReadPacket did not unblock after Close")
	}
}

func TestMemoryWritePacketAfterClose(t *testing.T) {
	ch := NewMemory(1500)
	ch.Close()

	err := ch.WritePacket([]byte{0x01})
	if err == nil {
		t.Error("WritePacket after Close should return error")
	}
}

func TestMemoryReadTimeout(t *testing.T) {
	ch := NewMemory(1500)
	defer ch.Close()

	got := ch.Read(50 * time.Millisecond)
	if got != nil {
		t.Error("Read should return nil on timeout")
	}
}

func TestMemoryMTU(t *testing.T) {
	ch := NewMemory(1400)
	defer ch.Close()

	if ch.MTU() != 1400 {
		t.Errorf("MTU() = %d, want 1400", ch.MTU())
	}
}

func TestMemoryDoubleClose(t *testing.T) {
	ch := NewMemory(1500)
	if err := ch.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := ch.Close(); err != nil {
		t.Fatalf("second Close should not error: %v", err)
	}
}
