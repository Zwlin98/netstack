package tcp

import (
	"io"
	"sync"
	"testing"
)

func TestRingBuffer_WriteRead(t *testing.T) {
	rb := newRingBuffer(16)
	done := make(chan struct{})

	data := []byte("hello world")
	n, err := rb.Write(data, done)
	if err != nil || n != len(data) {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(data))
	}

	buf := make([]byte, 32)
	n, err = rb.Read(buf, done)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello world" {
		t.Fatalf("Read = %q; want %q", buf[:n], "hello world")
	}
}

func TestRingBuffer_WrapAround(t *testing.T) {
	rb := newRingBuffer(8)
	done := make(chan struct{})

	// Fill and drain to advance r/w pointers.
	rb.Write([]byte("12345"), done)
	tmp := make([]byte, 5)
	rb.Read(tmp, done)

	// Now r=w=5. Write 6 bytes to wrap around.
	data := []byte("abcdef")
	n, err := rb.Write(data, done)
	if err != nil || n != 6 {
		t.Fatalf("Write = %d, %v; want 6, nil", n, err)
	}

	buf := make([]byte, 8)
	n, err = rb.Read(buf, done)
	if err != nil || string(buf[:n]) != "abcdef" {
		t.Fatalf("Read = %q, %v; want %q", buf[:n], err, "abcdef")
	}
}

func TestRingBuffer_LenFree(t *testing.T) {
	rb := newRingBuffer(16)
	done := make(chan struct{})

	if rb.Len() != 0 || rb.Free() != 16 {
		t.Fatalf("empty: Len=%d, Free=%d; want 0, 16", rb.Len(), rb.Free())
	}

	rb.Write([]byte("1234567890"), done) // 10 bytes
	if rb.Len() != 10 || rb.Free() != 6 {
		t.Fatalf("after write: Len=%d, Free=%d; want 10, 6", rb.Len(), rb.Free())
	}

	buf := make([]byte, 4)
	rb.Read(buf, done)
	if rb.Len() != 6 || rb.Free() != 10 {
		t.Fatalf("after read: Len=%d, Free=%d; want 6, 10", rb.Len(), rb.Free())
	}
}

func TestRingBuffer_Full(t *testing.T) {
	rb := newRingBuffer(4)
	done := make(chan struct{})

	n, err := rb.Write([]byte("abcd"), done)
	if err != nil || n != 4 {
		t.Fatalf("Write = %d, %v; want 4, nil", n, err)
	}
	if rb.Free() != 0 || rb.Len() != 4 {
		t.Fatalf("full: Free=%d, Len=%d; want 0, 4", rb.Free(), rb.Len())
	}
}

func TestRingBuffer_BlockingWriteUnblocksOnRead(t *testing.T) {
	rb := newRingBuffer(4)
	done := make(chan struct{})

	// Fill buffer.
	rb.Write([]byte("abcd"), done)

	var wg sync.WaitGroup
	wg.Go(func() {
		// This should block until space is available.
		n, err := rb.Write([]byte("ef"), done)
		if err != nil || n != 2 {
			t.Errorf("Write = %d, %v; want 2, nil", n, err)
		}
	})

	// Read to free space.
	buf := make([]byte, 4)
	rb.Read(buf, done)

	wg.Wait()
}

func TestRingBuffer_BlockingReadUnblocksOnWrite(t *testing.T) {
	rb := newRingBuffer(16)
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 5)
		n, err := rb.Read(buf, done)
		if err != nil || n != 5 {
			t.Errorf("Read = %d, %v; want 5, nil", n, err)
		}
	})

	rb.Write([]byte("hello"), done)
	wg.Wait()
}

func TestRingBuffer_CloseWrite_EOF(t *testing.T) {
	rb := newRingBuffer(16)
	done := make(chan struct{})

	rb.Write([]byte("data"), done)
	rb.CloseWrite()

	// Should be able to read remaining data.
	buf := make([]byte, 16)
	n, err := rb.Read(buf, done)
	if err != nil || string(buf[:n]) != "data" {
		t.Fatalf("Read = %q, %v; want %q, nil", buf[:n], err, "data")
	}

	// Next read should return EOF.
	n, err = rb.Read(buf, done)
	if err != io.EOF || n != 0 {
		t.Fatalf("Read after close = %d, %v; want 0, io.EOF", n, err)
	}
}

func TestRingBuffer_CloseWrite_UnblocksReader(t *testing.T) {
	rb := newRingBuffer(16)
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 16)
		_, err := rb.Read(buf, done)
		if err != io.EOF {
			t.Errorf("Read err = %v; want io.EOF", err)
		}
	})

	rb.CloseWrite()
	wg.Wait()
}

func TestRingBuffer_DoneUnblocksRead(t *testing.T) {
	rb := newRingBuffer(16)
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 16)
		_, err := rb.Read(buf, done)
		if err != errBufferClosed {
			t.Errorf("Read err = %v; want errBufferClosed", err)
		}
	})

	close(done)
	wg.Wait()
}

func TestRingBuffer_DoneUnblocksWrite(t *testing.T) {
	rb := newRingBuffer(4)
	done := make(chan struct{})

	// Fill buffer.
	rb.Write([]byte("abcd"), done)

	var wg sync.WaitGroup
	wg.Go(func() {
		_, err := rb.Write([]byte("more"), done)
		if err != errBufferClosed {
			t.Errorf("Write err = %v; want errBufferClosed", err)
		}
	})

	close(done)
	wg.Wait()
}

func TestRingBuffer_ReadNoBlock(t *testing.T) {
	rb := newRingBuffer(16)
	done := make(chan struct{})

	// ReadNoBlock on empty buffer returns 0.
	buf := make([]byte, 16)
	n := rb.ReadNoBlock(buf)
	if n != 0 {
		t.Fatalf("ReadNoBlock empty = %d; want 0", n)
	}

	rb.Write([]byte("test"), done)
	n = rb.ReadNoBlock(buf)
	if n != 4 || string(buf[:n]) != "test" {
		t.Fatalf("ReadNoBlock = %d, %q; want 4, %q", n, buf[:n], "test")
	}
}

func TestRingBuffer_ConcurrentReadWrite(t *testing.T) {
	rb := newRingBuffer(64)
	done := make(chan struct{})

	const total = 1024
	var wg sync.WaitGroup

	// Writer goroutine.
	wg.Go(func() {
		data := make([]byte, 7) // prime-sized to stress wrap-around
		for i := range data {
			data[i] = byte(i)
		}
		written := 0
		for written < total {
			chunk := min(len(data), total-written)
			n, err := rb.Write(data[:chunk], done)
			if err != nil {
				t.Errorf("Write err: %v", err)
				return
			}
			written += n
		}
		rb.CloseWrite()
	})

	// Reader goroutine.
	wg.Go(func() {
		buf := make([]byte, 11) // different prime
		totalRead := 0
		for {
			n, err := rb.Read(buf, done)
			totalRead += n
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("Read err: %v", err)
				return
			}
		}
		if totalRead != total {
			t.Errorf("totalRead = %d; want %d", totalRead, total)
		}
	})

	wg.Wait()
}
