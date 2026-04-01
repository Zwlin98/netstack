package tcp

import (
	"errors"
	"io"
	"sync"
)

var errBufferClosed = errors.New("ring buffer closed")

// ringBuffer is a circular byte buffer with blocking Read/Write.
// Blocking is performed via channel select so callers can pass a done
// channel to unblock on connection close.
type ringBuffer struct {
	buf  []byte
	r, w int
	full bool

	mu       sync.Mutex
	notEmpty chan struct{} // signaled (closed+re-created) when data is written
	notFull  chan struct{} // signaled (closed+re-created) when data is read
	closed   bool         // CloseWrite sets this
}

func newRingBuffer(size int) *ringBuffer {
	return &ringBuffer{
		buf:      make([]byte, size),
		notEmpty: make(chan struct{}),
		notFull:  make(chan struct{}),
	}
}

// Cap returns the total buffer capacity.
func (rb *ringBuffer) Cap() int {
	return len(rb.buf)
}

// Len returns the number of bytes available for reading.
func (rb *ringBuffer) Len() int {
	rb.mu.Lock()
	n := rb.lenLocked()
	rb.mu.Unlock()
	return n
}

func (rb *ringBuffer) lenLocked() int {
	if rb.full {
		return len(rb.buf)
	}
	return (rb.w - rb.r + len(rb.buf)) % len(rb.buf)
}

// Free returns the number of bytes available for writing.
func (rb *ringBuffer) Free() int {
	rb.mu.Lock()
	n := len(rb.buf) - rb.lenLocked()
	rb.mu.Unlock()
	return n
}

// Write writes p into the buffer, blocking until space is available.
// Returns errBufferClosed if the buffer was closed.
// done is used to unblock when the connection is shutting down.
func (rb *ringBuffer) Write(p []byte, done <-chan struct{}) (int, error) {
	written := 0
	for written < len(p) {
		rb.mu.Lock()
		if rb.closed {
			rb.mu.Unlock()
			return written, errBufferClosed
		}
		free := len(rb.buf) - rb.lenLocked()
		if free == 0 {
			// Wait for space.
			notFull := rb.notFull
			rb.mu.Unlock()
			select {
			case <-notFull:
				continue
			case <-done:
				return written, errBufferClosed
			}
		}
		// Copy as much as we can.
		n := rb.writeLocked(p[written:], free)
		written += n
		// Signal readers.
		close(rb.notEmpty)
		rb.notEmpty = make(chan struct{})
		rb.mu.Unlock()
	}
	return written, nil
}

// writeLocked copies up to free bytes from p into the buffer.
// Caller must hold rb.mu.
func (rb *ringBuffer) writeLocked(p []byte, free int) int {
	n := min(len(p), free)
	// First chunk: w to end of buffer.
	first := min(len(rb.buf)-rb.w, n)
	copy(rb.buf[rb.w:rb.w+first], p[:first])
	// Second chunk: wrap around.
	second := n - first
	if second > 0 {
		copy(rb.buf[:second], p[first:n])
	}
	rb.w = (rb.w + n) % len(rb.buf)
	if rb.w == rb.r {
		rb.full = true
	}
	return n
}

// Read reads into p, blocking until data is available.
// Returns io.EOF when the buffer is closed and empty.
// done is used to unblock when the connection is shutting down.
func (rb *ringBuffer) Read(p []byte, done <-chan struct{}) (int, error) {
	for {
		rb.mu.Lock()
		n := rb.lenLocked()
		if n > 0 {
			copied := rb.readLocked(p, n)
			// Signal writers.
			close(rb.notFull)
			rb.notFull = make(chan struct{})
			rb.mu.Unlock()
			return copied, nil
		}
		if rb.closed {
			rb.mu.Unlock()
			return 0, io.EOF
		}
		notEmpty := rb.notEmpty
		rb.mu.Unlock()
		select {
		case <-notEmpty:
		case <-done:
			return 0, errBufferClosed
		}
	}
}

// ReadNoBlock reads available data into p without blocking.
// Returns the number of bytes read (may be 0).
func (rb *ringBuffer) ReadNoBlock(p []byte) int {
	rb.mu.Lock()
	n := rb.lenLocked()
	if n == 0 {
		rb.mu.Unlock()
		return 0
	}
	copied := rb.readLocked(p, n)
	close(rb.notFull)
	rb.notFull = make(chan struct{})
	rb.mu.Unlock()
	return copied
}

// readLocked copies up to len(p) bytes from the buffer.
// avail is the number of bytes in the buffer. Caller must hold rb.mu.
func (rb *ringBuffer) readLocked(p []byte, avail int) int {
	n := min(len(p), avail)
	// First chunk: r to end of buffer.
	first := min(len(rb.buf)-rb.r, n)
	copy(p[:first], rb.buf[rb.r:rb.r+first])
	// Second chunk: wrap around.
	second := n - first
	if second > 0 {
		copy(p[first:n], rb.buf[:second])
	}
	rb.r = (rb.r + n) % len(rb.buf)
	rb.full = false
	return n
}

// WriteNoBlock writes as much of p as fits without blocking.
// Returns the number of bytes written.
func (rb *ringBuffer) WriteNoBlock(p []byte) int {
	rb.mu.Lock()
	if rb.closed {
		rb.mu.Unlock()
		return 0
	}
	free := len(rb.buf) - rb.lenLocked()
	if free == 0 {
		rb.mu.Unlock()
		return 0
	}
	n := rb.writeLocked(p, free)
	close(rb.notEmpty)
	rb.notEmpty = make(chan struct{})
	rb.mu.Unlock()
	return n
}

// Grow resizes the buffer to newCap, preserving unread data.
// If newCap <= current capacity, this is a no-op.
func (rb *ringBuffer) Grow(newCap int) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	oldCap := len(rb.buf)
	if newCap <= oldCap {
		return
	}

	used := rb.lenLocked()
	newBuf := make([]byte, newCap)

	// Copy unread data into the new buffer starting at position 0.
	if used > 0 {
		if rb.r < rb.w || (rb.full && rb.r == rb.w) {
			// Data is contiguous or buffer is full.
			if rb.full || rb.r < rb.w {
				if rb.r < rb.w {
					copy(newBuf, rb.buf[rb.r:rb.w])
				} else {
					// Full buffer: r == w. Copy from r to end, then 0 to w.
					n := copy(newBuf, rb.buf[rb.r:])
					copy(newBuf[n:], rb.buf[:rb.w])
				}
			}
		} else {
			// Data wraps around: copy r..end, then 0..w.
			n := copy(newBuf, rb.buf[rb.r:])
			copy(newBuf[n:], rb.buf[:rb.w])
		}
	}

	rb.buf = newBuf
	rb.r = 0
	rb.w = used
	rb.full = false

	// Signal writers that space is available.
	close(rb.notFull)
	rb.notFull = make(chan struct{})
}

// CloseWrite signals that no more data will be written.
// Subsequent Read calls will return io.EOF once the buffer is drained.
func (rb *ringBuffer) CloseWrite() {
	rb.mu.Lock()
	rb.closed = true
	close(rb.notEmpty)
	rb.notEmpty = make(chan struct{})
	rb.mu.Unlock()
}
