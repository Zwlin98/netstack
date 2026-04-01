package packet

import "sync"
import "sync/atomic"

const (
	// MaxPayloadSize is the maximum payload size for a RefBuf.
	// Covers all MSS scenarios (Ethernet MTU 1500 - IP 20 - TCP 20 = 1460).
	MaxPayloadSize = 1500
)

// RefBuf is a reference-counted byte buffer backed by sync.Pool.
// It allows multiple holders (e.g. send path and retransmit queue) to share
// the same data without copying. The buffer is returned to the pool when
// the last reference is released via DecRef.
type RefBuf struct {
	buf [MaxPayloadSize]byte
	len int
	ref atomic.Int32
}

var refBufPool = sync.Pool{
	New: func() any {
		return &RefBuf{}
	},
}

// GetRefBuf obtains a RefBuf from the pool with refcount=1 and len=0.
func GetRefBuf() *RefBuf {
	rb := refBufPool.Get().(*RefBuf)
	rb.ref.Store(1)
	rb.len = 0
	return rb
}

// IncRef increments the reference count.
func (rb *RefBuf) IncRef() {
	rb.ref.Add(1)
}

// DecRef decrements the reference count. When it reaches zero the buffer
// is reset and returned to the pool.
func (rb *RefBuf) DecRef() {
	if rb.ref.Add(-1) == 0 {
		rb.len = 0
		refBufPool.Put(rb)
	}
}

// Buf returns the full backing array for writing data into.
func (rb *RefBuf) Buf() []byte {
	return rb.buf[:]
}

// Bytes returns the valid data region buf[:len].
func (rb *RefBuf) Bytes() []byte {
	return rb.buf[:rb.len]
}

// SetLen sets the number of valid bytes in the buffer.
func (rb *RefBuf) SetLen(n int) {
	rb.len = n
}

// Len returns the number of valid bytes.
func (rb *RefBuf) Len() int {
	return rb.len
}
