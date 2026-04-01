package packet

import "testing"

func TestRefBufGetAndRelease(t *testing.T) {
	rb := GetRefBuf()
	if rb.Len() != 0 {
		t.Fatalf("new RefBuf Len = %d, want 0", rb.Len())
	}
	if len(rb.Bytes()) != 0 {
		t.Fatal("new RefBuf Bytes should be empty")
	}
	if len(rb.Buf()) != MaxPayloadSize {
		t.Fatalf("Buf() len = %d, want %d", len(rb.Buf()), MaxPayloadSize)
	}
	rb.DecRef() // should return to pool without panic
}

func TestRefBufSetLenAndBytes(t *testing.T) {
	rb := GetRefBuf()
	defer rb.DecRef()

	copy(rb.Buf(), []byte("hello"))
	rb.SetLen(5)

	if rb.Len() != 5 {
		t.Fatalf("Len = %d, want 5", rb.Len())
	}
	if string(rb.Bytes()) != "hello" {
		t.Fatalf("Bytes = %q, want %q", rb.Bytes(), "hello")
	}
}

func TestRefBufIncRefDecRef(t *testing.T) {
	rb := GetRefBuf()
	copy(rb.Buf(), []byte("data"))
	rb.SetLen(4)

	rb.IncRef() // refcount = 2

	// First DecRef: refcount = 1, should NOT reset.
	rb.DecRef()
	if rb.Len() != 4 {
		t.Fatalf("after first DecRef, Len = %d, want 4", rb.Len())
	}

	// Second DecRef: refcount = 0, returned to pool.
	rb.DecRef()
}

func TestRefBufPoolReuse(t *testing.T) {
	// Get and release a RefBuf, then get another — it should be reusable.
	rb1 := GetRefBuf()
	copy(rb1.Buf(), []byte("old"))
	rb1.SetLen(3)
	rb1.DecRef()

	rb2 := GetRefBuf()
	defer rb2.DecRef()

	// After pool return, Len should be reset to 0.
	if rb2.Len() != 0 {
		t.Fatalf("reused RefBuf Len = %d, want 0", rb2.Len())
	}
}

func TestRefBufSharedRead(t *testing.T) {
	// Simulate send path: sendPending writes data, recordSent shares via IncRef.
	rb := GetRefBuf()
	copy(rb.Buf(), []byte("segment payload"))
	rb.SetLen(15)

	// recordSent: IncRef to share.
	rb.IncRef()

	// Both holders can read the same data.
	if string(rb.Bytes()) != "segment payload" {
		t.Fatal("shared read failed")
	}

	// Send path done (e.g., writeLoop released PB).
	rb.DecRef() // refcount 2 → 1

	// Retransmit still has valid data.
	if string(rb.Bytes()) != "segment payload" {
		t.Fatal("data lost after first DecRef")
	}

	// ACK: removeAcked releases.
	rb.DecRef() // refcount 1 → 0, returned to pool
}
