package packet

import "testing"

func BenchmarkRefBufGetDecRef(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		rb := GetRefBuf()
		copy(rb.Buf(), make([]byte, 1460))
		rb.SetLen(1460)
		rb.DecRef()
	}
}

func BenchmarkMakeByteSlice(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		data := make([]byte, 1460)
		_ = data
	}
}

func BenchmarkRefBufSharedLifecycle(b *testing.B) {
	// Simulates the send path: Get → IncRef (recordSent) → DecRef (writeLoop) → DecRef (ACK).
	b.ReportAllocs()
	for b.Loop() {
		rb := GetRefBuf()
		copy(rb.Buf(), make([]byte, 1460))
		rb.SetLen(1460)
		rb.IncRef()  // recordSent
		rb.DecRef()  // writeLoop done
		rb.DecRef()  // ACK
	}
}

func BenchmarkMakeAndCopy(b *testing.B) {
	// Simulates the old path: make for send + append(nil, data...) for recordSent.
	b.ReportAllocs()
	src := make([]byte, 1460)
	for b.Loop() {
		data := make([]byte, 1460)
		copy(data, src)
		saved := append([]byte(nil), data...)
		_ = saved
	}
}
