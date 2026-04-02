package tcp

import (
	"testing"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/tcpip"
)

func TestSetTCPPartialChecksum(t *testing.T) {
	src := tcpip.From4(10, 0, 0, 1)
	dst := tcpip.From4(10, 0, 0, 2)

	// Build a minimal TCP header.
	var buf [header.TCPMinHeaderSize]byte
	hdr := header.TCP(buf[:])
	hdr.Encode(&header.TCPFields{
		SrcPort:    1234,
		DstPort:    80,
		SeqNum:     100,
		AckNum:     200,
		DataOffset: header.TCPMinHeaderSize / 4,
		Flags:      header.TCPFlagACK,
		WindowSize: 65535,
	})

	tcpLen := uint16(header.TCPMinHeaderSize)
	setTCPPartialChecksum(hdr, src, dst, tcpLen)

	gotPartial := hdr.Checksum()
	expected := header.PseudoHeaderChecksum(tcpip.TCPProtocolNumber, src, dst, tcpLen)
	if gotPartial != expected {
		t.Errorf("partial checksum = 0x%04x, want 0x%04x (PseudoHeaderChecksum)", gotPartial, expected)
	}

	// The partial checksum must differ from the full checksum.
	hdr2 := header.TCP(make([]byte, header.TCPMinHeaderSize))
	copy(hdr2, buf[:])
	setTCPChecksum(hdr2, src, dst, tcpLen)
	if gotPartial == hdr2.Checksum() {
		t.Error("partial checksum should differ from full checksum")
	}
}

func TestRecordSentGSO(t *testing.T) {
	mss := 1460
	s := &sender{mss: mss}

	// 3 full MSS + 500 byte tail = 4880 bytes
	dataLen := 3*mss + 500
	data := make([]byte, dataLen)
	for i := range data {
		data[i] = byte(i % 256)
	}

	seq := uint32(1000)
	s.recordSentGSO(seq, data, mss)

	// Expect 4 entries: 1460, 1460, 1460, 500
	if len(s.unacked) != 4 {
		t.Fatalf("unacked count = %d, want 4", len(s.unacked))
	}

	expectedSizes := []int{mss, mss, mss, 500}
	expectedSeqs := []uint32{1000, 1000 + uint32(mss), 1000 + 2*uint32(mss), 1000 + 3*uint32(mss)}

	for i, seg := range s.unacked {
		if seg.seq != expectedSeqs[i] {
			t.Errorf("unacked[%d].seq = %d, want %d", i, seg.seq, expectedSeqs[i])
		}
		if seg.ref == nil {
			t.Fatalf("unacked[%d].ref is nil", i)
		}
		if seg.ref.Len() != expectedSizes[i] {
			t.Errorf("unacked[%d].ref.Len() = %d, want %d", i, seg.ref.Len(), expectedSizes[i])
		}
		// Verify data integrity.
		offset := i * mss
		for j := 0; j < seg.ref.Len(); j++ {
			if seg.ref.Bytes()[j] != data[offset+j] {
				t.Errorf("unacked[%d] data mismatch at byte %d", i, j)
				break
			}
		}
	}

	// Clean up RefBufs.
	for _, seg := range s.unacked {
		seg.ref.DecRef()
	}
}

func TestRecordSentGSO_ExactMSSMultiple(t *testing.T) {
	mss := 1460
	s := &sender{mss: mss}

	dataLen := 2 * mss
	data := make([]byte, dataLen)
	s.recordSentGSO(500, data, mss)

	if len(s.unacked) != 2 {
		t.Fatalf("unacked count = %d, want 2", len(s.unacked))
	}
	if s.unacked[0].ref.Len() != mss {
		t.Errorf("unacked[0] size = %d, want %d", s.unacked[0].ref.Len(), mss)
	}
	if s.unacked[1].ref.Len() != mss {
		t.Errorf("unacked[1] size = %d, want %d", s.unacked[1].ref.Len(), mss)
	}

	for _, seg := range s.unacked {
		seg.ref.DecRef()
	}
}

func TestGSOBufPoolRoundtrip(t *testing.T) {
	buf := packet.GetGSOBuf()
	if len(buf) != packet.GSOBufSize {
		t.Fatalf("GetGSOBuf() len = %d, want %d", len(buf), packet.GSOBufSize)
	}
	// Write some data and return.
	buf[0] = 0xAA
	buf[packet.GSOBufSize-1] = 0xBB
	packet.PutGSOBuf(buf)

	// Get again — should not panic.
	buf2 := packet.GetGSOBuf()
	if len(buf2) != packet.GSOBufSize {
		t.Fatalf("second GetGSOBuf() len = %d, want %d", len(buf2), packet.GSOBufSize)
	}
	packet.PutGSOBuf(buf2)
}
