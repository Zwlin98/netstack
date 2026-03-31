package header_test

import (
	"testing"

	"github.com/Zwlin98/netstack/header"
)

func TestParseSynOptions_MSSWSAndSACK(t *testing.T) {
	// MSS=1460 (0x05B4), NOP, WS=7, SACK-Permitted
	opts := []byte{
		0x02, 0x04, 0x05, 0xB4, // MSS=1460
		0x01,                   // NOP
		0x03, 0x03, 0x07,       // WS=7
		0x04, 0x02,             // SACK Permitted
	}
	so := header.ParseSynOptions(opts)
	if so.MSS != 1460 {
		t.Errorf("MSS = %d, want 1460", so.MSS)
	}
	if so.WS != 7 {
		t.Errorf("WS = %d, want 7", so.WS)
	}
	if !so.SACKPermit {
		t.Error("SACKPermit = false, want true")
	}
}

func TestParseSynOptions_NoOptions(t *testing.T) {
	so := header.ParseSynOptions(nil)
	if so.MSS != 0 {
		t.Errorf("MSS = %d, want 0", so.MSS)
	}
	if so.WS != -1 {
		t.Errorf("WS = %d, want -1", so.WS)
	}
	if so.SACKPermit {
		t.Error("SACKPermit = true, want false")
	}
}

func TestParseSynOptions_UnknownOption(t *testing.T) {
	// Unknown kind=42 length=4, then MSS=1460
	opts := []byte{
		42, 0x04, 0x00, 0x00, // unknown
		0x02, 0x04, 0x05, 0xB4, // MSS=1460
	}
	so := header.ParseSynOptions(opts)
	if so.MSS != 1460 {
		t.Errorf("MSS = %d, want 1460", so.MSS)
	}
}

func TestParseSynOptions_WSClamped(t *testing.T) {
	opts := []byte{0x03, 0x03, 20} // WS=20, should clamp to 14
	so := header.ParseSynOptions(opts)
	if so.WS != 14 {
		t.Errorf("WS = %d, want 14 (clamped)", so.WS)
	}
}

func TestParseSynOptions_MalformedLength(t *testing.T) {
	// Length=0 is invalid — parser should stop.
	opts := []byte{0x02, 0x00}
	so := header.ParseSynOptions(opts)
	if so.MSS != 0 {
		t.Errorf("MSS = %d, want 0", so.MSS)
	}
}

func TestParseSynOptions_EOLStops(t *testing.T) {
	// EOL before MSS
	opts := []byte{0x00, 0x02, 0x04, 0x05, 0xB4}
	so := header.ParseSynOptions(opts)
	if so.MSS != 0 {
		t.Errorf("MSS = %d, want 0 (EOL stops parsing)", so.MSS)
	}
}

func TestParseSegmentOptions_SACKBlocks(t *testing.T) {
	// SACK option with 2 blocks
	opts := []byte{
		header.TCPOptionSACK, 18, // kind=5, length=18 (2+2*8)
		0x00, 0x00, 0x03, 0xE8, // start=1000
		0x00, 0x00, 0x05, 0xDC, // end=1500
		0x00, 0x00, 0x07, 0xD0, // start=2000
		0x00, 0x00, 0x09, 0xC4, // end=2500
	}
	so := header.ParseSegmentOptions(opts)
	if len(so.SACKBlocks) != 2 {
		t.Fatalf("SACKBlocks count = %d, want 2", len(so.SACKBlocks))
	}
	if so.SACKBlocks[0].Start != 1000 || so.SACKBlocks[0].End != 1500 {
		t.Errorf("block[0] = (%d,%d), want (1000,1500)", so.SACKBlocks[0].Start, so.SACKBlocks[0].End)
	}
	if so.SACKBlocks[1].Start != 2000 || so.SACKBlocks[1].End != 2500 {
		t.Errorf("block[1] = (%d,%d), want (2000,2500)", so.SACKBlocks[1].Start, so.SACKBlocks[1].End)
	}
}

func TestParseSegmentOptions_NoSACK(t *testing.T) {
	so := header.ParseSegmentOptions(nil)
	if so.SACKBlocks != nil {
		t.Errorf("SACKBlocks = %v, want nil", so.SACKBlocks)
	}
}

func TestEncodeMSSOption_Roundtrip(t *testing.T) {
	buf := make([]byte, 4)
	n := header.EncodeMSSOption(buf, 1460)
	if n != 4 {
		t.Fatalf("EncodeMSSOption returned %d, want 4", n)
	}
	so := header.ParseSynOptions(buf[:n])
	if so.MSS != 1460 {
		t.Errorf("roundtrip MSS = %d, want 1460", so.MSS)
	}
}

func TestEncodeWSOption_Roundtrip(t *testing.T) {
	buf := make([]byte, 3)
	n := header.EncodeWSOption(buf, 7)
	if n != 3 {
		t.Fatalf("EncodeWSOption returned %d, want 3", n)
	}
	so := header.ParseSynOptions(buf[:n])
	if so.WS != 7 {
		t.Errorf("roundtrip WS = %d, want 7", so.WS)
	}
}

func TestEncodeSACKPermittedOption_Roundtrip(t *testing.T) {
	buf := make([]byte, 2)
	n := header.EncodeSACKPermittedOption(buf)
	if n != 2 {
		t.Fatalf("EncodeSACKPermittedOption returned %d, want 2", n)
	}
	so := header.ParseSynOptions(buf[:n])
	if !so.SACKPermit {
		t.Error("roundtrip SACKPermit = false, want true")
	}
}

func TestEncodeSACKBlocks_Roundtrip(t *testing.T) {
	blocks := []header.SACKBlock{
		{Start: 1000, End: 1500},
		{Start: 2000, End: 2500},
	}
	buf := make([]byte, 34) // 2 + 2*8 = 18
	n := header.EncodeSACKBlocks(buf, blocks)
	if n != 18 {
		t.Fatalf("EncodeSACKBlocks returned %d, want 18", n)
	}
	so := header.ParseSegmentOptions(buf[:n])
	if len(so.SACKBlocks) != 2 {
		t.Fatalf("roundtrip SACKBlocks count = %d, want 2", len(so.SACKBlocks))
	}
	if so.SACKBlocks[0] != blocks[0] {
		t.Errorf("block[0] = %v, want %v", so.SACKBlocks[0], blocks[0])
	}
	if so.SACKBlocks[1] != blocks[1] {
		t.Errorf("block[1] = %v, want %v", so.SACKBlocks[1], blocks[1])
	}
}

func TestEncodeOption_BufferTooSmall(t *testing.T) {
	if n := header.EncodeMSSOption(make([]byte, 3), 1460); n != 0 {
		t.Errorf("EncodeMSSOption with small buf returned %d, want 0", n)
	}
	if n := header.EncodeWSOption(make([]byte, 2), 7); n != 0 {
		t.Errorf("EncodeWSOption with small buf returned %d, want 0", n)
	}
	if n := header.EncodeSACKPermittedOption(make([]byte, 1)); n != 0 {
		t.Errorf("EncodeSACKPermittedOption with small buf returned %d, want 0", n)
	}
}

func TestTCPOptions_Accessor(t *testing.T) {
	// Build a TCP header with 12 bytes of options (DataOffset = 8 words = 32 bytes)
	buf := make([]byte, 32)
	hdr := header.TCP(buf)
	hdr.Encode(&header.TCPFields{
		DataOffset: 8, // 32 bytes total header
	})
	// Write some option bytes
	buf[20] = header.TCPOptionMSS
	buf[21] = 4
	buf[22] = 0x05
	buf[23] = 0xB4

	opts := hdr.Options()
	if len(opts) != 12 {
		t.Fatalf("Options() len = %d, want 12", len(opts))
	}
	if opts[0] != header.TCPOptionMSS {
		t.Errorf("Options()[0] = %d, want %d", opts[0], header.TCPOptionMSS)
	}
}

func TestTCPOptions_NoOptions(t *testing.T) {
	buf := make([]byte, 20)
	hdr := header.TCP(buf)
	hdr.Encode(&header.TCPFields{
		DataOffset: 5, // 20 bytes, no options
	})
	opts := hdr.Options()
	if opts != nil {
		t.Errorf("Options() = %v, want nil", opts)
	}
}
