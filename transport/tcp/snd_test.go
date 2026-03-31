package tcp

import (
	"testing"
	"time"
)

func TestUpdateRTT_FirstMeasurement(t *testing.T) {
	s := &sender{mss: 1460}

	s.updateRTT(100 * time.Millisecond)

	if s.srtt != 100*time.Millisecond {
		t.Errorf("srtt = %v, want 100ms", s.srtt)
	}
	if s.rttvar != 50*time.Millisecond {
		t.Errorf("rttvar = %v, want 50ms", s.rttvar)
	}
	// RTO = SRTT + 4*RTTVAR = 100ms + 200ms = 300ms
	wantRTO := 300 * time.Millisecond
	if s.rto != wantRTO {
		t.Errorf("rto = %v, want %v", s.rto, wantRTO)
	}
}

func TestUpdateRTT_ConvergesWithStableInput(t *testing.T) {
	s := &sender{mss: 1460}
	stableRTT := 50 * time.Millisecond

	// Feed 20 identical RTT measurements.
	for i := 0; i < 20; i++ {
		s.updateRTT(stableRTT)
	}

	// SRTT should converge to the stable RTT.
	diff := s.srtt - stableRTT
	if diff < 0 {
		diff = -diff
	}
	if diff > 2*time.Millisecond {
		t.Errorf("srtt = %v, want ~%v (diff %v)", s.srtt, stableRTT, diff)
	}

	// RTTVAR should converge toward zero with stable input.
	if s.rttvar > 5*time.Millisecond {
		t.Errorf("rttvar = %v, want near zero with stable input", s.rttvar)
	}
}

func TestUpdateRTT_TracksVariableInput(t *testing.T) {
	s := &sender{mss: 1460}

	// Alternate between 30ms and 70ms (mean=50ms, variation=20ms).
	for i := 0; i < 40; i++ {
		if i%2 == 0 {
			s.updateRTT(30 * time.Millisecond)
		} else {
			s.updateRTT(70 * time.Millisecond)
		}
	}

	// SRTT should be near the mean (50ms).
	diff := s.srtt - 50*time.Millisecond
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Millisecond {
		t.Errorf("srtt = %v, want ~50ms", s.srtt)
	}

	// RTTVAR should be non-trivial reflecting the variation.
	if s.rttvar < 5*time.Millisecond {
		t.Errorf("rttvar = %v, expected non-trivial variance", s.rttvar)
	}
}

func TestUpdateRTT_MinRTOBound(t *testing.T) {
	s := &sender{mss: 1460}

	// Very small RTT should still produce RTO >= 200ms.
	s.updateRTT(1 * time.Millisecond)

	if s.rto < minRTO {
		t.Errorf("rto = %v, want >= %v", s.rto, minRTO)
	}
}

func TestUpdateRTT_MaxRTOBound(t *testing.T) {
	s := &sender{mss: 1460}

	// Very large RTT.
	s.updateRTT(100 * time.Second)

	if s.rto > maxRTO {
		t.Errorf("rto = %v, want <= %v", s.rto, maxRTO)
	}
}
