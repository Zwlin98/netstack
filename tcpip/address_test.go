package tcpip

import "testing"

func TestFrom4AndTo4(t *testing.T) {
	addr := From4(192, 168, 1, 1)
	got := addr.To4()
	want := [4]byte{192, 168, 1, 1}
	if got != want {
		t.Errorf("To4() = %v, want %v", got, want)
	}
}

func TestAddressString(t *testing.T) {
	tests := []struct {
		addr Address
		want string
	}{
		{From4(0, 0, 0, 0), "0.0.0.0"},
		{From4(127, 0, 0, 1), "127.0.0.1"},
		{From4(192, 168, 1, 1), "192.168.1.1"},
		{From4(255, 255, 255, 255), "255.255.255.255"},
		{From4(10, 0, 0, 1), "10.0.0.1"},
	}
	for _, tt := range tests {
		if got := tt.addr.String(); got != tt.want {
			t.Errorf("Address(%d).String() = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestAddressRoundTrip(t *testing.T) {
	octets := [4]byte{172, 16, 254, 3}
	addr := From4(octets[0], octets[1], octets[2], octets[3])
	got := addr.To4()
	if got != octets {
		t.Errorf("round-trip failed: got %v, want %v", got, octets)
	}
}

func TestFullAddressString(t *testing.T) {
	fa := FullAddress{Addr: From4(10, 0, 0, 1), Port: 8080}
	want := "10.0.0.1:8080"
	if got := fa.String(); got != want {
		t.Errorf("FullAddress.String() = %q, want %q", got, want)
	}
}

func TestAddressComparable(t *testing.T) {
	a := From4(192, 168, 1, 1)
	b := From4(192, 168, 1, 1)
	c := From4(192, 168, 1, 2)
	if a != b {
		t.Error("equal addresses should be ==")
	}
	if a == c {
		t.Error("different addresses should not be ==")
	}
}

func TestAddressAsMapKey(t *testing.T) {
	m := map[Address]string{
		From4(10, 0, 0, 1): "host1",
		From4(10, 0, 0, 2): "host2",
	}
	if m[From4(10, 0, 0, 1)] != "host1" {
		t.Error("address should work as map key")
	}
}
