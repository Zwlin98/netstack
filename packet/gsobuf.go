package packet

import "sync"

const (
	// GSOBufSize is the size of a GSO buffer (max IP total length).
	GSOBufSize = 65536

	// GSOBufHeadroom is the headroom to reserve for IP + max TCP header.
	// IPv4 header (20) + max TCP header with options (60) = 80 bytes.
	GSOBufHeadroom = 80
)

type gsoBuf [GSOBufSize]byte

var gsoBufPool = sync.Pool{
	New: func() any {
		return new(gsoBuf)
	},
}

// GetGSOBuf obtains a large buffer from the pool for GSO segment construction.
// The returned slice has length GSOBufSize.
func GetGSOBuf() []byte {
	return gsoBufPool.Get().(*gsoBuf)[:]
}

// PutGSOBuf returns a GSO buffer to the pool.
// The argument must be a slice originally obtained from GetGSOBuf (or a sub-slice
// whose backing array is a *gsoBuf). Callers typically pass the full slice.
func PutGSOBuf(b []byte) {
	gsoBufPool.Put((*gsoBuf)(b[:GSOBufSize]))
}
