package tcpip

import "errors"

var (
	ErrBadAddress        = errors.New("bad address")
	ErrPacketTooShort    = errors.New("packet too short")
	ErrBadChecksum       = errors.New("bad checksum")
	ErrConnectionRefused = errors.New("connection refused")
	ErrConnectionReset   = errors.New("connection reset")
	ErrTimeout           = errors.New("timeout")
	ErrClosedForSend     = errors.New("closed for send")
	ErrClosedForReceive  = errors.New("closed for receive")
)
