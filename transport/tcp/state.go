package tcp

type tcpState int

const (
	stateClosed tcpState = iota
	stateSynRcvd
	stateEstablished
)

func (s tcpState) String() string {
	switch s {
	case stateClosed:
		return "CLOSED"
	case stateSynRcvd:
		return "SYN_RCVD"
	case stateEstablished:
		return "ESTABLISHED"
	default:
		return "UNKNOWN"
	}
}
