package tcp

type tcpState int

const (
	stateClosed tcpState = iota
	stateSynRcvd
	stateEstablished
	stateFinWait1
	stateFinWait2
	stateCloseWait
	stateLastAck
	stateTimeWait
)

func (s tcpState) String() string {
	switch s {
	case stateClosed:
		return "CLOSED"
	case stateSynRcvd:
		return "SYN_RCVD"
	case stateEstablished:
		return "ESTABLISHED"
	case stateFinWait1:
		return "FIN_WAIT_1"
	case stateFinWait2:
		return "FIN_WAIT_2"
	case stateCloseWait:
		return "CLOSE_WAIT"
	case stateLastAck:
		return "LAST_ACK"
	case stateTimeWait:
		return "TIME_WAIT"
	default:
		return "UNKNOWN"
	}
}
