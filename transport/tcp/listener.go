package tcp

import (
	"net"

	"github.com/Zwlin98/netstack/tcpip"
)

// TCPListener accepts new established TCP connections.
type TCPListener struct {
	acceptCh chan *TCPConn
	done     chan struct{}
}

// Accept blocks until a new ESTABLISHED connection is available.
func (l *TCPListener) Accept() (*TCPConn, tcpip.FullAddress, error) {
	select {
	case conn := <-l.acceptCh:
		addr := tcpip.FullAddress{
			Addr: conn.flow.SrcAddr,
			Port: conn.flow.SrcPort,
		}
		return conn, addr, nil
	case <-l.done:
		return nil, tcpip.FullAddress{}, net.ErrClosed
	}
}

// Close shuts down the listener, unblocking any waiting Accept calls.
func (l *TCPListener) Close() {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
}
