package tcp

import "net"

// TCPListener accepts new established TCP connections.
type TCPListener struct {
	acceptCh chan *TCPConn
	done     chan struct{}
}

// Accept blocks until a new ESTABLISHED connection is available.
func (l *TCPListener) Accept() (*TCPConn, error) {
	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
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
