package tun

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// TUNChannel adapts a Linux TUN device to the channel.Channel interface.
// Read path: batch-reads into an internal buffer, returns one packet per ReadPacket call.
// Write path: writes each packet directly to the TUN fd via writev (zero-copy virtio header prepend).
type TUNChannel struct {
	tun *nativeTun

	// Read-side batch buffer.
	bufs  [][]byte
	sizes []int
	head  int // next packet to return
	count int // packets available in current batch

	// Write-side: pre-allocated empty virtio header for writev.
	emptyVnetHdr [virtioNetHdrLen]byte
}

// NewChannel creates a TUNChannel backed by a new TUN device with the given name and MTU.
func NewChannel(name string, mtu int) (*TUNChannel, error) {
	t, err := createTUN(name, mtu)
	if err != nil {
		return nil, err
	}
	return newChannel(t), nil
}


func newChannel(t *nativeTun) *TUNChannel {
	bs := t.batchSize()
	bufs := make([][]byte, bs)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	return &TUNChannel{
		tun:   t,
		bufs:  bufs,
		sizes: make([]int, bs),
	}
}

// ReadPacket reads one IP packet into buf.
// Internally batch-reads from the TUN device and returns packets one at a time.
func (c *TUNChannel) ReadPacket(buf []byte) (int, error) {
	for {
		// Return buffered packet if available.
		if c.head < c.count {
			n := copy(buf, c.bufs[c.head][:c.sizes[c.head]])
			c.head++
			return n, nil
		}

		// Batch-read from TUN.
		count, err := c.tun.read(c.bufs, c.sizes, 0)
		if count > 0 {
			c.head = 0
			c.count = count
			continue
		}
		if err != nil {
			if errors.Is(err, ErrTooManySegments) {
				continue
			}
			return 0, err
		}
	}
}

// WritePacket writes one complete IP packet to the TUN device.
// When vnetHdr is enabled, uses writev to prepend an empty virtio header without copying the data.
func (c *TUNChannel) WritePacket(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	if c.tun.vnetHdr {
		_, err := unix.Writev(c.tun.tunFd, [][]byte{c.emptyVnetHdr[:], data})
		if errors.Is(err, os.ErrClosed) {
			return os.ErrClosed
		}
		return err
	}

	_, err := c.tun.tunFile.Write(data)
	if errors.Is(err, os.ErrClosed) {
		return os.ErrClosed
	}
	return err
}

// Name returns the TUN interface name (e.g. "tun0").
func (c *TUNChannel) Name() (string, error) {
	return c.tun.name()
}

// File returns the underlying TUN device file, useful for configuring
// the interface via ioctl or netlink.
func (c *TUNChannel) File() *os.File {
	return c.tun.tunFile
}

// Close closes the underlying TUN device.
func (c *TUNChannel) Close() error {
	return c.tun.close()
}

// MTU returns the TUN device's MTU.
func (c *TUNChannel) MTU() int {
	mtu, err := c.tun.mtu()
	if err != nil {
		return 1500
	}
	return mtu
}
