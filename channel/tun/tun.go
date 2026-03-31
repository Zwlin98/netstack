/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package tun provides an interface for TUN/TAP devices.
package tun

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64

	IdealBatchSize = 128 // maximum number of packets handled per read and write
)

const (
	tunTCPOffloads = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
	tunUDPOffloads = unix.TUN_F_USO4 | unix.TUN_F_USO6
)

type nativeTun struct {
	tunFd               int
	iovecsOutputDefault []unix.Iovec
	tunFile             *os.File
	index               int32 // if index
	batchSz             int
	vnetHdr             bool
	udpGSO              bool

	closeOnce sync.Once

	nameOnce  sync.Once // guards calling initNameCache, which sets following fields
	nameCache string    // name of interface
	nameErr   error

	readOpMu sync.Mutex                    // readOpMu guards readBuff
	readBuff [virtioNetHdrLen + 65535]byte // if vnetHdr every read() is prefixed by virtioNetHdr

	writeOpMu   sync.Mutex // writeOpMu guards toWrite, tcpGROTable
	toWrite     []int
	tcpGROTable *tcpGROTable
	udpGROTable *udpGROTable
}

func (tun *nativeTun) File() *os.File {
	return tun.tunFile
}

func getIFIndex(name string) (int32, error) {
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFINDEX),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return 0, errno
	}

	return *(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])), nil
}

func (tun *nativeTun) setMTU(n int) error {
	name, err := tun.name()
	if err != nil {
		return err
	}

	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}

	defer unix.Close(fd)

	// do ioctl call
	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	*(*uint32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uint32(n)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return fmt.Errorf("failed to set MTU of TUN device: %w", errno)
	}

	return nil
}

func (tun *nativeTun) mtu() (int, error) {
	name, err := tun.name()
	if err != nil {
		return 0, err
	}

	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	// do ioctl call

	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return 0, fmt.Errorf("failed to get MTU of TUN device: %w", errno)
	}

	return int(*(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))), nil
}

func (tun *nativeTun) name() (string, error) {
	tun.nameOnce.Do(tun.initNameCache)
	return tun.nameCache, tun.nameErr
}

func (tun *nativeTun) initNameCache() {
	tun.nameCache, tun.nameErr = tun.nameSlow()
}

func (tun *nativeTun) nameSlow() (string, error) {
	sysconn, err := tun.tunFile.SyscallConn()
	if err != nil {
		return "", err
	}
	var ifr [ifReqSize]byte
	var errno syscall.Errno
	err = sysconn.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(unix.TUNGETIFF),
			uintptr(unsafe.Pointer(&ifr[0])),
		)
	})
	if err != nil {
		return "", fmt.Errorf("failed to get name of TUN device: %w", err)
	}
	if errno != 0 {
		return "", fmt.Errorf("failed to get name of TUN device: %w", errno)
	}
	return unix.ByteSliceToString(ifr[:]), nil
}

func (tun *nativeTun) write(bufs [][]byte, offset int) (int, error) {
	tun.writeOpMu.Lock()
	defer func() {
		tun.tcpGROTable.reset()
		tun.udpGROTable.reset()
		tun.writeOpMu.Unlock()
	}()
	var (
		errs  error
		total int
	)
	tun.toWrite = tun.toWrite[:0]
	if tun.vnetHdr {
		err := handleGRO(bufs, offset, tun.tcpGROTable, tun.udpGROTable, tun.udpGSO, &tun.toWrite)
		if err != nil {
			return 0, err
		}
		offset -= virtioNetHdrLen
	} else {
		for i := range bufs {
			tun.toWrite = append(tun.toWrite, i)
		}
	}
	for _, bufsI := range tun.toWrite {
		n, err := tun.tunFile.Write(bufs[bufsI][offset:])
		if errors.Is(err, syscall.EBADFD) {
			return total, os.ErrClosed
		}
		if err != nil {
			errs = errors.Join(errs, err)
		} else {
			total += n
		}
	}
	return total, errs
}

func (tun *nativeTun) read(bufs [][]byte, sizes []int, offset int) (int, error) {
	tun.readOpMu.Lock()
	defer tun.readOpMu.Unlock()
	readInto := bufs[0][offset:]
	if tun.vnetHdr {
		readInto = tun.readBuff[:]
	}
	n, err := tun.tunFile.Read(readInto)
	if errors.Is(err, syscall.EBADFD) {
		err = os.ErrClosed
	}
	if err != nil {
		return 0, err
	}
	if tun.vnetHdr {
		return handleVirtioRead(readInto[:n], bufs, sizes, offset)
	} else {
		sizes[0] = n
		return 1, nil
	}
}

func (tun *nativeTun) close() error {
	return tun.tunFile.Close()
}

func (tun *nativeTun) batchSize() int {
	return tun.batchSz
}

func (tun *nativeTun) initFromFlags(name string) error {
	sc, err := tun.tunFile.SyscallConn()
	if err != nil {
		return err
	}
	if e := sc.Control(func(fd uintptr) {
		var (
			ifr *unix.Ifreq
		)
		ifr, err = unix.NewIfreq(name)
		if err != nil {
			return
		}
		err = unix.IoctlIfreq(int(fd), unix.TUNGETIFF, ifr)
		if err != nil {
			return
		}
		got := ifr.Uint16()
		if got&unix.IFF_VNET_HDR != 0 {
			// tunTCPOffloads were added in Linux v2.6. We require their support
			// if IFF_VNET_HDR is set.
			err = unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tunTCPOffloads)
			if err != nil {
				slog.Error("TUN device does not support TCP offloads", "error", err)
				return
			}
			tun.vnetHdr = true
			tun.batchSz = IdealBatchSize
			// tunUDPOffloads were added in Linux v6.2. We do not return an
			// error if they are unsupported at runtime.
			tun.udpGSO = unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tunTCPOffloads|tunUDPOffloads) == nil
		} else {
			tun.batchSz = 1
		}
	}); e != nil {
		return e
	}
	return err
}

// createTUN creates a nativeTun with the provided name and MTU.
func createTUN(name string, mtu int) (*nativeTun, error) {
	nfd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("createTUN(%q) failed; %s does not exist", name, cloneDevicePath)
		}
		return nil, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	// IFF_VNET_HDR enables the "tun status hack" via routineHackListener()
	// where a null write will return EINVAL indicating the TUN is up.
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr)
	if err != nil {
		return nil, err
	}

	err = unix.SetNonblock(nfd, true)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}

	// Note that the above -- open,ioctl,nonblock -- must happen prior to handing it to netpoll as below this line.

	file := os.NewFile(uintptr(nfd), cloneDevicePath)
	return createTUNFromFile(file, nfd, mtu)
}

// createTUNFromFile creates a nativeTun from an os.File with the provided MTU.
func createTUNFromFile(file *os.File, fd int, mtu int) (*nativeTun, error) {
	tun := &nativeTun{
		tunFd:       fd,
		tunFile:     file,
		tcpGROTable: newTCPGROTable(),
		udpGROTable: newUDPGROTable(),
		toWrite:     make([]int, 0, IdealBatchSize),
	}

	name, err := tun.name()
	if err != nil {
		return nil, err
	}

	err = tun.initFromFlags(name)
	if err != nil {
		return nil, err
	}

	// start event listener
	tun.index, err = getIFIndex(name)
	if err != nil {
		return nil, err
	}

	err = tun.setMTU(mtu)
	if err != nil {
		return nil, err
	}

	return tun, nil
}
