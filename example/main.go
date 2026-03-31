// Example: echo / forward server over TUN device.
//
// Requires root. Tests ICMP, TCP, and UDP through the netstack.
//
// Usage:
//
//	./echo                                   # echo mode (default)
//	./echo -forward <ssh-host>:5201             # forward all TCP to remote host
//
// Test from another terminal:
//
//	ping 10.0.0.1                            # ICMP echo (stack built-in)
//	echo hello | nc 10.0.0.1 7777            # TCP echo
//	echo hello | nc -u -w1 10.0.0.1 7777     # UDP echo
//	iperf3 -c 10.0.0.1                       # TCP forward (with -forward)
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/Zwlin98/netstack/channel/tun"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
	"github.com/Zwlin98/netstack/transport/udp"
)

const (
	tunName   = "tun0"
	tunMTU    = 1500
	tunSubnet = "10.0.0.0/24"
)

var forwardAddr = flag.String("forward", "", "forward all TCP to this address (e.g. host:5201)")

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// 1. Create TUN device.
	ch, err := tun.NewChannel(tunName, tunMTU)
	if err != nil {
		log.Fatalf("create tun: %v", err)
	}
	defer ch.Close()

	name, _ := ch.Name()
	log.Printf("TUN device %s created", name)

	// 2. Bring up interface and add route (no IP on TUN — avoids local routing).
	run("ip", "link", "set", name, "up")
	run("ip", "route", "add", tunSubnet, "dev", name)
	log.Printf("configured %s route %s", name, tunSubnet)

	// 3. Create stack and register handlers.
	s := stack.New(ch)

	tcpHandler := tcp.NewTCPHandler(s)
	s.RegisterHandler(tcpip.TCPProtocolNumber, tcpHandler)

	udpHandler := udp.NewUDPHandler(s)
	s.RegisterHandler(tcpip.UDPProtocolNumber, udpHandler)

	s.Start()
	defer s.Stop()

	// 4. Start handlers.
	if *forwardAddr != "" {
		log.Printf("stack started, forwarding TCP to %s", *forwardAddr)
		go tcpForward(tcpHandler.Listener(), *forwardAddr)
	} else {
		log.Println("stack started, echo on all ports")
		go tcpEcho(tcpHandler.Listener())
	}
	go udpEcho(udpHandler)

	// 5. Wait for signal.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
}

func tcpEcho(ln *tcp.TCPListener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		log.Printf("[tcp] echo from %s", conn.RemoteAddr())
		go func() {
			defer conn.Close()
			buf := make([]byte, 4096)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					conn.Write(buf[:n])
				}
				if err != nil {
					if err != io.EOF {
						log.Printf("[tcp] read error: %v", err)
					}
					return
				}
			}
		}()
	}
}

func tcpForward(ln *tcp.TCPListener, addr string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		log.Printf("[tcp] forward %s → %s", conn.RemoteAddr(), addr)
		go func() {
			defer conn.Close()
			remote, err := net.Dial("tcp", addr)
			if err != nil {
				log.Printf("[tcp] dial %s: %v", addr, err)
				return
			}
			defer remote.Close()
			done := make(chan struct{})
			go func() {
				io.Copy(remote, conn)
				remote.(*net.TCPConn).CloseWrite()
				close(done)
			}()
			io.Copy(conn, remote)
			conn.CloseWrite()
			<-done
		}()
	}
}

func udpEcho(h *udp.UDPHandler) {
	buf := make([]byte, 4096)
	for {
		n, src, dst, err := h.ReadFrom(buf)
		if err != nil {
			return
		}
		log.Printf("[udp] %d bytes from %s → %s", n, src, dst)
		h.WriteTo(buf[:n], dst, src)
	}
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("exec %s %v: %v", name, args, err)
	}
}
