// Example: echo server over TUN device.
//
// Requires root. Tests ICMP, TCP, and UDP through the netstack.
//
// Setup (automatic):
//
//	Creates tun0 with IP 10.0.0.1/24
//
// Test from another terminal:
//
//	ping 10.0.0.1                          # ICMP echo (stack built-in)
//	echo hello | nc 10.0.0.1 7777          # TCP echo
//	echo hello | nc -u -w1 10.0.0.1 7777   # UDP echo
package main

import (
	"io"
	"log"
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
	tunName = "tun0"
	tunMTU  = 1500
	tunSubnet = "10.0.0.0/24"
)

func main() {
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

	log.Println("stack started, echo on all ports")

	// 4. Start echo servers.
	go tcpEcho(tcpHandler.Listener())
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
		log.Printf("[tcp] connection from %s", conn.RemoteAddr())
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
