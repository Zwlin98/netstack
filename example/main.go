// Example: echo / forward server over TUN device.
//
// Requires root. Tests ICMP, TCP, and UDP through the netstack.
//
// Usage:
//
//	./echo                                   # echo mode (default)
//	./echo -forward <host>:5201              # forward all TCP to remote host
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
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Zwlin98/netstack/channel/tun"
	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
	"github.com/Zwlin98/netstack/transport/udp"
)

var (
	tunName     = flag.String("tun", "tun0", "TUN device name")
	tunMTU      = flag.Int("mtu", 1500, "TUN MTU")
	tunSubnet   = flag.String("subnet", "10.0.0.0/24", "route subnet for TUN device")
	forwardAddr = flag.String("forward", "", "forward all TCP to this address (e.g. host:5201)")
	readDelay   = flag.Duration("read-delay", 0, "delay between reads in echo handler (e.g. 50ms)")
	statsFlag   = flag.Bool("stats", false, "enable stats and log periodically")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// 1. Create TUN device.
	ch, err := tun.NewChannel(*tunName, *tunMTU)
	if err != nil {
		log.Fatalf("create tun: %v", err)
	}
	defer ch.Close()

	name, _ := ch.Name()
	log.Printf("TUN device %s created", name)

	// 2. Bring up interface and add route (no IP on TUN — avoids local routing).
	run("ip", "link", "set", name, "up")
	run("ip", "route", "add", *tunSubnet, "dev", name)
	log.Printf("configured %s route %s", name, *tunSubnet)

	// 3. Create stack and register handlers.
	s := stack.New(ch)

	tcpHandler := tcp.NewTCPHandler(s)
	s.RegisterHandler(tcpip.TCPProtocolNumber, tcpHandler)

	udpHandler := udp.NewUDPHandler(s)
	s.RegisterHandler(tcpip.UDPProtocolNumber, udpHandler)

	// Enable stats if requested.
	if *statsFlag {
		stkStats := s.EnableStats()
		tcpStats := tcpHandler.EnableStats()
		udpStats := udpHandler.EnableStats()
		go logStats(s, stkStats, tcpStats, udpStats, tcpHandler)
	}

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
				if *readDelay > 0 {
					time.Sleep(*readDelay)
				}
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
	buf := make([]byte, 0xffff-header.IPv4MinHeaderSize-header.UDPHeaderSize)
	for {
		n, src, dst, err := h.ReadFrom(buf)
		if err != nil {
			return
		}
		log.Printf("[udp] %d bytes from %s → %s", n, src, dst)
		h.WriteTo(buf[:n], dst, src)
	}
}

func logStats(s *stack.Stack, stkStats *stack.Stats, tcpStats *tcp.Stats, udpStats *udp.Stats, tcpHandler *tcp.TCPHandler) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		log.Printf("[stats] stack: in=%d out=%d bytes_in=%d bytes_out=%d dropped=%d unknown=%d queue=%d",
			stkStats.PacketsIn.Load(), stkStats.PacketsOut.Load(),
			stkStats.BytesIn.Load(), stkStats.BytesOut.Load(),
			stkStats.DroppedOutbound.Load(), stkStats.UnknownProtocol.Load(),
			s.OutboundQueueLen())
		log.Printf("[stats] tcp: active=%d accepted=%d closed=%d reset=%d seg_in=%d seg_out=%d "+
			"bytes_in=%d bytes_out=%d retx=%d fast_retx=%d dup_ack=%d rst_sent=%d rst_rcvd=%d "+
			"chksum_err=%d dropped=%d zwp=%d paws=%d",
			tcpStats.ActiveConns.Load(), tcpStats.TotalAccepted.Load(),
			tcpStats.TotalClosed.Load(), tcpStats.TotalReset.Load(),
			tcpStats.SegmentsIn.Load(), tcpStats.SegmentsOut.Load(),
			tcpStats.PayloadBytesIn.Load(), tcpStats.PayloadBytesOut.Load(),
			tcpStats.Retransmits.Load(), tcpStats.FastRetransmits.Load(),
			tcpStats.DupACKsIn.Load(), tcpStats.ResetsSent.Load(),
			tcpStats.ResetsReceived.Load(), tcpStats.ChecksumErrors.Load(),
			tcpStats.DroppedInbound.Load(), tcpStats.ZeroWindowProbes.Load(),
			tcpStats.PAWSDrops.Load())
		log.Printf("[stats] udp: in=%d out=%d bytes_in=%d bytes_out=%d dropped=%d chksum_err=%d",
			udpStats.DatagramsIn.Load(), udpStats.DatagramsOut.Load(),
			udpStats.BytesIn.Load(), udpStats.BytesOut.Load(),
			udpStats.DroppedInbound.Load(), udpStats.ChecksumErrors.Load())

		// Per-connection snapshots.
		snaps := tcpHandler.ConnSnapshots()
		if len(snaps) > 0 {
			var lines []string
			for _, snap := range snaps {
				lines = append(lines, fmt.Sprintf("  %s→%s:%d state=%s rtt=%s cwnd=%d unacked=%d rbuf=%d/%d",
					snap.Flow.SrcAddr, snap.Flow.DstAddr, snap.Flow.DstPort,
					snap.State, snap.SRTT, snap.Cwnd, snap.Unacked,
					snap.ReadBufUsed, snap.BufCap))
			}
			log.Printf("[stats] connections:\n%s", strings.Join(lines, "\n"))
		}
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
