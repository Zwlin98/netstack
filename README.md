# netstack

纯 Go 实现的用户态 IPv4 网络协议栈，专为网关场景设计。

## 特性

- **IPv4** — 头部解析/构建、校验和验证
- **TCP** — 服务端全状态机：三次握手、数据传输、半关闭、优雅关闭
  - TCP 选项：MSS 协商、窗口缩放 (RFC 7323)、SACK (RFC 2018)、DSACK (RFC 2883)、Timestamps (RFC 7323)
  - 拥塞控制：New Reno 快速恢复 (RFC 5681)、Limited Transmit (RFC 3042)
  - 可靠重传：RTO 定时器 (RFC 6298)、Karn 算法、SACK 驱动丢包检测、最大重试限制
  - RTT 测量：时间戳 RTTM (RFC 7323)、SRTT/RTTVAR 平滑
  - PAWS 防回绕序列号保护 (RFC 7323)
  - Nagle 算法 (RFC 1122)、`SetNoDelay` 禁用
  - Delayed ACK (RFC 1122)：200ms 延迟确认
  - SWS 避免：接收端 Clark's algorithm + 发送端抑制 (RFC 1122 §4.2.3.4)
  - 零窗口探测 (RFC 1122)
  - 接收缓冲区自动调优：按 RTT 窗口测量吞吐量，动态扩容至配置上限
  - Keepalive (RFC 1122 §4.2.3.6)：可配置 idle/interval/count
  - 超时管理：SYN_RCVD、FIN_WAIT_2、TIME_WAIT (2×MSL)
- **UDP** — PacketConn 风格 API（ReadFrom / WriteTo），上层自由处理数据
- **ICMP** — 自动 Echo Reply（ping 响应）
- **TUN** — 内置 Linux TUN 设备驱动，支持 GRO 合并和校验和卸载
- 零拷贝包缓冲区 + `sync.Pool` 对象复用

## 架构

```mermaid
graph TB
    App["用户代码<br/>conn.Read() / conn.Write()"]

    subgraph Transport["传输层"]
        TCP["TCPHandler<br/>TCPListener / TCPConn"]
        UDP["UDPHandler<br/>ReadFrom / WriteTo"]
    end

    Stack["Stack<br/>IPv4 解析 · 协议分发 · ICMP 应答"]
    Channel["Channel 接口<br/>MemoryChannel | TUN Device | ..."]

    App --> TCP
    App --> UDP
    TCP --> Stack
    UDP --> Stack
    Stack --> Channel
    Channel --> Stack
```

## 安装

```bash
go get github.com/Zwlin98/netstack
```

## 快速开始

### 创建网络栈并接收 TCP 连接

```go
package main

import (
	"fmt"

	"github.com/Zwlin98/netstack/channel"
	"github.com/Zwlin98/netstack/stack"
	"github.com/Zwlin98/netstack/tcpip"
	"github.com/Zwlin98/netstack/transport/tcp"
	"github.com/Zwlin98/netstack/transport/udp"
)

func main() {
	// 1. 创建 Channel（实际使用时替换为 TUN 设备）
	ch := channel.NewMemory(1500)

	// 2. 创建协议栈（可选配置）
	s := stack.New(ch)

	// 3. 注册传输层处理器（可选配置）
	tcpHandler := tcp.NewTCPHandler(s)
	udpHandler := udp.NewUDPHandler(s)
	s.RegisterHandler(tcpip.TCPProtocolNumber, tcpHandler)
	s.RegisterHandler(tcpip.UDPProtocolNumber, udpHandler)

	// 4. 启动
	s.Start()
	defer s.Stop()

	// 5. 接受 TCP 连接
	for {
		conn, err := tcpHandler.Listener().Accept()
		if err != nil {
			break
		}
		go handleConn(conn)
	}
}

func handleConn(conn *tcp.TCPConn) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	fmt.Printf("新连接: %s:%d\n", remote.Addr, remote.Port)

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n]) // echo
	}
}
```

### 自定义配置

每层构造函数通过 Functional Options 注入配置，不传则使用 RFC 推荐的默认值：

```go
// Stack 层
s := stack.New(ch,
    stack.WithTTL(128),
    stack.WithOutboundQueueSize(1024),
)

// TCP 层
tcpHandler := tcp.NewTCPHandler(s,
    // 缓冲区
    tcp.WithReadBufferSize(512*1024),
    tcp.WithWriteBufferSize(512*1024),
    tcp.WithMaxReadBufferSize(8*1024*1024), // 接收缓冲区自动调优上限
    tcp.WithAcceptQueueSize(64),

    // Keepalive
    tcp.WithKeepaliveIdle(60*time.Second),
    tcp.WithKeepaliveInterval(10*time.Second),
    tcp.WithKeepaliveCount(3),

    // 超时
    tcp.WithFinWait2Timeout(30*time.Second),
    tcp.WithSynRcvdTimeout(15*time.Second),
    tcp.WithTimeWaitDuration(30*time.Second),
    tcp.WithDelayedACKTimeout(100*time.Millisecond),

    // 重传
    tcp.WithMinRTO(100*time.Millisecond),
    tcp.WithMaxRTO(30*time.Second),
    tcp.WithMaxRetries(10),
)

// UDP 层
udpHandler := udp.NewUDPHandler(s,
    udp.WithInboundQueueSize(1024),
)
```

### 接入 TUN 设备

内置 `channel/tun` 包，直接创建 Linux TUN 设备（需要 root 权限）：

```go
import "github.com/Zwlin98/netstack/channel/tun"

ch, err := tun.NewChannel("tun0", 1500)
if err != nil {
    log.Fatal(err)
}

s := stack.New(ch)
// ... 注册 handler、启动 ...
```

如需对接其他网络设备，实现 `channel.Channel` 接口即可：

```go
type Channel interface {
	ReadPacket(buf []byte) (int, error)  // 从设备读一个 IP 包
	WritePacket(data []byte) error       // 向设备写一个 IP 包
	Close() error
	MTU() int
}
```

### UDP 数据报收发

UDP handler 提供 `net.PacketConn` 风格的 API，上层自行决定如何处理数据（NAT 转发、过滤等）：

```go
udpHandler := udp.NewUDPHandler(s)
s.RegisterHandler(tcpip.UDPProtocolNumber, udpHandler)

go func() {
	buf := make([]byte, 1500)
	for {
		// 读取入站 UDP 数据报（纯 payload，不含协议头）
		n, src, dst, err := udpHandler.ReadFrom(buf)
		if err != nil {
			break
		}
		// src = 客户端地址, dst = 原始目标地址
		// 上层自行决定处理方式：转发、修改、丢弃...
		resp := handleUDP(dst, buf[:n])
		// 将响应写回客户端（handler 自动构建 UDP+IPv4 头）
		udpHandler.WriteTo(resp, dst, src)
	}
}()
```

## 包结构

| 包 | 说明 |
|---|------|
| `tcpip` | 核心类型：`Address`、`FullAddress`、协议号、错误定义 |
| `header` | 零拷贝协议头视图：IPv4、TCP、UDP、ICMPv4 + 校验和 |
| `packet` | `PacketBuffer` — 带 headroom 的包缓冲区，`sync.Pool` 复用 |
| `channel` | `Channel` 接口 + `MemoryChannel`（内存实现，用于测试） |
| `channel/tun` | Linux TUN 设备驱动，支持 GRO/校验和卸载 |
| `stack` | 协议栈核心：IPv4 解析、协议分发、ICMP、读写循环、`Config` + `Option` |
| `transport/tcp` | TCP 实现：`TCPHandler` / `TCPListener` / `TCPConn`、`Config` + `Option` |
| `transport/udp` | UDP 数据报收发：`UDPHandler`（ReadFrom / WriteTo）、`Config` + `Option` |

## TCP 状态机

```mermaid
stateDiagram-v2
    [*] --> SYN_RCVD : 收到 SYN
    SYN_RCVD --> ESTABLISHED : 收到 ACK
    ESTABLISHED --> FIN_WAIT_1 : Close()
    ESTABLISHED --> CLOSE_WAIT : 收到 FIN
    FIN_WAIT_1 --> FIN_WAIT_2 : 收到 ACK
    FIN_WAIT_2 --> TIME_WAIT : 收到 FIN
    CLOSE_WAIT --> LAST_ACK : Close()
    LAST_ACK --> [*] : 收到 ACK
    TIME_WAIT --> [*] : 2×MSL 超时
```

## 设计要点

- **IPv4-only** — 不支持 IPv6
- **服务端 TCP** — 支持 Listen/Accept，不支持主动 Dial
- **TUN 网关** — 面向内网设备，client→gateway 存在真实网络 RTT
- **gVisor 风格** — `[]byte` 命名类型作为协议头视图，零分配解析

## 测试

### 单元测试

```bash
go test ./...
```

TCP 测试包含从 [gVisor](https://github.com/google/gvisor) 移植的工业级测试用例，覆盖握手边界条件、拥塞控制、连接关闭和 RFC 合规性。

### 集成测试

集成测试通过 TUN 设备进行真实网络栈交互，需要 root 权限和 `tc`/`iperf3` 等工具：

```bash
# 运行全部集成测试
sudo ./test/run_all.sh

# 运行指定测试
sudo ./test/run_all.sh test/01_icmp.sh test/02_tcp_echo.sh
```

| 脚本 | 说明 |
|------|------|
| `01_icmp.sh` | ICMP Echo Reply（ping 响应） |
| `02_tcp_echo.sh` | TCP 回显基本功能 |
| `03_udp_echo.sh` | UDP 数据报收发 |
| `04_packet_loss.sh` | 丢包场景下的 TCP 重传恢复 |
| `05_concurrent.sh` | 多连接并发 |
| `06_iperf3.sh` | iperf3 吞吐量测试 |
| `07_reorder.sh` | 乱序报文处理 |
| `08_duplicate.sh` | 重复报文处理 |
| `09_jitter.sh` | 网络抖动场景 |
| `10_bandwidth.sh` | 带宽限制场景 |
| `11_large_transfer.sh` | 大数据量传输 |
| `12_stress.sh` | 高并发压力测试 |
| `13_combined.sh` | 组合网络劣化（丢包+延迟+乱序） |
| `14_zero_window.sh` | 零窗口探测 |
| `15_conn_lifecycle.sh` | 连接生命周期（建立→传输→关闭） |
| `16_half_close.sh` | 半关闭（单向 shutdown） |
| `17_abrupt_disconnect.sh` | 异常断开（RST 处理） |
