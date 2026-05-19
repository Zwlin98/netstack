package stack

import (
	"sort"
	"sync"
	"time"

	"github.com/Zwlin98/netstack/header"
	"github.com/Zwlin98/netstack/packet"
	"github.com/Zwlin98/netstack/tcpip"
)

const (
	ipv4ReassemblyTimeout       = 30 * time.Second
	ipv4ReassemblyHighThreshold = 4 << 20
	ipv4ReassemblyLowThreshold  = 3 << 20
	ipv4MaxPayloadSize          = 0xffff - header.IPv4MinHeaderSize
)

type ipv4FragmentKey struct {
	src   tcpip.Address
	dst   tcpip.Address
	id    uint16
	proto tcpip.TransportProtocolNumber
}

type ipv4Fragment struct {
	offset int
	data   []byte
}

type ipv4FragmentSet struct {
	createdAt time.Time
	header    []byte
	fragments []ipv4Fragment
	totalLen  int
	mem       int
}

type ipv4Reassembler struct {
	mu      sync.Mutex
	sets    map[ipv4FragmentKey]*ipv4FragmentSet
	mem     int
	timeout time.Duration
}

func newIPv4Reassembler() *ipv4Reassembler {
	return &ipv4Reassembler{
		sets:    make(map[ipv4FragmentKey]*ipv4FragmentSet),
		timeout: ipv4ReassemblyTimeout,
	}
}

// process consumes an IPv4 fragment packet. It returns a complete packet buffer
// when all fragments for the datagram have arrived.
func (r *ipv4Reassembler) process(pb *packet.PacketBuffer, ipHdr header.IPv4) (*packet.PacketBuffer, bool) {
	defer pb.Release()

	payloadLen := len(pb.Data)
	if payloadLen == 0 {
		return nil, false
	}

	offset := int(ipHdr.FragmentOffset()) * 8
	if offset < 0 || offset+payloadLen > ipv4MaxPayloadSize {
		return nil, false
	}
	if ipHdr.More() && payloadLen%8 != 0 {
		return nil, false
	}

	key := ipv4FragmentKey{
		src:   ipHdr.SourceAddress(),
		dst:   ipHdr.DestinationAddress(),
		id:    ipHdr.ID(),
		proto: ipHdr.Protocol(),
	}

	fragData := make([]byte, payloadLen)
	copy(fragData, pb.Data)

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.evictExpiredLocked(now)

	set := r.sets[key]
	if set == nil {
		set = &ipv4FragmentSet{
			createdAt: now,
			totalLen:  -1,
		}
		r.sets[key] = set
	}

	end := offset + payloadLen
	for _, frag := range set.fragments {
		fragEnd := frag.offset + len(frag.data)
		if end <= frag.offset || fragEnd <= offset {
			continue
		}
		if offset == frag.offset && end == fragEnd {
			return nil, false
		}
		r.releaseSetLocked(key, set)
		return nil, false
	}

	if offset == 0 {
		set.header = append(set.header[:0], pb.NetworkHeader...)
	}
	if !ipHdr.More() {
		if set.totalLen >= 0 && set.totalLen != end {
			r.releaseSetLocked(key, set)
			return nil, false
		}
		set.totalLen = end
	}

	set.fragments = append(set.fragments, ipv4Fragment{
		offset: offset,
		data:   fragData,
	})
	set.mem += payloadLen
	r.mem += payloadLen

	if set.totalLen >= 0 && set.header != nil && set.complete() {
		complete := set.assemble()
		r.releaseSetLocked(key, set)
		return complete, true
	}

	r.trimMemoryLocked()
	if r.sets[key] != set {
		return nil, false
	}

	return nil, false
}

func (s *ipv4FragmentSet) complete() bool {
	sort.Slice(s.fragments, func(i, j int) bool {
		return s.fragments[i].offset < s.fragments[j].offset
	})

	next := 0
	for _, frag := range s.fragments {
		if frag.offset != next {
			return false
		}
		next += len(frag.data)
		if next == s.totalLen {
			return true
		}
		if next > s.totalLen {
			return false
		}
	}
	return false
}

func (s *ipv4FragmentSet) assemble() *packet.PacketBuffer {
	hdrLen := len(s.header)
	raw := make([]byte, hdrLen+s.totalLen)
	copy(raw, s.header)
	for _, frag := range s.fragments {
		copy(raw[hdrLen+frag.offset:], frag.data)
	}

	ipHdr := header.IPv4(raw)
	ipHdr.SetTotalLength(uint16(len(raw)))
	ipHdr.SetFlagsFragmentOffset(0, 0)
	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(header.Checksum(raw[:hdrLen], 0))

	pb := packet.NewPacketBufferWithData(raw)
	pb.NetworkHeader = pb.Buf()[:hdrLen]
	pb.Data = pb.Buf()[hdrLen:len(raw)]
	return pb
}

func (r *ipv4Reassembler) evictExpiredLocked(now time.Time) {
	for key, set := range r.sets {
		if now.Sub(set.createdAt) > r.timeout {
			r.releaseSetLocked(key, set)
		}
	}
}

func (r *ipv4Reassembler) trimMemoryLocked() {
	for r.mem > ipv4ReassemblyHighThreshold {
		var oldestKey ipv4FragmentKey
		var oldestSet *ipv4FragmentSet
		for key, set := range r.sets {
			if oldestSet == nil || set.createdAt.Before(oldestSet.createdAt) {
				oldestKey = key
				oldestSet = set
			}
		}
		if oldestSet == nil {
			return
		}
		r.releaseSetLocked(oldestKey, oldestSet)
		if r.mem <= ipv4ReassemblyLowThreshold {
			return
		}
	}
}

func (r *ipv4Reassembler) releaseSetLocked(key ipv4FragmentKey, set *ipv4FragmentSet) {
	delete(r.sets, key)
	r.mem -= set.mem
	if r.mem < 0 {
		r.mem = 0
	}
}
