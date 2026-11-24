//go:build with_gvisor

package packettunnel

import (
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

const (
	icmpProbePrefix        = "REKAICMP"
	icmpProbeNonceSize     = 16
	icmpProbeReplyLifetime = 15 * time.Second
)

type syntheticEchoReply struct {
	nonce    [icmpProbeNonceSize]byte
	sequence uint16
	at       time.Time
}

type syntheticEchoReplies struct {
	mu      sync.Mutex
	entries [128]syntheticEchoReply
	next    int
}

func (d *packetDevice) ObserveSyntheticICMPEchoReply(sequence uint16, payload stack.PacketData) {
	const size = len(icmpProbePrefix) + icmpProbeNonceSize
	if payload.Size() != size {
		return
	}
	data, ok := payload.PullUp(size)
	if !ok || string(data[:len(icmpProbePrefix)]) != icmpProbePrefix {
		return
	}
	replies := &d.probes
	replies.mu.Lock()
	defer replies.mu.Unlock()
	replies.entries[replies.next] = syntheticEchoReply{
		nonce: [icmpProbeNonceSize]byte(data[len(icmpProbePrefix):]), sequence: sequence, at: time.Now(),
	}
	replies.next = (replies.next + 1) % len(replies.entries)
}

type icmpProbeProvenance struct {
	Synthetic bool `json:"synthetic"`
}

func (s *Session) icmpProbeProvenance(token string, sequence uint16) (icmpProbeProvenance, error) {
	var nonce [icmpProbeNonceSize]byte
	if len(token) != hex.EncodedLen(len(nonce)) {
		return icmpProbeProvenance{}, errors.New("invalid ICMP probe nonce")
	}
	if _, err := hex.Decode(nonce[:], []byte(token)); err != nil {
		return icmpProbeProvenance{}, errors.New("invalid ICMP probe nonce")
	}

	replies := &s.device.probes
	replies.mu.Lock()
	defer replies.mu.Unlock()
	cutoff := time.Now().Add(-icmpProbeReplyLifetime)
	for i := range replies.entries {
		reply := replies.entries[i]
		if reply.nonce == nonce && reply.sequence == sequence && reply.at.After(cutoff) {
			return icmpProbeProvenance{Synthetic: true}, nil
		}
	}
	return icmpProbeProvenance{}, nil
}
