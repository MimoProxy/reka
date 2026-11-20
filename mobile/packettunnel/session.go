//go:build with_gvisor

// Package packettunnel runs one Reka outbound on a host-provided packet flow.
package packettunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

const (
	MTU       = 1280
	MaxBatch  = 16
	queueSize = 64
	maxTCP    = 32
	maxUDP    = 32
	Address4  = "198.18.0.1/30"
	Address6  = "fd83:7265:6b61::1/64"
)

type Node struct {
	Server   netip.Addr `json:"server"`
	Port     uint16     `json:"port"`
	Method   string     `json:"method"`
	Password string     `json:"password"`
}

type Session struct {
	ctx      context.Context
	cancel   context.CancelFunc
	input    sync.Mutex
	close    sync.Once
	device   *packetDevice
	backend  *sagernet.Backend
	outbound *sagernet.Outbound
	tunnel   io.Closer
	profile  *profileSession
}

func newSession() *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{ctx: ctx, cancel: cancel, device: &packetDevice{endpoint: channel.New(queueSize, MTU, "")}}
}

func Start(node Node) (*Session, error) {
	if !node.Server.IsValid() || node.Server.IsUnspecified() || node.Server.IsMulticast() ||
		node.Server.Zone() != "" || node.Port == 0 || node.Method == "" || node.Password == "" {
		return nil, errors.New("invalid Packet Tunnel node")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	backend := sagernet.New(sagernet.Options{Logger: logger})
	outbound, err := backend.NewOutbound("packet-tunnel", sagernet.ShadowsocksSpec{
		Server: node.Server.String(), Port: node.Port, Method: node.Method, Password: node.Password,
	})
	if err != nil {
		_ = backend.Close()
		return nil, err
	}
	backend.SetRoute(sagernet.Fixed(outbound))
	s := newSession()
	tunnel, err := backend.AttachPacketFlow(
		s.device, MTU, netip.MustParsePrefix(Address4), netip.MustParsePrefix(Address6), maxTCP, maxUDP, nil,
	)
	if err != nil {
		s.cancel()
		_ = outbound.Close()
		_ = backend.Close()
		return nil, err
	}
	s.backend, s.outbound, s.tunnel = backend, outbound, tunnel
	return s, nil
}

// Submit copies one host packet into the stack before returning. The host may
// reuse its buffer immediately.
func (s *Session) Submit(data []byte) bool {
	protocol, ok := packetProtocol(data)
	if !ok {
		return false
	}
	s.input.Lock()
	defer s.input.Unlock()
	if s.ctx.Err() != nil {
		return false
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
	defer packet.DecRef()
	s.device.endpoint.InjectInbound(protocol, packet)
	return true
}

// ReadBatch blocks for the first packet, then drains the available packets.
// The host provides one MTU-sized slot per length. Zero indicates shutdown.
func (s *Session) ReadBatch(output []byte, lengths []uint16) int {
	if len(lengths) == 0 || len(lengths) > MaxBatch || len(output) < len(lengths)*MTU {
		return 0
	}
	packet := s.device.endpoint.ReadContext(s.ctx)
	for written := 0; ; {
		if packet == nil || s.ctx.Err() != nil {
			if packet != nil {
				packet.DecRef()
			}
			return written
		}
		if packet.Size() <= MTU {
			lengths[written] = uint16(copyPacket(output[written*MTU:], packet))
			written++
		}
		packet.DecRef()
		if written == len(lengths) {
			return written
		}
		packet = s.device.endpoint.Read()
		// Oversized frames must not end the host's read loop.
		if packet == nil && written == 0 {
			packet = s.device.endpoint.ReadContext(s.ctx)
		}
	}
}

func (s *Session) Traffic() (upload, download uint64) {
	if s.profile != nil {
		return s.profile.engine.PacketFlowTraffic()
	}
	return s.backend.Traffic()
}

func (s *Session) Close() {
	s.close.Do(func() {
		s.cancel()
		s.input.Lock()
		defer s.input.Unlock()
		if s.profile != nil {
			s.profile.mu.Lock()
			defer s.profile.mu.Unlock()
			s.profile.engine.CloseConnections(nil)
			_ = s.tunnel.Close()
			s.profile.engine.Close()
			return
		}
		s.backend.SetRoute(sagernet.Fixed(nil))
		s.backend.CloseConnections(nil)
		_ = s.tunnel.Close()
		_ = s.outbound.Close()
		_ = s.backend.Close()
	})
}

func packetProtocol(data []byte) (tcpip.NetworkProtocolNumber, bool) {
	if len(data) == 0 || len(data) > MTU {
		return 0, false
	}
	switch data[0] >> 4 {
	case 4:
		if len(data) >= header.IPv4MinimumSize {
			destination := netip.AddrFrom4([4]byte(data[16:20]))
			return header.IPv4ProtocolNumber, destination.IsGlobalUnicast()
		}
	case 6:
		if len(data) >= header.IPv6MinimumSize {
			destination := netip.AddrFrom16([16]byte(data[24:40]))
			return header.IPv6ProtocolNumber, destination.IsGlobalUnicast()
		}
	}
	return 0, false
}

func copyPacket(output []byte, packet *stack.PacketBuffer) int {
	views, skip := packet.AsViewList()
	copied := 0
	for view := views.Front(); view != nil; view = view.Next() {
		data := view.AsSlice()
		if skip >= len(data) {
			skip -= len(data)
			continue
		}
		copied += copy(output[copied:], data[skip:])
		skip = 0
	}
	return copied
}

type packetDevice struct {
	endpoint *channel.Endpoint
}

var _ tun.GVisorTun = (*packetDevice)(nil)

func (d *packetDevice) Name() (string, error) { return "packet-flow", nil }
func (d *packetDevice) Start() error          { return nil }
func (d *packetDevice) Close() error          { d.endpoint.Close(); return nil }

func (d *packetDevice) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return d.endpoint, stack.NICOptions{}, nil
}

var errPacketFlowInterface = errors.New("packet-flow uses its link endpoint")

func (d *packetDevice) Read([]byte) (int, error)             { return 0, errPacketFlowInterface }
func (d *packetDevice) Write([]byte) (int, error)            { return 0, errPacketFlowInterface }
func (d *packetDevice) UpdateRouteOptions(tun.Options) error { return errPacketFlowInterface }

func (d *packetDevice) WritePacket(packet *stack.PacketBuffer) (int, error) {
	var packets stack.PacketBufferList
	packets.PushBack(packet)
	n, err := d.endpoint.WritePackets(packets)
	if n == 1 {
		return packet.Size(), nil
	}
	if err != nil {
		return 0, errors.New(err.String())
	}
	return 0, io.ErrShortWrite
}
