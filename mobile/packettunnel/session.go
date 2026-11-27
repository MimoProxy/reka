//go:build with_gvisor

// Package packettunnel runs Reka on a host-provided packet flow.
package packettunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

const (
	DefaultMTU = 1280
	maxMTU     = 4064
	MaxBatch   = 64
	queueSize  = 1024
	maxTCP     = 128
	maxUDP     = 128
	Address4   = "198.18.0.1/30"
	Address6   = "fd83:7265:6b61::1/64"

	// Packet Tunnel has a memory budget of roughly 50 MB. Sing-box's libbox
	// keeps 1000 closed connection summaries without event timelines. Keep
	// 64 rows here, with enough bytes for connection rows of about 3 KiB.
	eventRows            = 64
	eventBytes           = 96 << 10
	connectionEventBytes = 192 << 10
	// Requests are kept longer so a rewritten or scripted request is still
	// listed after a page loads its images. A request row takes about
	// 1.3 KiB with its search text, so 256 rows add about 230 KiB.
	requestEventRows  = 256
	requestEventBytes = 320 << 10
	// A script run row takes about 1 KiB with its search text. A background
	// run also keeps up to 16 KiB of logs and value as its detail.
	scriptEventRows  = 128
	scriptEventBytes = 192 << 10
)

var configuredMTU atomic.Int32

func init() {
	configuredMTU.Store(DefaultMTU)
}

// SetMTU sets the packet MTU for future sessions. It reports whether mtu is
// in the supported range from 1280 to 4064 bytes.
func SetMTU(mtu int) bool {
	if mtu < DefaultMTU || mtu > maxMTU {
		return false
	}
	configuredMTU.Store(int32(mtu))
	return true
}

type Node struct {
	Server   netip.Addr `json:"server"`
	Port     uint16     `json:"port"`
	Method   string     `json:"method"`
	Password string     `json:"password"`
}

type Session struct {
	ctx       context.Context
	cancel    context.CancelFunc
	mtu       int
	input     sync.Mutex
	close     sync.Once
	device    *packetDevice
	backend   *sagernet.Backend
	outbound  *sagernet.Outbound
	tunnel    *sagernet.PacketFlow
	profile   *profileSession
	events    *history.Store
	logger    *slog.Logger
	logs      tunnelLogHandler
	started   time.Time
	ranking   trafficRanking
	speed     speedTestState
	guard     *memoryGuard
	guardOnce sync.Once
}

func newSession() *Session {
	mtu := int(configuredMTU.Load())
	ctx, cancel := context.WithCancel(context.Background())
	events := history.NewBoundedByKind(map[history.Kind]history.Limit{
		history.DNS:         {Rows: eventRows, Bytes: eventBytes},
		history.Logs:        {Rows: eventRows, Bytes: eventBytes},
		history.Connections: {Rows: eventRows, Bytes: connectionEventBytes},
		history.Requests:    {Rows: requestEventRows, Bytes: requestEventBytes},
		history.Scripts:     {Rows: scriptEventRows, Bytes: scriptEventBytes},
	})
	logs := newTunnelLogHandler(events)
	now := time.Now()
	return &Session{
		ctx: ctx, cancel: cancel, mtu: mtu, device: &packetDevice{endpoint: channel.New(queueSize, uint32(mtu), "")},
		events: events, logger: slog.New(logs), logs: logs, started: now, ranking: trafficRanking{sinceMS: now.UnixMilli()},
	}
}

func (s *Session) backendOptions() sagernet.Options {
	return sagernet.Options{
		History: s.events, Logger: s.logger.With("component", "core"), OnConnectionClosed: s.ranking.recordClosed,
		// On iOS the Go resolver keeps working inside the extension; a macOS
		// system extension needs the system resolver to look up servers.
		SystemResolver: runtime.GOOS == "darwin",
		// A macOS system extension can read the system socket table to find
		// the process behind a tunnel flow, as the desktop daemon does. iOS
		// does not expose other apps' sockets.
		FindProcess: runtime.GOOS == "darwin",
	}
}

func Start(node Node) (*Session, error) {
	if !node.Server.IsValid() || node.Server.IsUnspecified() || node.Server.IsMulticast() ||
		node.Server.Zone() != "" || node.Port == 0 || node.Method == "" || node.Password == "" {
		return nil, errors.New("invalid Packet Tunnel node")
	}
	s := newSession()
	backend := sagernet.New(s.backendOptions())
	outbound, err := backend.NewOutbound("packet-tunnel", sagernet.ShadowsocksSpec{
		Server: node.Server.String(), Port: node.Port, Method: node.Method, Password: node.Password,
	})
	if err != nil {
		s.cancel()
		_ = backend.Close()
		return nil, err
	}
	backend.SetRoute(sagernet.Fixed(outbound))
	tunnel, err := backend.AttachPacketFlow(
		s.device, s.mtu, netip.MustParsePrefix(Address4), netip.MustParsePrefix(Address6), maxTCP, maxUDP, nil,
	)
	if err != nil {
		s.cancel()
		_ = outbound.Close()
		_ = backend.Close()
		return nil, err
	}
	s.backend, s.outbound, s.tunnel = backend, outbound, tunnel
	setProfileFlows(tunnel.Active)
	s.captureDefaultLogger()
	s.logger.Info("Packet tunnel started", "mode", "node", "mtu", s.mtu, "method", node.Method)
	return s, nil
}

// MTU returns the packet size limit and read slot size for this session.
func (s *Session) MTU() int { return s.mtu }

// Submit copies one host packet into the stack before returning. The host may
// reuse its buffer immediately.
func (s *Session) Submit(data []byte) bool {
	protocol, ok := packetProtocol(data, s.mtu)
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
// The host provides one slot of s.MTU() bytes per length. Zero indicates shutdown.
func (s *Session) ReadBatch(output []byte, lengths []uint16) int {
	mtu := s.mtu
	if len(lengths) == 0 || len(lengths) > MaxBatch || len(output) < len(lengths)*mtu {
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
		if packet.Size() <= mtu {
			offset := written * mtu
			lengths[written] = uint16(copyPacket(output[offset:offset+mtu], packet))
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
		if s.tunnel != nil {
			setProfileFlows(nil)
			upload, download := s.Traffic()
			connections, _ := s.Counts()
			s.logger.Info("Packet tunnel stopping", "uptime", time.Since(s.started).Round(time.Second),
				"uploaded", upload, "downloaded", download, "connections", connections)
		}
		s.releaseDefaultLogger()
		defer s.logs.sink.close()
		s.guardOnce.Do(func() {})
		if s.guard != nil {
			s.guard.stop()
		}
		s.cancel()
		s.input.Lock()
		defer s.input.Unlock()
		if s.profile != nil {
			s.profile.mu.Lock()
			defer s.profile.mu.Unlock()
			s.profile.engine.CloseConnections(nil)
			if s.tunnel != nil {
				_ = s.tunnel.Close()
			} else {
				s.device.endpoint.Close()
			}
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

func packetProtocol(data []byte, mtu int) (tcpip.NetworkProtocolNumber, bool) {
	if len(data) == 0 || len(data) > mtu {
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
	probes   syntheticEchoReplies
	// Packets the stack handed to the host queue, and those dropped because
	// the queue was full.
	written, dropped atomic.Uint64
}

// countingEndpoint records how many outbound packets the host queue accepts.
type countingEndpoint struct {
	*channel.Endpoint
	device *packetDevice
}

func (e countingEndpoint) WritePackets(packets stack.PacketBufferList) (int, tcpip.Error) {
	total := packets.Len()
	n, err := e.Endpoint.WritePackets(packets)
	e.device.written.Add(uint64(n))
	if n < total {
		e.device.dropped.Add(uint64(total - n))
	}
	return n, err
}

var _ tun.GVisorTun = (*packetDevice)(nil)

func (d *packetDevice) Name() (string, error) { return "packet-flow", nil }
func (d *packetDevice) Start() error          { return nil }
func (d *packetDevice) Close() error          { d.endpoint.Close(); return nil }

func (d *packetDevice) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return countingEndpoint{Endpoint: d.endpoint, device: d}, stack.NICOptions{}, nil
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
