package sagernet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"

	"github.com/enfein/mieru/v3/apis/client"
	apicommon "github.com/enfein/mieru/v3/apis/common"
	mierulog "github.com/enfein/mieru/v3/apis/log"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var _ adapter.OutboundWithMultiplex = (*mieruOutbound)(nil)

var mieruLogOnce sync.Once

type mieruOutbound struct {
	outbound.Adapter
	client    client.Client
	udp       bool
	multiplex bool

	physical  *mieruDialer
	cancel    context.CancelFunc
	mu        sync.RWMutex
	startOnce sync.Once
	startErr  error
}

type mieruOptions struct {
	option.ServerOptions
	option.DialerOptions
	ServerPorts    []string `json:"server_ports"`
	Transport      string   `json:"transport"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	Multiplexing   string   `json:"multiplexing"`
	HandshakeMode  string   `json:"handshake_mode"`
	TrafficPattern string   `json:"traffic_pattern"`
	UDP            bool     `json:"udp"`
}

func newMieruOutbound(ctx context.Context, tag string, data []byte) (adapter.Outbound, error) {
	var o mieruOptions
	if err := json.UnmarshalDisallowUnknownFields(data, &o); err != nil {
		return nil, err
	}
	if o.TCPFastOpen || o.TCPMultiPath {
		return nil, errors.New("Mieru does not support TCP Fast Open or MPTCP")
	}
	profile, err := o.profile(tag)
	if err != nil {
		return nil, err
	}
	d, err := dialer.New(ctx, o.DialerOptions, o.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	physical := &mieruDialer{base: d, lifetime: lifetime}
	config := &client.ClientConfig{
		Profile: profile, Dialer: physical, PacketDialer: physical,
		// TCP passes the hostname to Reka's dialer, including a detour.
		DNSConfig: &apicommon.ClientDNSConfig{BypassDialerDNS: true},
	}
	if o.Transport == "UDP" && o.ServerIsDomain() {
		// Mieru needs a numeric peer for WriteTo. Use the same DNS router,
		// flow context and address-family strategy as Reka's stream dialer.
		config.Resolver = mieruResolver{service.FromContext[adapter.DNSRouter](ctx), C.DomainStrategy(o.DomainStrategy)}
	}
	// Mieru's logger is process-wide, shared by all outbound generations.
	mieruLogOnce.Do(func() { mierulog.SetLevel("ERROR") })
	c := client.NewClient()
	if err := c.Store(config); err != nil {
		cancel()
		return nil, err
	}
	networks := []string{N.NetworkTCP}
	if o.UDP {
		networks = append(networks, N.NetworkUDP)
	}
	return &mieruOutbound{
		Adapter:   outbound.NewAdapterWithDialerOptions("mieru", tag, networks, o.DialerOptions),
		client:    c,
		udp:       o.UDP,
		multiplex: profile.GetMultiplexing().GetLevel() != pb.MultiplexingLevel_MULTIPLEXING_OFF,
		physical:  physical,
		cancel:    cancel,
	}, nil
}

func (o mieruOptions) profile(tag string) (*pb.ClientProfile, error) {
	binding := &pb.PortBinding{}
	switch o.Transport {
	case "TCP":
		binding.Protocol = pb.TransportProtocol_TCP.Enum()
	case "UDP":
		binding.Protocol = pb.TransportProtocol_UDP.Enum()
	default:
		return nil, errors.New("Mieru transport must be TCP or UDP")
	}
	switch {
	case o.ServerPort != 0 && len(o.ServerPorts) == 0:
		binding.Port = new(int32(o.ServerPort))
	case o.ServerPort == 0 && len(o.ServerPorts) == 1:
		binding.PortRange = &o.ServerPorts[0]
	default:
		return nil, errors.New("Mieru requires either a port or one port range")
	}
	server := &pb.ServerEndpoint{PortBindings: []*pb.PortBinding{binding}}
	if o.ServerIsDomain() {
		server.DomainName = &o.Server
	} else {
		server.IpAddress = &o.Server
	}
	profile := &pb.ClientProfile{
		ProfileName: &tag,
		Servers:     []*pb.ServerEndpoint{server},
		User:        &pb.User{Name: &o.Username, Password: &o.Password},
	}
	if o.Multiplexing != "" {
		level, ok := pb.MultiplexingLevel_value[o.Multiplexing]
		if !ok {
			return nil, fmt.Errorf("invalid Mieru multiplexing %q", o.Multiplexing)
		}
		profile.Multiplexing = &pb.MultiplexingConfig{Level: pb.MultiplexingLevel(level).Enum()}
	}
	if o.HandshakeMode != "" {
		mode, ok := pb.HandshakeMode_value[o.HandshakeMode]
		if !ok {
			return nil, fmt.Errorf("invalid Mieru handshake mode %q", o.HandshakeMode)
		}
		profile.HandshakeMode = pb.HandshakeMode(mode).Enum()
	}
	if o.TrafficPattern != "" {
		pattern, err := trafficpattern.Decode(o.TrafficPattern)
		if err != nil {
			return nil, fmt.Errorf("decode Mieru traffic pattern: %w", err)
		}
		profile.TrafficPattern = pattern // Client.Store validates the decoded pattern.
	}
	return profile, nil
}

type mieruDialer struct {
	base     N.Dialer
	lifetime context.Context
	sockets  interrupt.Group
}

func (d *mieruDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.base.DialContext(adapter.ContextForMultiplexSession(ctx), network, M.ParseSocksaddr(address))
	if err != nil {
		return nil, err
	}
	conn = d.sockets.NewConn(conn, false)
	if d.lifetime.Err() != nil {
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (d *mieruDialer) ListenPacket(ctx context.Context, _, _, remote string) (net.PacketConn, error) {
	// Mieru's packet underlay requests an ephemeral local port, passing an empty local address.
	addr, err := netip.ParseAddrPort(remote)
	if err != nil {
		return nil, fmt.Errorf("invalid Mieru UDP server address %q: %w", remote, err)
	}
	conn, err := d.base.ListenPacket(adapter.ContextForMultiplexSession(ctx), M.SocksaddrFromNetIP(addr))
	if err != nil {
		return nil, err
	}
	conn = d.sockets.NewPacketConn(conn, false)
	if d.lifetime.Err() != nil {
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	return conn, nil
}

type mieruResolver struct {
	router   adapter.DNSRouter
	strategy C.DomainStrategy
}

func (r mieruResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	strategy := r.strategy
	switch network {
	case "ip", "":
	case "ip4":
		strategy = C.DomainStrategyIPv4Only
	case "ip6":
		strategy = C.DomainStrategyIPv6Only
	default:
		return nil, net.UnknownNetworkError(network)
	}
	addresses, err := r.router.Lookup(ctx, host, adapter.DNSQueryOptions{Strategy: strategy})
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addresses))
	for _, addr := range addresses {
		ips = append(ips, net.IP(addr.AsSlice()))
	}
	return ips, nil
}

func (m *mieruOutbound) MultiplexEnabled() bool { return m.multiplex }

func (m *mieruOutbound) dial(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.physical.lifetime.Err() != nil {
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.startOnce.Do(func() { m.startErr = m.client.Start() })
	if m.startErr != nil {
		return nil, fmt.Errorf("start Mieru client: %w", m.startErr)
	}
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.physical.lifetime, cancel)
	defer cancel()
	defer stop()
	conn, err := m.client.DialContext(dialCtx, model.NetAddrSpec{
		Net: network, AddrSpec: model.AddrSpec{IP: dst.Addr.AsSlice(), FQDN: dst.Fqdn, Port: int(dst.Port)},
	})
	if m.physical.lifetime.Err() != nil {
		err = net.ErrClosed
	} else if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		// A failed standard handshake can still return an open session.
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	return conn, nil
}

func (m *mieruOutbound) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return m.dial(ctx, N.NetworkTCP, dst)
	case N.NetworkUDP:
		conn, err := m.ListenPacket(ctx, dst)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, dst), nil
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

func (m *mieruOutbound) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	if !m.udp {
		return nil, errors.New("UDP is disabled for this Mieru outbound")
	}
	conn, err := m.dial(ctx, N.NetworkUDP, dst)
	if err != nil {
		return nil, err
	}
	frames := &mieruPacketFrames{PacketConn: apicommon.NewPacketOverStreamTunnel(conn)}
	return &mieruPacketConn{PacketConn: apicommon.NewUDPAssociateWrapper(frames)}, nil
}

func (m *mieruOutbound) Close() error {
	// A forced close can race both DNS/dial and the standard SOCKS handshake.
	// Wake socket I/O as well, then let Stop collect the finished underlays.
	m.cancel()
	m.physical.sockets.Interrupt(true)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client.IsRunning() {
		return m.client.Stop()
	}
	return nil
}

type mieruPacketFrames struct {
	net.PacketConn
	readMu sync.Mutex
}

func (f *mieruPacketFrames) ReadFrom(p []byte) (int, net.Addr, error) {
	// PacketOverStreamTunnel consumes a frame in several reads. Keep concurrent
	// readers on frame boundaries, including when a caller supplies a short buffer.
	f.readMu.Lock()
	defer f.readMu.Unlock()
	b := p
	if len(b) < math.MaxUint16 { // Mieru frames have a uint16 length prefix.
		b = buf.Get(math.MaxUint16)
		defer buf.Put(b)
	}
	n, _, err := f.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	// Only the UDP associate header supplies a datagram's source address.
	return copy(p, b[:n]), nil, nil
}

type mieruPacketConn struct{ net.PacketConn }

func (c *mieruPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == io.EOF && addr != nil {
		// UDPAssociateWrapper uses bytes.Reader for the payload of a decoded datagram.
		// Its EOF here identifies a valid empty datagram; transport EOF has no address.
		err = nil
	}
	return n, addr, err
}

func (c *mieruPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	_, addr, err := buffer.ReadPacketFrom(c)
	return M.SocksaddrFromNet(addr), err
}

func (c *mieruPacketConn) WritePacket(buffer *buf.Buffer, dst M.Socksaddr) error {
	defer buffer.Release()
	// Keep a flow's domain name in the SOCKS UDP header when the router supplies one.
	_, err := c.WriteTo(buffer.Bytes(), dst)
	return err
}
