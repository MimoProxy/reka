package sagernet

import (
	"context"
	"errors"
	"net"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const tailscaleType = "tailscale"

var errTailscaleUDPDisabled = errors.New("Tailscale UDP is disabled for this outbound")

type TailscaleOptions struct {
	TailscaleIdentity
	TailscalePreferences
}

type TailscaleIdentity struct {
	StateDirectory string
	ControlURL     string
	AuthKey        string
	Hostname       string
	Ephemeral      bool
	HostPacketFlow bool
}

type TailscalePreferences struct {
	AcceptRoutes           bool
	ExitNode               string
	ExitNodeAllowLANAccess bool
}

type TailscaleDialer interface {
	DialContext(context.Context, string, M.Socksaddr) (net.Conn, error)
	ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error)
}

type TailscaleNode interface {
	TailscaleDialer
	SetPreferences(TailscalePreferences) error
	Status() api.TailscaleStatus
	Close() error
}

type tailscaleOutbound struct {
	outbound.Adapter
	dialer TailscaleDialer
	udp    bool
}

// NewTailscaleOutbound gives the generation a lease on a borrowed dialer.
// The engine owns the node and its shutdown independently of that lease.
func (b *Backend) NewTailscaleOutbound(tag string, dialer TailscaleDialer, udp bool) *Outbound {
	scope := adapter.NewScope(b.ctx, b.componentLogger("outbound", tailscaleType, tag))
	networks := []string{N.NetworkTCP}
	if udp {
		networks = append(networks, N.NetworkUDP)
	}
	out := &tailscaleOutbound{
		Adapter: outbound.NewAdapter(tailscaleType, tag, networks, nil),
		dialer:  dialer,
		udp:     udp,
	}
	return scopedOutbound(tag, tailscaleType, out, scope)
}

func (o *tailscaleOutbound) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if !o.udp && N.NetworkName(network) == N.NetworkUDP {
		return nil, errTailscaleUDPDisabled
	}
	return o.dialer.DialContext(ctx, network, dst)
}

func (o *tailscaleOutbound) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	if !o.udp {
		return nil, errTailscaleUDPDisabled
	}
	return o.dialer.ListenPacket(ctx, dst)
}
