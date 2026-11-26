package sagernet

import (
	"context"
	"net"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const tailscaleType = "tailscale"

type TailscaleOptions struct {
	StateDirectory string
	ControlURL     string
	AuthKey        string
	Hostname       string
	Ephemeral      bool
	AcceptRoutes   bool
	HostPacketFlow bool
}

type TailscaleDialer interface {
	DialContext(context.Context, string, M.Socksaddr) (net.Conn, error)
	ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error)
}

type TailscaleNode interface {
	TailscaleDialer
	Status() api.TailscaleStatus
	Close() error
}

type tailscaleOutbound struct {
	outbound.Adapter
	TailscaleDialer
}

// NewTailscaleOutbound gives the generation a lease on a borrowed dialer.
// The engine owns the node and its shutdown independently of that lease.
func (b *Backend) NewTailscaleOutbound(tag string, dialer TailscaleDialer) *Outbound {
	scope := adapter.NewScope(b.ctx, b.componentLogger("outbound", tailscaleType, tag))
	out := &tailscaleOutbound{
		Adapter:         outbound.NewAdapter(tailscaleType, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		TailscaleDialer: dialer,
	}
	return scopedOutbound(tag, tailscaleType, out, scope)
}
