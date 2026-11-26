package sagernet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/MimoProxy/reka/internal/compat/ssr"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ssrOutboundOptions struct {
	option.DialerOptions
	option.ServerOptions
	Method        string             `json:"method"`
	Password      string             `json:"password"`
	Obfs          string             `json:"obfs"`
	ObfsParam     string             `json:"obfs_param"`
	Protocol      string             `json:"protocol"`
	ProtocolParam string             `json:"protocol_param"`
	UDP           *bool              `json:"udp"`
	Network       option.NetworkList `json:"network"`
}

type ssrOutbound struct {
	outbound.Adapter
	client *ssr.Client
	dialer N.Dialer
	server M.Socksaddr
	udp    bool
}

func newSSROutbound(ctx context.Context, tag string, o ssrOutboundOptions) (adapter.Outbound, error) {
	client, err := ssr.New(ssr.Config{
		Server: o.Server, Port: o.ServerPort, Password: o.Password, Method: o.Method,
		Obfs: o.Obfs, ObfsParam: o.ObfsParam, Protocol: o.Protocol, ProtocolParam: o.ProtocolParam,
	})
	if err != nil {
		return nil, err
	}
	d, err := dialer.New(ctx, o.DialerOptions, o.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	udp := o.UDP != nil && *o.UDP
	if o.Network != "" {
		networks := o.Network.Build()
		if !slices.Contains(networks, N.NetworkTCP) {
			return nil, errors.New("SSR network must include TCP")
		}
		networkUDP := slices.Contains(networks, N.NetworkUDP)
		if o.UDP != nil && networkUDP != udp {
			return nil, errors.New("SSR network and udp options disagree")
		}
		udp = networkUDP
	}
	networks := []string{N.NetworkTCP}
	if udp {
		networks = append(networks, N.NetworkUDP)
	}
	return &ssrOutbound{
		Adapter: outbound.NewAdapterWithDialerOptions("ssr", tag, networks, o.DialerOptions),
		client:  client, dialer: d, server: o.ServerOptions.Build(), udp: udp,
	}, nil
}

func (o *ssrOutbound) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkUDP:
		conn, err := o.ListenPacket(ctx, dst)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, dst), nil
	case N.NetworkTCP:
		ctx, metadata := adapter.ExtendContext(ctx)
		metadata.Outbound, metadata.Destination = o.Tag(), dst
		raw, err := o.dialer.DialContext(ctx, N.NetworkTCP, o.server)
		if err != nil {
			return nil, err
		}
		// Unlike an early Shadowsocks connection, setup writes the destination
		// before returning. Cancel a blocked write along with the dial.
		stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
		conn, err := o.client.StreamConn(raw, dst)
		if !stop() {
			return nil, ctx.Err()
		}
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("%w: %s", N.ErrUnknownNetwork, network)
	}
}

func (o *ssrOutbound) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	if !o.udp {
		return nil, errors.New("SSR UDP is disabled")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound, metadata.Destination = o.Tag(), dst
	raw, err := o.dialer.ListenPacket(ctx, o.server)
	if err != nil {
		return nil, err
	}
	var server net.Addr = o.server
	if o.server.IsIP() {
		server = o.server.UDPAddr()
	}
	return o.client.PacketConn(raw, server), nil
}
