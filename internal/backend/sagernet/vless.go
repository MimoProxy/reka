package sagernet

import (
	"context"
	"fmt"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// vlessRealityOutbound is a VLESS client over Reka's own REALITY client.
// sing-box's VLESS outbound builds its TLS client internally, so it cannot
// use a REALITY implementation that keeps the X25519MLKEM768 share. The
// VLESS framing, Vision and XUDP still come from sing-vmess.
//
// Raw TCP transport only; no multiplex.
type vlessRealityOutbound struct {
	outbound.Adapter
	logger     log.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	reality    *realityClient
	client     *vless.Client
}

var _ adapter.Outbound = (*vlessRealityOutbound)(nil)

func newVLESSRealityOutbound(ctx context.Context, logger log.ContextLogger, tag string, s VLESSSpec) (*vlessRealityOutbound, error) {
	serverAddr := M.ParseSocksaddrHostPort(s.Server, s.Port)
	outboundDialer, err := dialer.New(ctx, option.DialerOptions{}, serverAddr.IsDomain())
	if err != nil {
		return nil, err
	}
	reality, err := newRealityClient(s.TLS)
	if err != nil {
		return nil, err
	}
	client, err := vless.NewClient(s.UUID, s.Flow, logger)
	if err != nil {
		return nil, err
	}
	return &vlessRealityOutbound{
		Adapter:    outbound.NewAdapter("vless", tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: serverAddr,
		reality:    reality,
		client:     client,
	}, nil
}

func (h *vlessRealityOutbound) connect(ctx context.Context) (net.Conn, error) {
	conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	tlsConn, err := h.reality.Handshake(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (h *vlessRealityOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	conn, err := h.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", h.serverAddr, err)
	}
	if N.NetworkName(network) == N.NetworkUDP {
		return h.client.DialEarlyXUDPPacketConn(conn, destination)
	}
	return h.client.DialEarlyConn(conn, destination)
}

func (h *vlessRealityOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	conn, err := h.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", h.serverAddr, err)
	}
	return h.client.DialEarlyXUDPPacketConn(conn, destination)
}
