package sagernet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/transport/v2ray"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// vlessRealityOutbound is a VLESS client over Reka's own REALITY client.
// sing-box's VLESS outbound builds its TLS client internally, so it cannot
// use a REALITY implementation that keeps the X25519MLKEM768 share. The
// VLESS framing, Vision and XUDP still come from sing-vmess.
//
// Non-Vision streams may use a V2Ray transport and client-owned multiplex.
type vlessRealityOutbound struct {
	httpObfs       *httpObfsOptions
	packetEncoding string
	outbound.Adapter
	h2         *option.V2RayHTTPOptions
	transport  adapter.V2RayClientTransport
	multiplex  *mux.Client
	logger     log.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	reality    *realityClient
	client     *vless.Client
}

var _ adapter.Outbound = (*vlessRealityOutbound)(nil)

func newVLESSRealityOutbound(ctx context.Context, logger log.ContextLogger, tag string, s VLESSSpec) (*vlessRealityOutbound, error) {
	serverAddr := M.ParseSocksaddrHostPort(s.Server, s.Port)
	var extra struct {
		PacketEncoding *string `json:"packet_encoding"`
		option.DialerOptions
		HTTP      *httpObfsOptions                 `json:"reka_http"`
		Transport *option.V2RayTransportOptions    `json:"transport"`
		Multiplex *option.OutboundMultiplexOptions `json:"multiplex"`
	}
	if len(s.Options) > 0 {
		if err := json.Unmarshal(s.Options, &extra); err != nil {
			return nil, err
		}
	}
	if extra.BindInterface != "" {
		if manager, ok := service.FromContext[adapter.NetworkManager](ctx).(*networkManager); ok && manager.protect != nil {
			ctx = service.ExtendContext(ctx)
			service.MustRegister[adapter.NetworkManager](ctx, &networkManager{protect: manager.protect, explicitProtect: true})
		}
	}
	outboundDialer, err := dialer.New(ctx, extra.DialerOptions, serverAddr.IsDomain())
	if err != nil {
		return nil, err
	}
	if (extra.Transport != nil || extra.HTTP != nil) && len(s.TLS.ALPN) == 0 {
		copy := *s.TLS
		s.TLS = &copy
		if extra.Transport != nil && (extra.Transport.Type == "grpc" || extra.Transport.Type == "http") {
			s.TLS.ALPN = []string{"h2"}
		} else {
			s.TLS.ALPN = []string{"http/1.1"}
		}
	}
	reality, err := newRealityClient(s.TLS)
	if err != nil {
		return nil, err
	}
	client, err := vless.NewClient(s.UUID, s.Flow, logger)
	if err != nil {
		return nil, err
	}
	encoding := "xudp"
	if extra.PacketEncoding != nil {
		encoding = *extra.PacketEncoding
	}
	h := &vlessRealityOutbound{
		packetEncoding: encoding,
		httpObfs:       extra.HTTP,
		Adapter:        outbound.NewAdapter("vless", tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		logger:         logger,
		dialer:         outboundDialer,
		serverAddr:     serverAddr,
		reality:        reality,
		client:         client,
	}

	if extra.Transport != nil && extra.Transport.Type == "http" {
		h.h2 = &extra.Transport.HTTPOptions
	} else if extra.Transport != nil {
		h.transport, err = v2ray.NewClientTransport(ctx, &realityTransportDialer{h}, serverAddr, *extra.Transport, nil)
		if err != nil {
			return nil, err
		}
	}
	if extra.Multiplex != nil {
		h.multiplex, err = mux.NewClientWithOptions(&realityFramingDialer{h}, logger, *extra.Multiplex)
		if err != nil {
			h.Close()
			return nil, err
		}
	}
	return h, nil
}

func (h *vlessRealityOutbound) connect(ctx context.Context) (net.Conn, error) {
	if h.transport != nil {
		return h.transport.DialContext(ctx)
	}
	c, err := h.connectRaw(ctx)
	if err == nil && h.h2 != nil {
		return newH2Stream(ctx, c, *h.h2)
	}
	if err == nil && h.httpObfs != nil {
		c = newHTTPObfsConn(c, h.serverAddr.AddrString(), *h.httpObfs)
	}
	return c, err
}
func (h *vlessRealityOutbound) connectRaw(ctx context.Context) (net.Conn, error) {
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

func (h *vlessRealityOutbound) dialFramed(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
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
		switch h.packetEncoding {
		case "packetaddr":
			if destination.IsDomain() {
				conn.Close()
				return nil, errors.New("packetaddr requires a resolved IP destination")
			}
			framed, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
			if err != nil {
				conn.Close()
				return nil, err
			}
			return bufio.NewBindPacketConn(packetaddr.NewConn(framed, destination), destination), nil
		case "":
			return h.client.DialEarlyPacketConn(conn, destination)
		default:
			return h.client.DialEarlyXUDPPacketConn(conn, destination)
		}
	}
	return h.client.DialEarlyConn(conn, destination)
}

func (h *vlessRealityOutbound) packetFramed(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	conn, err := h.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", h.serverAddr, err)
	}
	switch h.packetEncoding {
	case "packetaddr":
		if destination.IsDomain() {
			conn.Close()
			return nil, errors.New("packetaddr requires a resolved IP destination")
		}
		framed, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
		if err != nil {
			conn.Close()
			return nil, err
		}
		return packetaddr.NewConn(framed, destination), nil
	case "":
		return h.client.DialEarlyPacketConn(conn, destination)
	default:
		return h.client.DialEarlyXUDPPacketConn(conn, destination)
	}
}

func (h *vlessRealityOutbound) DialContext(ctx context.Context, network string, d M.Socksaddr) (net.Conn, error) {
	if h.multiplex != nil {
		return h.multiplex.DialContext(ctx, network, d)
	}
	return h.dialFramed(ctx, network, d)
}
func (h *vlessRealityOutbound) ListenPacket(ctx context.Context, d M.Socksaddr) (net.PacketConn, error) {
	if h.multiplex != nil {
		return h.multiplex.ListenPacket(ctx, d)
	}
	return h.packetFramed(ctx, d)
}
func (h *vlessRealityOutbound) Close() error {
	var errs []error
	if h.multiplex != nil {
		errs = append(errs, h.multiplex.Close())
	}
	if h.transport != nil {
		errs = append(errs, h.transport.Close())
	}
	return errors.Join(errs...)
}

type realityTransportDialer struct{ h *vlessRealityOutbound }

func (d *realityTransportDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return d.h.connectRaw(ctx)
}
func (d *realityTransportDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("REALITY transport requires TCP")
}

type realityFramingDialer struct{ h *vlessRealityOutbound }

func (d *realityFramingDialer) DialContext(ctx context.Context, n string, a M.Socksaddr) (net.Conn, error) {
	return d.h.dialFramed(ctx, n, a)
}
func (d *realityFramingDialer) ListenPacket(ctx context.Context, a M.Socksaddr) (net.PacketConn, error) {
	return d.h.packetFramed(ctx, a)
}
