package sagernet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common/json/badoption"
)

// Server is a proxy node that relays everything directly. Reka does not
// serve proxy protocols to the network; servers exist so tests and local
// tools can run a node on loopback.
type Server struct {
	b   *Backend
	in  *Inbound
	out *Outbound
}

// Close stops the server and the connections it relays.
func (s *Server) Close() error {
	err := errors.Join(s.in.Close(), s.out.Close())
	s.b.CloseConnections(nil)
	s.b.Close()
	return err
}

func startNode(logger *slog.Logger, build func(b *Backend) (adapter.Inbound, string, error)) (*Server, error) {
	return startNodeWithRoute(logger, Fixed, build)
}

func startNodeWithRoute(logger *slog.Logger, routes func(*Outbound) RouteFunc, build func(b *Backend) (adapter.Inbound, string, error)) (*Server, error) {
	b := New(Options{Logger: logger})
	out, err := b.NewOutbound("direct", DirectSpec{})
	if err != nil {
		b.Close()
		return nil, err
	}
	b.SetRoute(routes(out))
	in, typ, err := build(b)
	if err == nil {
		var adopted *Inbound
		if adopted, err = b.adoptInbound("server", typ, in, b.componentLogger("inbound", typ, "server")); err == nil {
			return &Server{b: b, in: adopted, out: out}, nil
		}
	}
	out.Close()
	b.Close()
	return nil, err
}

func listenOpts(listen netip.AddrPort) option.ListenOptions {
	addr := badoption.Addr(listen.Addr())
	return option.ListenOptions{Listen: &addr, ListenPort: listen.Port()}
}

// StartShadowsocksServer runs a Shadowsocks node on listen.
func StartShadowsocksServer(listen netip.AddrPort, method, password string, logger *slog.Logger) (*Server, error) {
	return startShadowsocksServer(listen, method, password, logger, Fixed)
}

// StartShadowsocksTestServer relays only explicitly mapped test addresses.
// The supplied targets are loopback services on the test host.
func StartShadowsocksTestServer(listen netip.AddrPort, method, password string, logger *slog.Logger, targets map[netip.AddrPort]netip.AddrPort) (*Server, error) {
	if len(targets) == 0 {
		return nil, errors.New("test node needs at least one target")
	}
	endpoints := make(map[netip.AddrPort]Destination, len(targets))
	for original, target := range targets {
		if !original.IsValid() || original.Port() == 0 || !target.Addr().IsLoopback() || target.Port() == 0 {
			return nil, errors.New("invalid test node target")
		}
		endpoints[original] = Destination{Addr: target.Addr(), Port: target.Port()}
	}
	return startShadowsocksServer(listen, method, password, logger, func(out *Outbound) RouteFunc {
		fixed := Fixed(out)
		return func(ctx context.Context, metadata Metadata) Route {
			destination, ok := endpoints[netip.AddrPortFrom(metadata.Destination.Addr, metadata.Destination.Port)]
			if !ok {
				return Route{}
			}
			route := fixed(ctx, metadata)
			route.Destination = &destination
			return route
		}
	})
}

func startShadowsocksServer(listen netip.AddrPort, method, password string, logger *slog.Logger, routes func(*Outbound) RouteFunc) (*Server, error) {
	return startNodeWithRoute(logger, routes, func(b *Backend) (adapter.Inbound, string, error) {
		in, err := shadowsocks.NewInbound(b.ctx, b.router, b.componentLogger("inbound", "shadowsocks", "server"), "server",
			option.ShadowsocksInboundOptions{ListenOptions: listenOpts(listen), Method: method, Password: password})
		return in, "shadowsocks", err
	})
}

// RealityServerOptions configure StartRealityServer.
type RealityServerOptions struct {
	Transport  json.RawMessage
	Multiplex  bool
	Listen     netip.AddrPort
	UUID       string
	Flow       string
	ServerName string
	// Target is the TLS site the server imitates for unauthenticated
	// clients.
	Target     netip.AddrPort
	PrivateKey []byte // X25519
	ShortID    string
}

// StartRealityServer runs a VLESS + REALITY node.
func StartRealityServer(o RealityServerOptions, logger *slog.Logger) (*Server, error) {
	if len(o.PrivateKey) != 32 {
		return nil, fmt.Errorf("reality: private key must be 32 bytes")
	}
	var transport *option.V2RayTransportOptions
	if len(o.Transport) > 0 {
		transport = &option.V2RayTransportOptions{}
		if err := json.Unmarshal(o.Transport, transport); err != nil {
			return nil, err
		}
	}
	var multiplex *option.InboundMultiplexOptions
	if o.Multiplex {
		multiplex = &option.InboundMultiplexOptions{Enabled: true}
	}
	return startNode(logger, func(b *Backend) (adapter.Inbound, string, error) {
		in, err := vless.NewInbound(b.ctx, b.router, b.componentLogger("inbound", "vless", "server"), "server", option.VLESSInboundOptions{
			ListenOptions: listenOpts(o.Listen),
			Transport:     transport, Multiplex: multiplex,
			Users: []option.VLESSUser{{Name: "user", UUID: o.UUID, Flow: o.Flow}},
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
				Enabled:    true,
				ServerName: o.ServerName,
				Reality: &option.InboundRealityOptions{
					Enabled: true,
					Handshake: option.InboundRealityHandshakeOptions{
						ServerOptions: option.ServerOptions{Server: o.Target.Addr().String(), ServerPort: o.Target.Port()},
					},
					PrivateKey: base64.RawURLEncoding.EncodeToString(o.PrivateKey),
					ShortID:    badoption.Listable[string]{o.ShortID},
				},
			}},
		})
		return in, "vless", err
	})
}
