package sagernet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	XC "github.com/MimoProxy/reka/internal/compat/xhttp"
	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	ST "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type xhttpStreamOptions struct {
	XC.Config
	Server           string              `json:"server,omitempty"`
	Port             uint16              `json:"port,omitempty"`
	DisableTLS       bool                `json:"disable-tls,omitempty"`
	TLS              *TLSSpec            `json:"reka_tls,omitempty"`
	DownloadSettings *xhttpStreamOptions `json:"download-settings,omitempty"`
}

type xhttpEndpoint struct {
	address M.Socksaddr
	alpn    string
	base    N.Dialer
	tls     ST.Config
	reality *realityClient
	autoECH func(context.Context, string) ([]byte, error)
	echName string
}

func xhttpALPN(t *TLSSpec) string {
	if t == nil || len(t.ALPN) == 0 {
		return "h2"
	}
	if len(t.ALPN) == 1 && (t.ALPN[0] == "h3" || t.ALPN[0] == "h2" || t.ALPN[0] == "http/1.1") {
		return t.ALPN[0]
	}
	return ""
}

func makeXHTTPEndpoint(ctx context.Context, logger log.ContextLogger, base N.Dialer, server string, port uint16, t *TLSSpec, configure bool) (*xhttpEndpoint, error) {
	e := &xhttpEndpoint{address: M.ParseSocksaddrHostPort(server, port), alpn: xhttpALPN(t), base: base}
	if e.alpn == "" {
		return nil, errors.New("xhttp TLS ALPN must include h2, http/1.1, or exclusively h3")
	}
	if t == nil {
		return e, nil
	}
	copy := *t
	copy.ALPN = []string{e.alpn}
	if copy.ServerName == "" {
		copy.ServerName = server
	}
	if copy.Reality != nil {
		if e.alpn == "h3" {
			return nil, errors.New("xhttp HTTP/3 cannot carry REALITY")
		}
		reality, err := newRealityClient(&copy)
		if err != nil {
			return nil, err
		}
		e.reality = reality
		return e, nil
	}
	if e.alpn == "h3" && (copy.Fingerprint != "" || copy.Carrier != nil) {
		return nil, errors.New("xhttp HTTP/3 cannot use TCP ClientHello presets or stream security carriers")
	}
	var err error
	var carrierConfigured, verificationConfigured *atomic.Bool
	if configure {
		// Download identities are independent. A missing download pin/carrier
		// must not inherit a main-endpoint context hook.
		ctx = context.WithValue(ctx, "reka.tls.configure.v1", struct{}{})
		ctx = context.WithValue(ctx, "reka.tls.client.v1", struct{}{})
		ctx, carrierConfigured = configureTLSCarrierContext(ctx, &copy)
		ctx, verificationConfigured = configureTLSContext(configureECHContext(ctx, &copy), &copy)
	}
	e.tls, err = ST.NewClient(ctx, logger, server, *copy.build())
	if copy.ECH != nil && copy.ECH.Config == "" {
		e.autoECH = copy.ECH.Lookup
		if e.autoECH == nil {
			e.autoECH, _ = ctx.Value("reka.tls.ech.lookup.v1").(func(context.Context, string) ([]byte, error))
		}
		e.echName = copy.ECH.QueryServerName
		if e.echName == "" {
			e.echName = copy.ServerName
		}
	}
	if err == nil && carrierConfigured != nil && !carrierConfigured.Load() {
		return nil, errors.New("required XHTTP download security carrier overlay is unavailable")
	}
	if err == nil && verificationConfigured != nil && !verificationConfigured.Load() {
		return nil, errors.New("required XHTTP download TLS verification overlay is unavailable")
	}
	return e, err
}

func (e *xhttpEndpoint) dialTCP(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := e.base.DialContext(ctx, N.NetworkTCP, e.address)
	if err != nil {
		return nil, err
	}
	if e.reality != nil {
		conn, err := e.reality.Handshake(ctx, raw)
		if err != nil {
			raw.Close()
		}
		return conn, err
	}
	if e.tls != nil {
		conn, err := ST.ClientHandshake(ctx, raw, e.tls)
		if err != nil {
			raw.Close()
		}
		return conn, err
	}
	return raw, nil
}
func (e *xhttpEndpoint) dialQUIC(ctx context.Context, cfg *quic.Config) (*quic.Conn, error) {
	if e.tls == nil {
		return nil, errors.New("xhttp HTTP/3 requires TLS")
	}
	tlsConfig := e.tls
	if e.autoECH != nil {
		// STDConfig has no context parameter. Resolve using this HTTP request's
		// scoped route pins before constructing the independent QUIC handshake.
		list, lookupErr := e.autoECH(ctx, e.echName)
		if lookupErr != nil {
			return nil, lookupErr
		}
		if len(list) == 0 {
			return nil, errors.New("empty XHTTP ECH configuration")
		}
		tlsConfig = e.tls.Clone()
		ech, ok := tlsConfig.(ST.ECHCapableConfig)
		if !ok {
			return nil, errors.New("XHTTP ECH TLS configuration is unavailable")
		}
		ech.SetECHConfigList(list)
	}
	config, err := tlsConfig.STDConfig()
	if err != nil {
		return nil, err
	}
	raw, err := e.base.DialContext(ctx, N.NetworkUDP, e.address)
	if err != nil {
		return nil, err
	}
	var remote *net.UDPAddr
	if actual, ok := raw.RemoteAddr().(*net.UDPAddr); ok {
		remote = actual
	} else if address, parseErr := netip.ParseAddrPort(raw.RemoteAddr().String()); parseErr == nil {
		remote = net.UDPAddrFromAddrPort(address)
	} else {
		remote = &net.UDPAddr{IP: net.IPv4zero, Port: int(e.address.Port)}
	}
	conn, err := quic.Dial(ctx, &dnsPacketConn{raw, remote}, remote, config, cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}
	context.AfterFunc(conn.Context(), func() { _ = raw.Close() })
	return conn, nil
}

func buildXHTTPStream(ctx context.Context, logger log.ContextLogger, values map[string]any, server string, port uint16, security *TLSSpec) (*XC.Client, error) {
	value := values["reka_xhttp"]
	if value == nil {
		return nil, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var opts xhttpStreamOptions
	if err = json.Unmarshal(data, &opts); err != nil {
		return nil, err
	}
	if opts.DownloadSettings != nil && opts.DownloadSettings.DownloadSettings != nil {
		return nil, errors.New("nested xhttp download settings")
	}
	opts.Config.DownloadConfig = nil
	if opts.Host == "" {
		opts.Host = server
	}
	data, err = json.Marshal(values)
	if err != nil {
		return nil, err
	}
	var physical option.DialerOptions
	if err = json.Unmarshal(data, &physical); err != nil {
		return nil, err
	}
	base, err := dialer.New(ctx, physical, M.ParseSocksaddrHostPort(server, port).IsDomain())
	if err != nil {
		return nil, err
	}
	up, err := makeXHTTPEndpoint(ctx, logger, base, server, port, security, false)
	if err != nil {
		return nil, err
	}
	if up.alpn == "h3" && security == nil {
		return nil, errors.New("xhttp HTTP/3 requires TLS")
	}
	down := up
	if ds := opts.DownloadSettings; ds != nil {
		if ds.Server == "" {
			ds.Server = server
		}
		if ds.Port == 0 {
			ds.Port = port
		}
		if ds.Host == "" {
			ds.Host = opts.Host
		}
		if ds.Path == "" {
			ds.Path = opts.Path
		}
		tls := ds.TLS
		if ds.DisableTLS && tls != nil {
			return nil, errors.New("xhttp download cannot disable TLS and configure TLS")
		}
		if ds.DisableTLS {
			tls = nil
		}
		if tls == nil && !ds.DisableTLS {
			tls = security
		}
		downloadBase, createErr := dialer.New(ctx, physical, M.ParseSocksaddrHostPort(ds.Server, ds.Port).IsDomain())
		if createErr != nil {
			return nil, fmt.Errorf("xhttp download dialer: %w", createErr)
		}
		down, err = makeXHTTPEndpoint(ctx, logger, downloadBase, ds.Server, ds.Port, tls, true)
		if err != nil {
			return nil, fmt.Errorf("xhttp download: %w", err)
		}
		opts.Config.DownloadConfig = &ds.Config
	}
	hooks := XHTTPHooks{DialTCP: func(ctx context.Context, download, _ bool) (net.Conn, error) {
		if download {
			return down.dialTCP(ctx)
		}
		return up.dialTCP(ctx)
	}, DialQUIC: func(ctx context.Context, download bool, cfg *quic.Config) (*quic.Conn, error) {
		if download {
			return down.dialQUIC(ctx, cfg)
		}
		return up.dialQUIC(ctx, cfg)
	}}
	return newXHTTPClient(XHTTPClientOptions{Config: &opts.Config, ALPN: []string{up.alpn}, DownloadALPN: []string{down.alpn}, HasReality: up.reality != nil, DownloadHasReality: down.reality != nil}, hooks)
}

// xhttpContext installs a stream dialer before VLESS framing. The physical
// dialer was captured first, retaining its original protect/detour context.
func xhttpContext(ctx context.Context, logger log.ContextLogger, values map[string]any, server string, port uint16, t *TLSSpec) (context.Context, *XC.Client, error) {
	client, err := buildXHTTPStream(ctx, logger, values, server, port, t)
	if err != nil || client == nil {
		return ctx, client, err
	}
	ctx = service.ExtendContext(ctx)
	service.MustRegister[adapter.OutboundManager](ctx, &singleOutboundManager{out: &xhttpOutboundDialer{Adapter: outbound.NewAdapter("direct", "reka-xhttp", []string{"tcp"}, nil), client: client}})
	for _, key := range []string{"reka_xhttp", "tls", "transport", "bind_interface", "routing_mark", "tcp_fast_open", "tcp_multi_path", "domain_strategy"} {
		delete(values, key)
	}
	values["detour"] = "reka-xhttp"
	return ctx, client, nil
}

type xhttpOutboundDialer struct {
	outbound.Adapter
	client *XC.Client
}

func (d *xhttpOutboundDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != "tcp" {
		return nil, errors.New("xhttp stream requires TCP")
	}
	return d.client.Dial(ctx)
}
func (d *xhttpOutboundDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("xhttp uses VLESS packet framing")
}

type xhttpV2RayTransport struct{ *XC.Client }

func (t *xhttpV2RayTransport) DialContext(ctx context.Context) (net.Conn, error) { return t.Dial(ctx) }
