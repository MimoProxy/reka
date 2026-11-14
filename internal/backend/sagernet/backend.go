package sagernet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

// Options configures a Backend.
type Options struct {
	// Logger receives all upstream logs. Defaults to slog.Default().
	Logger *slog.Logger
	// Protect, when set, is applied to every outbound socket before it
	// connects. On Android it calls VpnService.protect().
	Protect control.Func
	// HalfCloseTimeout bounds how long a relay keeps receiving after the
	// client half-closed and the outbound connection cannot. Default 2s.
	HalfCloseTimeout time.Duration
}

const defaultHalfCloseTimeout = 2 * time.Second

// Backend owns the upstream service context. Inbounds and outbounds created
// from it are independent instances: each has its own lifecycle scope and can
// be closed without touching the others.
type Backend struct {
	ctx    context.Context
	cancel context.CancelFunc
	slog   *slog.Logger
	logger *slogLogger
	router *router

	halfCloseTimeout time.Duration
}

// New builds the upstream context with only the services the enabled
// protocols look up: network manager, DNS router and DNS transport manager.
// Everything else upstream reads from the context is nil-tolerant.
func New(opts Options) *Backend {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = service.ContextWithDefaultRegistry(ctx)
	b := &Backend{
		ctx:    ctx,
		cancel: cancel,
		slog:   opts.Logger,
		logger: newLogger(opts.Logger, "backend"),

		halfCloseTimeout: opts.HalfCloseTimeout,
	}
	if b.halfCloseTimeout <= 0 {
		b.halfCloseTimeout = defaultHalfCloseTimeout
	}
	b.router = &router{backend: b}
	service.MustRegister[adapter.NetworkManager](ctx, &networkManager{protect: opts.Protect})
	service.MustRegister[adapter.DNSRouter](ctx, &dnsRouter{resolver: net.DefaultResolver})
	service.MustRegister[adapter.DNSTransportManager](ctx, &dnsTransportManager{})
	service.MustRegister[adapter.Router](ctx, b.router)
	return b
}

// SetRoute atomically replaces the routing function. Connections already
// relaying keep the outbound they were given.
func (b *Backend) SetRoute(fn RouteFunc) {
	b.router.setRoute(fn)
}

// Close cancels the shared context. Callers close their inbounds and
// outbounds first.
func (b *Backend) Close() error {
	b.cancel()
	return nil
}

func (b *Backend) componentLogger(kind, typ, tag string) log.ContextLogger {
	return newLogger(b.slog, fmt.Sprintf("%s/%s[%s]", kind, typ, tag))
}

// start runs every upstream start stage for one component inside its own
// scope, so closing that scope releases exactly what the component opened.
func (b *Backend) start(name string, component any, logger log.ContextLogger) (*adapter.Scope, error) {
	scope := adapter.NewScope(b.ctx, logger)
	if lc, ok := component.(adapter.Lifecycle); ok {
		for _, stage := range adapter.ListStartStages {
			if err := scope.Start(name, lc, stage); err != nil {
				_ = scope.Close()
				return nil, err
			}
		}
	}
	return scope, nil
}

// Outbound is one upstream outbound instance.
type Outbound struct {
	tag    string
	typ    string
	out    adapter.Outbound
	scope  *adapter.Scope
	active atomic.Int64
	once   sync.Once
}

func (o *Outbound) Tag() string  { return o.tag }
func (o *Outbound) Type() string { return o.typ }

// Active reports how many relayed connections currently use this instance.
func (o *Outbound) Active() int64 { return o.active.Load() }

func (o *Outbound) acquire() func() {
	o.active.Add(1)
	var once sync.Once
	return func() { once.Do(func() { o.active.Add(-1) }) }
}

// Close closes this instance and whatever its scope opened. It does not wait
// for connections still relaying through it.
func (o *Outbound) Close() error {
	var err error
	o.once.Do(func() {
		err = errors.Join(common.Close(o.out), o.scope.Close())
	})
	return err
}

// DirectSpec dials the destination directly.
type DirectSpec struct{}

// ShadowsocksSpec is a Shadowsocks client.
type ShadowsocksSpec struct {
	Server   string
	Port     uint16
	Method   string
	Password string
}

// VLESSSpec is a VLESS client. Flow is "" or "xtls-rprx-vision".
type VLESSSpec struct {
	Server string
	Port   uint16
	UUID   string
	Flow   string
	TLS    *TLSSpec
}

// TLSSpec is client TLS. Fingerprint enables uTLS (for example "chrome").
type TLSSpec struct {
	ServerName  string
	Insecure    bool
	Fingerprint string
	Reality     *RealitySpec
}

// RealitySpec is the client side of REALITY. X25519MLKEM768 keeps the
// post-quantum hybrid key share in the ClientHello (share-link parameter
// support-x25519mlkem768); newer Xray servers may require it, older ones
// reject it.
type RealitySpec struct {
	PublicKey      string
	ShortID        string
	X25519MLKEM768 bool
}

// NewOutbound creates and starts one outbound instance. spec is one of
// DirectSpec, ShadowsocksSpec or VLESSSpec.
func (b *Backend) NewOutbound(tag string, spec any) (*Outbound, error) {
	var (
		typ string
		out adapter.Outbound
		err error
	)
	switch s := spec.(type) {
	case DirectSpec:
		typ = "direct"
		out, err = direct.NewOutbound(b.ctx, b.router, b.componentLogger("outbound", typ, tag), tag, option.DirectOutboundOptions{})
	case ShadowsocksSpec:
		typ = "shadowsocks"
		out, err = shadowsocks.NewOutbound(b.ctx, b.router, b.componentLogger("outbound", typ, tag), tag, option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{Server: s.Server, ServerPort: s.Port},
			Method:        s.Method,
			Password:      s.Password,
		})
	case VLESSSpec:
		typ = "vless"
		if s.TLS != nil && s.TLS.Reality != nil {
			// Reka's own REALITY client; see vless.go.
			out, err = newVLESSRealityOutbound(b.ctx, b.componentLogger("outbound", typ, tag), tag, s)
			break
		}
		out, err = vless.NewOutbound(b.ctx, b.router, b.componentLogger("outbound", typ, tag), tag, option.VLESSOutboundOptions{
			ServerOptions:               option.ServerOptions{Server: s.Server, ServerPort: s.Port},
			UUID:                        s.UUID,
			Flow:                        s.Flow,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: s.TLS.build()},
		})
	default:
		return nil, fmt.Errorf("reka: unsupported outbound spec %T", spec)
	}
	if err != nil {
		return nil, fmt.Errorf("create outbound/%s[%s]: %w", typ, tag, err)
	}
	return b.adoptOutbound(tag, typ, out)
}

// adoptOutbound starts an already constructed upstream outbound in its own
// scope and wraps it.
func (b *Backend) adoptOutbound(tag, typ string, out adapter.Outbound) (*Outbound, error) {
	scope, err := b.start("outbound/"+typ+"["+tag+"]", out, b.componentLogger("outbound", typ, tag))
	if err != nil {
		common.Close(out)
		return nil, err
	}
	return &Outbound{tag: tag, typ: typ, out: out, scope: scope}, nil
}

func (t *TLSSpec) build() *option.OutboundTLSOptions {
	if t == nil {
		return nil
	}
	o := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: t.ServerName,
		Insecure:   t.Insecure,
	}
	if t.Fingerprint != "" {
		o.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: t.Fingerprint}
	}
	return o
}

// Inbound is one upstream inbound instance.
type Inbound struct {
	tag   string
	typ   string
	in    adapter.Inbound
	scope *adapter.Scope
	once  sync.Once
}

func (i *Inbound) Tag() string  { return i.tag }
func (i *Inbound) Type() string { return i.typ }

// Close stops the listener. Connections it already accepted keep relaying.
func (i *Inbound) Close() error {
	var err error
	i.once.Do(func() {
		err = errors.Join(i.scope.Close(), common.Close(i.in))
	})
	return err
}

// NewMixedInbound starts a SOCKS4/4a/5 and HTTP proxy listener on listen.
func (b *Backend) NewMixedInbound(tag string, listen netip.AddrPort) (*Inbound, error) {
	addr := badoption.Addr(listen.Addr())
	options := option.HTTPMixedInboundOptions{
		ListenOptions: option.ListenOptions{Listen: &addr, ListenPort: listen.Port()},
	}
	logger := b.componentLogger("inbound", "mixed", tag)
	in, err := mixed.NewInbound(b.ctx, b.router, logger, tag, options)
	if err != nil {
		return nil, fmt.Errorf("create inbound/mixed[%s]: %w", tag, err)
	}
	return b.adoptInbound(tag, "mixed", in, logger)
}

func (b *Backend) adoptInbound(tag, typ string, in adapter.Inbound, logger log.ContextLogger) (*Inbound, error) {
	scope, err := b.start("inbound/"+typ+"["+tag+"]", in, logger)
	if err != nil {
		common.Close(in)
		return nil, err
	}
	return &Inbound{tag: tag, typ: typ, in: in, scope: scope}, nil
}
