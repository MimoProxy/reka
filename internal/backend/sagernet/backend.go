package sagernet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/MimoProxy/reka/internal/lease"

	"github.com/MimoProxy/reka/internal/history"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

// Options configures a Backend.
type Options struct {
	History           *history.Store
	HistoryScope      func() history.Scope
	ProcessInfoLookup func(context.Context, Metadata) (ProcessInfo, bool)
	ProcessLookup     func(context.Context, Metadata) (string, bool)
	// OnConnectionClosed receives final counters when a relay leaves the
	// active table. It runs under the table lock and must not call into it.
	OnConnectionClosed func(ConnInfo)
	// Logger receives all upstream logs. Defaults to slog.Default().
	Logger *slog.Logger
	// Protect, when set, is applied to every outbound socket before it
	// connects. On Android it calls VpnService.protect().
	Protect control.Func
	// ProtectFD is Protect for hosts that work with raw descriptors, such
	// as Android's VpnService.protect(int). Ignored when Protect is set.
	ProtectFD func(fd int) error
	// HalfCloseTimeout bounds how long a relay keeps receiving after the
	// client half-closed and the outbound connection cannot. Default 2s.
	HalfCloseTimeout time.Duration
	// UDPTimeout closes a UDP destination flow after this much idle time.
	// Default 60s.
	UDPTimeout time.Duration
	// FindProcess enables looking up the process that owns a connection,
	// where the platform supports it.
	FindProcess bool
}

const defaultHalfCloseTimeout = 2 * time.Second

// Backend owns the upstream service context. Inbounds and outbounds created
// from it are independent instances: each has its own lifecycle scope and can
// be closed without touching the others.
type Backend struct {
	debugMu           sync.Mutex
	httpsDebug        *httpsDebug
	history           *history.Store
	historyScope      func() history.Scope
	processTraffic    processTrafficTable
	trafficUpload     atomic.Uint64
	trafficDownload   atomic.Uint64
	processInfoLookup func(context.Context, Metadata) (ProcessInfo, bool)
	protect           control.Func
	processLookup     func(context.Context, Metadata) (string, bool)
	resolver          *net.Resolver
	ctx               context.Context
	cancel            context.CancelFunc
	slog              *slog.Logger
	logger            *slogLogger
	router            *router
	conns             connTable

	halfCloseTimeout time.Duration
	udpTimeout       time.Duration
	searcher         process.Searcher
}

// New builds the upstream context with only the services the enabled
// protocols look up: network manager, DNS router and DNS transport manager.
// Everything else upstream reads from the context is nil-tolerant.
func New(opts Options) *Backend {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = service.ContextWithDefaultRegistry(ctx)
	b := &Backend{
		history:           opts.History,
		historyScope:      opts.HistoryScope,
		processInfoLookup: opts.ProcessInfoLookup,
		processLookup:     opts.ProcessLookup,
		ctx:               ctx,
		cancel:            cancel,
		slog:              opts.Logger,
		logger:            newLogger(opts.Logger, "backend"),
		conns:             connTable{onClosed: opts.OnConnectionClosed},

		halfCloseTimeout: opts.HalfCloseTimeout,
	}
	if b.halfCloseTimeout <= 0 {
		b.halfCloseTimeout = defaultHalfCloseTimeout
	}
	b.udpTimeout = opts.UDPTimeout
	if b.udpTimeout <= 0 {
		b.udpTimeout = defaultUDPTimeout
	}
	if opts.FindProcess && processSupported {
		if s, err := process.NewSearcher(process.Config{Logger: newLogger(opts.Logger, "process")}); err == nil {
			b.searcher = s
		}
	}
	b.router = &router{backend: b}
	protect := opts.Protect
	if protect == nil && opts.ProtectFD != nil {
		fn := opts.ProtectFD
		protect = func(_, _ string, conn syscall.RawConn) error {
			var perr error
			if err := conn.Control(func(fd uintptr) { perr = fn(int(fd)) }); err != nil {
				return err
			}
			return perr
		}
	}
	b.protect = protect
	service.MustRegister[adapter.NetworkManager](ctx, &networkManager{protect: protect})
	b.resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := &net.Dialer{}
		if protect != nil {
			d.Control = protect
		}
		return d.DialContext(ctx, network, address)
	}}
	service.MustRegister[adapter.DNSRouter](ctx, &dnsRouter{resolver: b.resolver})
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
	b.StopHTTPSDebug()
	if b.searcher != nil {
		b.searcher.Close()
	}
	return nil
}

func (o *Outbound) CloseIdleConnections() {
	if keeper, ok := o.out.(adapter.IdleConnectionKeeper); ok {
		keeper.CloseIdleConnections()
	}
}

// CanFindProcess reports whether FindProcess can return results.
func (b *Backend) CanFindProcess() bool {
	return b.searcher != nil || b.processLookup != nil || b.processInfoLookup != nil
}

// FindProcess returns the path of the process that opened the connection
// described by md, if the platform can tell.
func (b *Backend) FindProcess(ctx context.Context, md Metadata) (string, bool) {
	info, ok := b.FindProcessInfo(ctx, md)
	return info.Path, ok && info.Path != ""
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

// Outbound is one upstream outbound instance. Every relay through it holds
// one lease on it; see Lease.
type Outbound struct {
	dependencyPins   atomic.Int64
	dependencyCloser *DetourSpec
	tag              string
	typ              string
	out              adapter.Outbound
	scope            *adapter.Scope
	lease            *lease.Lease
	once             sync.Once
}

func (o *Outbound) Tag() string  { return o.tag }
func (o *Outbound) Type() string { return o.typ }

// Lease is the instance's lease counter. A RouteFunc takes a lease when it
// picks the instance; the relay releases it when the connection ends.
// Retiring the lease stops new connections from using the instance.
func (o *Outbound) Lease() *lease.Lease { return o.lease }

// Active reports how many relayed connections currently use this instance.
func (o *Outbound) Active() int64 { return max(0, o.lease.Active()-o.dependencyPins.Load()) }

// Close retires and closes this instance and whatever its scope opened. It
// does not wait for connections still relaying through it: without
// multiplexing they keep running, with multiplexing they are cut. Retire
// and drain first (internal/runtime does) to avoid cutting them.
func (o *Outbound) Close() error {
	var err error
	o.once.Do(func() {
		o.lease.Retire()
		err = errors.Join(common.Close(o.out), o.scope.Close(), o.dependencyCloser.Close())
	})
	return err
}

// DirectSpec dials the destination directly.
type DirectSpec struct {
	// DomainStrategy uses the sing-box domain_strategy values.
	DomainStrategy string
}

// ShadowsocksSpec is a Shadowsocks client.
type ShadowsocksSpec struct {
	Server   string
	Port     uint16
	Method   string
	Password string
}

// HTTPSpec is an HTTP CONNECT proxy client, over TLS when TLS is set.
type HTTPSpec struct {
	Server   string
	Port     uint16
	Username string
	Password string
	TLS      *TLSSpec
}

// SOCKSSpec is a SOCKS5 client.
type SOCKSSpec struct {
	Server   string
	Port     uint16
	Username string
	Password string
}

// VLESSSpec is a VLESS client. Flow is "" or "xtls-rprx-vision".
type VLESSSpec struct {
	ECHLookup  func(context.Context, string) ([]byte, error)
	Encryption string
	Detour     *DetourSpec
	Options    json.RawMessage
	Server     string
	Port       uint16
	UUID       string
	Flow       string
	TLS        *TLSSpec
}

// TLSSpec is client TLS. Fingerprint enables uTLS (for example "chrome").
type TLSSpec struct {
	Carrier                                             *TLSCarrierSpec
	ECH                                                 *ECHSpec
	CertificatePin, VerifyName, Certificate, PrivateKey string
	ServerName                                          string
	Insecure                                            bool
	Fingerprint                                         string
	ALPN                                                []string
	Reality                                             *RealitySpec
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
// DirectSpec, HTTPSpec, SOCKSSpec, ShadowsocksSpec or VLESSSpec.
func (b *Backend) NewOutbound(tag string, spec any) (*Outbound, error) {
	var (
		typ        string
		out        adapter.Outbound
		err        error
		dependency *DetourSpec
		multiplex  *multiplexSpec
	)
	switch s := spec.(type) {
	case ProxySpec:
		dependency = s.Detour
		typ = s.Type
		out, err = b.newProtocol(tag, s)
	case DropSpec:
		typ = "reject-drop"
		out = newDropOutbound(tag)
	case DirectSpec:
		typ = "direct"
		var opts option.DirectOutboundOptions
		if s.DomainStrategy != "" {
			strategy, _ := json.Marshal(s.DomainStrategy)
			if err = opts.DomainStrategy.UnmarshalJSON(strategy); err != nil {
				break
			}
		}
		out, err = direct.NewOutbound(b.ctx, b.router, b.componentLogger("outbound", typ, tag), tag, opts)
	case HTTPSpec:
		typ = "http"
		out, err = http.NewOutbound(b.ctx, b.router, b.componentLogger("outbound", typ, tag), tag, option.HTTPOutboundOptions{
			ServerOptions:               option.ServerOptions{Server: s.Server, ServerPort: s.Port},
			Username:                    s.Username,
			Password:                    s.Password,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: s.TLS.build()},
		})
	case SOCKSSpec:
		typ = "socks"
		out, err = socks.NewOutbound(b.ctx, b.router, b.componentLogger("outbound", typ, tag), tag, option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: s.Server, ServerPort: s.Port},
			Version:       "5",
			Username:      s.Username,
			Password:      s.Password,
		})
	case ShadowsocksSpec:
		typ = "shadowsocks"
		out, err = shadowsocks.NewOutbound(b.ctx, b.router, b.componentLogger("outbound", typ, tag), tag, option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{Server: s.Server, ServerPort: s.Port},
			Method:        s.Method,
			Password:      s.Password,
		})
	case VLESSSpec:
		dependency = s.Detour
		typ = "vless"
		if s.TLS == nil || s.TLS.Reality == nil {
			var values map[string]any
			values, err = decodeProtocolOptions(s.Options)
			if err != nil {
				break
			}
			if s.Flow != "" {
				values["flow"] = s.Flow
			}
			s.Options, _ = json.Marshal(values)
			out, err = b.newProtocol(tag, ProxySpec{Type: typ, Server: s.Server, Port: s.Port, UUID: s.UUID, Encryption: s.Encryption, TLS: s.TLS, Options: s.Options, Detour: s.Detour, ECHLookup: s.ECHLookup})
			break
		}
		ctx := detourContext(b.ctx, s.Detour)
		if s.ECHLookup != nil {
			ctx = context.WithValue(ctx, "reka.tls.ech.lookup.v1", s.ECHLookup)
		}
		var values map[string]any
		values, err = decodeProtocolOptions(s.Options)
		if err != nil {
			break
		}
		multiplex, err = popMultiplex(values)
		if err != nil {
			break
		}
		if s.Detour != nil {
			values["detour"] = "reka-detour"
		}
		s.Options, _ = json.Marshal(values)
		// Reka's own REALITY client; see vless.go.
		out, err = newVLESSRealityOutbound(ctx, b.componentLogger("outbound", typ, tag), tag, s)
	default:
		return nil, fmt.Errorf("reka: unsupported outbound spec %T", spec)
	}
	if err != nil {
		dependency.Close()
		return nil, fmt.Errorf("create outbound/%s[%s]: %w", typ, tag, err)
	}
	if multiplex != nil {
		base := out
		out, err = wrapMultiplex(base, multiplex, b.componentLogger("multiplex", typ, tag))
		if err != nil {
			common.Close(base)
			dependency.Close()
			return nil, err
		}
	}
	wrapped, err := b.adoptOutbound(tag, typ, out)
	if err != nil {
		dependency.Close()
		return nil, err
	}
	wrapped.dependencyCloser = dependency
	return wrapped, nil
}

// adoptOutbound starts an already constructed upstream outbound in its own
// scope and wraps it.
func (b *Backend) adoptOutbound(tag, typ string, out adapter.Outbound) (*Outbound, error) {
	scope, err := b.start("outbound/"+typ+"["+tag+"]", out, b.componentLogger("outbound", typ, tag))
	if err != nil {
		common.Close(out)
		return nil, err
	}
	return &Outbound{tag: tag, typ: typ, out: out, scope: scope, lease: lease.New()}, nil
}

func (t *TLSSpec) build() *option.OutboundTLSOptions {
	if t == nil {
		return nil
	}
	o := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: t.ServerName,
		Insecure:   t.Insecure,
		ALPN:       t.ALPN,
	}
	if t.ECH != nil {
		o.ECH = &option.OutboundECHOptions{Enabled: true, QueryServerName: t.ECH.QueryServerName}
		if t.ECH.Config != "" {
			data, _ := base64.StdEncoding.DecodeString(t.ECH.Config)
			o.ECH.Config = []string{string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: data}))}
		}
	}
	if t.Certificate != "" {
		o.ClientCertificate = []string{t.Certificate}
		o.ClientKey = []string{t.PrivateKey}
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
	return b.NewInbound(tag, "mixed", listen)
}

// NewInbound starts a listener of type typ ("mixed", "socks" or "http")
// on listen. Binding errors, such as a port in use, are returned here.
func (b *Backend) NewInbound(tag, typ string, listen netip.AddrPort) (*Inbound, error) {
	return b.NewInboundWithUsers(tag, typ, listen, nil)
}

type InboundUser struct{ Username, Password string }

// NewInboundWithUsers starts a local application proxy with optional explicit
// authentication. User identity is passed to the router by the protocol parser.
func (b *Backend) NewInboundWithUsers(tag, typ string, listen netip.AddrPort, users []InboundUser) (*Inbound, error) {
	addr := badoption.Addr(listen.Addr())
	lo := option.ListenOptions{Listen: &addr, ListenPort: listen.Port()}
	credentials := make([]auth.User, len(users))
	for i, user := range users {
		credentials[i] = auth.User{Username: user.Username, Password: user.Password}
	}
	logger := b.componentLogger("inbound", typ, tag)
	var (
		in  adapter.Inbound
		err error
	)
	switch typ {
	case "mixed":
		in, err = mixed.NewInbound(b.observeHTTP(tag), b.router, logger, tag, option.HTTPMixedInboundOptions{ListenOptions: lo, Users: credentials})
	case "socks":
		in, err = socks.NewInbound(b.ctx, b.router, logger, tag, option.SocksInboundOptions{ListenOptions: lo, Users: credentials})
	case "http":
		in, err = http.NewInbound(b.observeHTTP(tag), b.router, logger, tag, option.HTTPMixedInboundOptions{ListenOptions: lo, Users: credentials})
	default:
		return nil, fmt.Errorf("reka: unsupported inbound type %q", typ)
	}
	if err != nil {
		return nil, fmt.Errorf("create inbound/%s[%s]: %w", typ, tag, err)
	}
	return b.adoptInbound(tag, typ, in, logger)
}

func (b *Backend) adoptInbound(tag, typ string, in adapter.Inbound, logger log.ContextLogger) (*Inbound, error) {
	scope, err := b.start("inbound/"+typ+"["+tag+"]", in, logger)
	if err != nil {
		common.Close(in)
		return nil, err
	}
	return &Inbound{tag: tag, typ: typ, in: in, scope: scope}, nil
}

func (b *Backend) Resolver() *net.Resolver { return b.resolver }
