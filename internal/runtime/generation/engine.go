// Package generation builds RuntimeGenerations from effective
// configurations on top of internal/runtime's snapshots and leases: it
// diffs outbound instances by fingerprint, swaps listeners bind-first,
// and routes connections against the published generation.
package generation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/platform"
	"github.com/MimoProxy/reka/internal/policy"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/subscription"
	"io"
	goruntime "runtime"
)

// Defaults for EngineOptions.
const (
	DefaultDrainTimeout = 30 * time.Second
	DefaultMaxRetiring  = 256
	defaultLookup       = 5 * time.Second
)

// EngineOptions configure an Engine.
type EngineOptions struct {
	StateRoot    string
	TUNFD        int
	NetworkHooks *platform.NetworkHooks
	Backend      sagernet.Options
	// DrainTimeout bounds how long a replaced outbound waits for its
	// connections before it is closed anyway.
	DrainTimeout time.Duration
	// MaxRetiring blocks commits while this many replaced outbounds are
	// still draining.
	MaxRetiring int
	// LogLevel, if set, is updated to the configured level on activation.
	LogLevel *slog.LevelVar
	// Resolver looks up domains for ip-cidr rules. Default: the system
	// resolver.
	Resolver *net.Resolver
}

// generation is the immutable value published with each snapshot.
type generation struct {
	policies *policy.Manager
	dns      *RD.Service
	revision uint64
	eff      *compile.Effective
	router   *router.Router
	outUDP   map[string]bool
	inUDP    map[string]bool
}

// Engine turns effective configurations into running generations: it
// computes what changes, prepares new instances and listeners, and
// switches atomically. Commits are serialized by the caller (ConfigService)
// and additionally by an internal lock.
type Engine struct {
	tunSerial   uint64
	takeover    *platform.Takeover
	networkErr  error
	guard       *sagernet.SocketGuard
	fake        *RD.FakePool
	dnsListener *sagernet.DNSListener
	dnsAddress  string
	opts        EngineOptions
	backend     *sagernet.Backend
	rt          *runtime.Runtime[*sagernet.Outbound]

	mu        sync.Mutex
	listeners map[string]*listener
	closed    bool
}

type listener struct {
	cfg compile.Listener
	in  *sagernet.Inbound
}

// NewEngine starts an engine with an empty generation that rejects every
// connection.
func NewEngine(opts EngineOptions) *Engine {
	if opts.DrainTimeout <= 0 {
		opts.DrainTimeout = DefaultDrainTimeout
	}
	if opts.MaxRetiring <= 0 {
		opts.MaxRetiring = DefaultMaxRetiring
	}

	e := &Engine{fake: RD.NewFakePool(65536), opts: opts, listeners: map[string]*listener{}}
	e.guard = sagernet.NewSocketGuard(opts.Backend.ProtectFD)
	oldProtect := opts.Backend.Protect
	opts.Backend.Protect = func(n, a string, c syscall.RawConn) error {
		if oldProtect != nil {
			if err := oldProtect(n, a, c); err != nil {
				return err
			}
		}
		return e.guard.Control(n, a, c)
	}
	opts.Backend.ProtectFD = nil
	e.backend = sagernet.New(opts.Backend)
	if opts.StateRoot != "" {
		hooks := platform.NetworkHooks{Settings: platform.NativeSettings{}, SettingsFor: platform.SystemSettings, Bypass: e.guard.Set, StartTUN: func(c platform.TUNConfig) (io.Closer, string, error) {
			d, name, err := e.backend.NewTUN(c, e.opts.TUNFD, e.guard, e.ExchangeDNS)
			if err == nil {
				e.tunSerial++
			}
			return d, name, err
		}}
		if opts.NetworkHooks != nil {
			hooks = *opts.NetworkHooks
		}
		e.takeover, e.networkErr = platform.NewTakeover(opts.StateRoot, hooks)
	}
	if e.opts.Resolver == nil {
		e.opts.Resolver = e.backend.Resolver()
	}
	e.rt = runtime.NewValue[*sagernet.Outbound](nil, &generation{}, runtime.Options{
		DrainTimeout: opts.DrainTimeout,
		MaxRetiring:  opts.MaxRetiring,
		OnClosed: func(id string, gen uint64, forced int64, err error) {
			l := slog.Default()
			if opts.Backend.Logger != nil {
				l = opts.Backend.Logger
			}
			if forced > 0 {
				l.Warn("closed a replaced outbound before its connections ended", "outbound", id, "generation", gen, "connections", forced)
			}
			if err != nil {
				l.Warn("close replaced outbound", "outbound", id, "err", err)
			}
		},
	})
	e.backend.SetRoute(e.route)
	return e
}

// ProcessLookup reports whether process-name rules can match here.
func (e *Engine) ProcessLookup() bool { return e.backend.CanFindProcess() }

// Change actions in a plan.
const (
	ActionKeep    = "keep"
	ActionCreate  = "create"
	ActionReplace = "replace"
	ActionRemove  = "remove"
	ActionRebind  = "rebind"
	ActionRestart = "restart"
)

// ResourceChange is one line of an impact plan.
type ResourceChange struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	// Connections is how many connections use the instance being replaced
	// or removed; they keep running on it while it drains.
	Connections int64  `json:"connections,omitempty"`
	Listen      string `json:"listen,omitempty"`
	Note        string `json:"note,omitempty"`
}

// GroupChange is a selection change.
type GroupChange struct {
	ID   string `json:"id"`
	From string `json:"from,omitempty"`
	To   string `json:"to"`
}

// Plan describes what activating a configuration changes. Nothing in it
// has happened yet.
type Plan struct {
	NetworkChanged         bool             `json:"network_changed"`
	NetworkNote            string           `json:"network_note,omitempty"`
	DNSChanged             bool             `json:"dns_changed"`
	AutomaticGroupsChanged bool             `json:"automatic_groups_changed"`
	Outbounds              []ResourceChange `json:"outbounds"`
	Listeners              []ResourceChange `json:"listeners"`
	RulesChanged           bool             `json:"rules_changed"`
	Rules                  int              `json:"rules"`
	Groups                 []GroupChange    `json:"groups,omitempty"`
	LogLevel               string           `json:"log_level,omitempty"`
	// RestartRequired lists settings that only take effect after the
	// process restarts.
	RestartRequired []string `json:"restart_required,omitempty"`
	// Draining is the number of instances that will be draining after the
	// switch; Blocked is set when that exceeds the limit.
	Draining   int    `json:"draining"`
	Blocked    string `json:"blocked,omitempty"`
	Interrupts bool   `json:"interrupts,omitempty"`
}

// ErrBlocked is returned when a commit would leave too many instances
// draining.
var ErrBlocked = errors.New("too many replaced outbounds are still draining; wait for their connections to end or close them")

func (e *Engine) current() (*runtime.Snapshot[*sagernet.Outbound], *generation) {
	s := e.rt.Current()
	return s, s.Value.(*generation)
}

// Effective returns the active configuration, or nil before the first
// activation.
func (e *Engine) Effective() (*compile.Effective, uint64) {
	_, g := e.current()
	return g.eff, g.revision
}

// Plan computes the impact of activating eff.
func (e *Engine) Plan(eff *compile.Effective) Plan {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.plan(eff)
}

func (e *Engine) plan(eff *compile.Effective) Plan {
	snap, gen := e.current()
	p := Plan{Rules: len(eff.Rules)}
	oldNetwork := platform.Network{Mode: "off"}
	if gen.eff != nil {
		oldNetwork = gen.eff.Network
	}
	p.NetworkChanged = !reflect.DeepEqual(oldNetwork, eff.Network)
	if eff.Network.Mode == "system-proxy" && proxyEndpoint(gen.eff) != proxyEndpoint(eff) {
		p.NetworkChanged = true
	}
	if p.NetworkChanged {
		p.Interrupts = true
		p.NetworkNote = "rebuilds system takeover; TUN flows may disconnect; Android host must rebuild VpnService for address, route or app changes"
	}
	if eff.Network.Mode != "off" && (e.takeover == nil || e.networkErr != nil) {
		p.Blocked = "network takeover unavailable or recovery incomplete"
	}
	p.DNSChanged = gen.eff == nil && eff.DNS != nil || gen.eff != nil && gen.eff.DNSFingerprint != eff.DNSFingerprint
	p.AutomaticGroupsChanged = gen.eff == nil && len(eff.AutoGroups) > 0 || gen.eff != nil && !reflect.DeepEqual(gen.eff.AutoGroups, eff.AutoGroups)
	keepIDs := map[string]bool{}
	for _, o := range eff.Outbounds {
		if o.Type == model.OutboundReject {
			continue
		}
		keepIDs[o.ID] = true
		old, ok := snap.Resources[o.ID]
		switch {
		case !ok:
			p.Outbounds = append(p.Outbounds, ResourceChange{ID: o.ID, Action: ActionCreate})
		case fingerprintOf(gen, o.ID) == o.Fingerprint:
			p.Outbounds = append(p.Outbounds, ResourceChange{ID: o.ID, Action: ActionKeep})
		default:
			p.Outbounds = append(p.Outbounds, ResourceChange{ID: o.ID, Action: ActionReplace, Connections: old.Active(),
				Note: "new connections use a new instance; the old one drains"})
			p.Draining++
		}
	}
	for id, old := range snap.Resources {
		if !keepIDs[id] {
			p.Outbounds = append(p.Outbounds, ResourceChange{ID: id, Action: ActionRemove, Connections: old.Active()})
			p.Draining++
		}
	}
	if cur := int(e.rt.Stats().Retiring); cur+p.Draining > e.opts.MaxRetiring {
		p.Blocked = fmt.Sprintf("%d instances are draining and this change adds %d; the limit is %d", cur, p.Draining, e.opts.MaxRetiring)
	}
	p.Draining += int(e.rt.Stats().Retiring)

	for _, ch := range e.listenerChanges(eff) {
		p.Listeners = append(p.Listeners, ch.ResourceChange)
		if ch.Action == ActionRestart {
			p.Interrupts = true
		}
	}
	if gen.eff == nil || gen.eff.RulesFingerprint != eff.RulesFingerprint {
		p.RulesChanged = true
	}
	old := map[string]string{}
	if gen.router != nil {
		for _, g := range gen.router.Groups() {
			old[g.ID] = g.Selected
		}
	}
	for _, g := range eff.Router.Groups() {
		if old[g.ID] != g.Selected {
			p.Groups = append(p.Groups, GroupChange{ID: g.ID, From: old[g.ID], To: g.Selected})
		}
	}
	if gen.eff == nil || gen.eff.LogLevel != eff.LogLevel {
		p.LogLevel = eff.LogLevel
	}
	if gen.eff != nil && gen.eff.Control != eff.Control {
		p.RestartRequired = append(p.RestartRequired, "/control/listen")
	}
	sortChanges(p.Outbounds)
	sortChanges(p.Listeners)
	return p
}

func sortChanges(cs []ResourceChange) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
}

func fingerprintOf(g *generation, id string) string {
	if g.eff == nil {
		return ""
	}
	o, _ := g.eff.Outbound(id)
	return o.Fingerprint
}

type listenerChange struct {
	ResourceChange
	cfg compile.Listener
	old *listener
}

// listenerChanges lists, for every listener in eff and every running one
// that eff drops, what happens to it. A listener that needs an address a
// running listener still holds (same port, new protocol) must stop the old
// one first; that is a restart, a short interruption for new connections.
func (e *Engine) listenerChanges(eff *compile.Effective) []listenerChange {
	byAddr := map[netip.AddrPort]*listener{}
	for _, l := range e.listeners {
		byAddr[l.cfg.Listen] = l
	}
	var out []listenerChange
	wanted := map[string]bool{}
	for _, c := range eff.Listeners {
		wanted[c.ID] = true
		old := e.listeners[c.ID]
		ch := listenerChange{ResourceChange: ResourceChange{ID: c.ID, Listen: c.Listen.String()}, cfg: c, old: old}
		holder := byAddr[c.Listen]
		switch {
		case old != nil && old.cfg.Listen == c.Listen && old.cfg.Fingerprint == c.Fingerprint:
			ch.Action = ActionKeep
		case holder != nil && (holder != old || old.cfg.Fingerprint != c.Fingerprint):
			ch.Action = ActionRestart
			ch.old = holder
			ch.Note = "the address is in use by the listener being replaced, so it stops first: new connections are refused briefly; accepted ones continue"
		case old != nil:
			ch.Action = ActionRebind
			ch.Note = "binds the new address first, then stops the old one; accepted connections continue"
		default:
			ch.Action = ActionCreate
		}
		out = append(out, ch)
	}
	for id, l := range e.listeners {
		if !wanted[id] {
			out = append(out, listenerChange{ResourceChange: ResourceChange{ID: id, Action: ActionRemove, Listen: l.cfg.Listen.String(),
				Note: "stops accepting; accepted connections continue"}, old: l})
		}
	}
	return out
}

// Prepared holds instances built for a configuration that is not active
// yet. Pass it to Activate or Abort exactly once.
type Prepared struct {
	policies    *policy.Manager
	dns         *RD.Service
	dnsListener *sagernet.DNSListener
	dnsBound    bool
	eff         *compile.Effective
	plan        Plan
	outbounds   map[string]*sagernet.Outbound
	created     []*sagernet.Outbound
	// bound are new listeners already accepting connections (bind-first).
	bound map[string]*sagernet.Inbound
	// changes are the listener changes, applied in Activate.
	changes []listenerChange
	done    bool
}

// Plan returns the plan this preparation implements.
func (p *Prepared) Plan() Plan { return p.plan }

// PrepareError is a failure to prepare; nothing changed.
type PrepareError struct {
	Path string
	Err  error
}

func (e *PrepareError) Error() string { return fmt.Sprintf("%s: %v", e.Path, e.Err) }
func (e *PrepareError) Unwrap() error { return e.Err }

// Prepare builds the outbound instances eff needs and binds new listeners
// that do not conflict with running ones. On error everything it built is
// released and the running generation is untouched. The engine stays
// locked until Activate or Abort.
func (e *Engine) Prepare(eff *compile.Effective) (*Prepared, error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, errors.New("engine closed")
	}
	p := &Prepared{eff: eff, outbounds: map[string]*sagernet.Outbound{}, bound: map[string]*sagernet.Inbound{}}
	p.plan = e.plan(eff)
	if p.plan.Blocked != "" {
		e.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrBlocked, p.plan.Blocked)
	}
	snap, gen := e.current()
	fail := func(err error) (*Prepared, error) {
		e.release(p)
		e.mu.Unlock()
		return nil, err
	}
	if goruntime.GOOS == "android" && eff.Network.Mode == "tun" && p.plan.NetworkChanged && e.opts.TUNFD <= 0 {
		return fail(&PrepareError{Path: "/network", Err: errors.New("host must supply a freshly established VpnService fd through reconfigureVPN")})
	}
	for _, o := range eff.Outbounds {
		if o.Type == model.OutboundReject {
			continue
		}
		if old, ok := snap.Resources[o.ID]; ok && fingerprintOf(gen, o.ID) == o.Fingerprint {
			p.outbounds[o.ID] = old
			continue
		}
		out, err := e.backend.NewOutbound(o.ID, specFor(o))
		if err != nil {
			return fail(&PrepareError{Path: "/outbounds/" + o.ID, Err: err})
		}
		p.created = append(p.created, out)
		p.outbounds[o.ID] = out
	}
	if err := e.prepareDNS(p); err != nil {
		return fail(&PrepareError{Path: "/dns", Err: err})
	}
	e.preparePolicies(p)
	p.changes = e.listenerChanges(eff)
	for _, ch := range p.changes {
		if ch.Action != ActionCreate && ch.Action != ActionRebind {
			continue
		}
		in, err := e.backend.NewInbound(ch.cfg.ID, ch.cfg.Type, ch.cfg.Listen)
		if err != nil {
			return fail(&PrepareError{Path: "/listeners/" + ch.cfg.ID + "/listen", Err: err})
		}
		p.bound[ch.cfg.ID] = in
	}
	return p, nil
}

func (e *Engine) release(p *Prepared) {
	if p.dnsBound {
		p.dnsListener.Close()
	}
	for _, o := range p.created {
		o.Close()
	}
	for _, in := range p.bound {
		in.Close()
	}
	p.done = true
}

// Abort releases a preparation without activating it.
func (e *Engine) Abort(p *Prepared) {
	if p.done {
		return
	}
	e.release(p)
	e.mu.Unlock()
}

// ActivateError reports a failure during the switch. Degraded means some
// listener could not be restored; the rest of the previous generation is
// running.
type ActivateError struct {
	Err      error
	Degraded bool
}

func (e *ActivateError) Error() string { return e.Err.Error() }
func (e *ActivateError) Unwrap() error { return e.Err }

// Activate switches to the prepared configuration: the new snapshot is
// published (new connections use it), dropped instances start draining,
// and listeners are swapped. It returns the new generation number.
func (e *Engine) Activate(p *Prepared, revision uint64) (uint64, error) {
	if p.done {
		return 0, errors.New("preparation already used")
	}
	defer e.mu.Unlock()
	p.done = true
	eff := p.eff
	_, previousGeneration := e.current()
	g := &generation{policies: p.policies, dns: p.dns, revision: revision, eff: eff, router: eff.Router, outUDP: map[string]bool{}, inUDP: map[string]bool{}}
	for _, o := range eff.Outbounds {
		g.outUDP[o.ID] = o.UDP
	}
	for _, l := range eff.Listeners {
		g.inUDP[l.ID] = l.UDP
	}
	genNo, err := e.rt.CommitValue(p.outbounds, g)
	if err != nil {
		for _, o := range p.created {
			o.Close()
		}
		for _, in := range p.bound {
			in.Close()
		}
		return 0, &ActivateError{Err: err}
	}
	if e.dnsListener != nil && e.dnsListener != p.dnsListener {
		e.dnsListener.Close()
	}
	e.dnsListener = p.dnsListener
	e.dnsAddress = ""
	if eff.DNS != nil {
		e.dnsAddress = eff.DNS.Listen
	}
	if previousGeneration.policies != nil {
		previousGeneration.policies.Close()
	}
	if g.policies != nil {
		g.policies.Start()
	}
	// Listeners: bound ones replace their predecessors; restarts stop the
	// holder first, then bind.
	var errs []error
	degraded := false
	for _, ch := range p.changes {
		switch ch.Action {
		case ActionCreate, ActionRebind:
			if ch.old != nil {
				ch.old.in.Close()
			}
			e.listeners[ch.ID] = &listener{cfg: ch.cfg, in: p.bound[ch.ID]}
		case ActionRemove:
			ch.old.in.Close()
			delete(e.listeners, ch.ID)
		case ActionKeep:
			e.listeners[ch.ID].cfg = ch.cfg
		}
	}
	for _, ch := range p.changes {
		if ch.Action != ActionRestart {
			continue
		}
		if ch.old != nil {
			ch.old.in.Close()
			delete(e.listeners, ch.old.cfg.ID)
		}
		in, err := e.backend.NewInbound(ch.cfg.ID, ch.cfg.Type, ch.cfg.Listen)
		if err != nil {
			errs = append(errs, fmt.Errorf("listener %s: %w", ch.ID, err))
			// Put the previous listener back if we can.
			if ch.old != nil {
				if back, err2 := e.backend.NewInbound(ch.old.cfg.ID, ch.old.cfg.Type, ch.old.cfg.Listen); err2 == nil {
					e.listeners[ch.old.cfg.ID] = &listener{cfg: ch.old.cfg, in: back}
				} else {
					degraded = true
				}
			}
			continue
		}
		e.listeners[ch.ID] = &listener{cfg: ch.cfg, in: in}
	}
	if e.opts.LogLevel != nil {
		e.opts.LogLevel.Set(parseLevel(eff.LogLevel))
	}
	if e.takeover != nil {
		proxy := ""
		for _, l := range eff.Listeners {
			if l.ID == eff.Network.ProxyListener {
				proxy = l.Listen.String()
			}
		}
		if err := e.takeover.Apply(eff.Network, proxy); err != nil {
			errs = append(errs, err)
			degraded = e.takeover.Status().State == "Degraded"
		} else if eff.Network.Mode == "off" {
			e.networkErr = nil
		}

	}
	if len(errs) > 0 {
		return genNo, &ActivateError{Err: errors.Join(errs...), Degraded: degraded}
	}
	return genNo, nil
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

func specFor(o compile.Outbound) any {
	tls := func() *sagernet.TLSSpec {
		if o.TLS == nil {
			return nil
		}
		t := &sagernet.TLSSpec{ServerName: o.TLS.ServerName, Insecure: o.TLS.Insecure, Fingerprint: o.TLS.Fingerprint, ALPN: o.TLS.ALPN}
		if r := o.TLS.Reality; r != nil {
			t.Reality = &sagernet.RealitySpec{PublicKey: r.PublicKey, ShortID: r.ShortID, X25519MLKEM768: r.X25519MLKEM768}
		}
		return t
	}
	if o.Type == "vmess" || o.Type == "trojan" || o.Type == "hysteria2" || o.Type == "tuic" || o.Type == "snell" || o.Type == "vless" && (o.Transport != nil || o.Multiplex != nil) && (o.TLS == nil || o.TLS.Reality == nil) {

		raw := protocolOptions(o)
		return sagernet.ProxySpec{Type: o.Type, Server: o.Server, Port: o.Port, UUID: o.UUID, Password: o.Password, TLS: tls(), Options: raw}
	}
	switch o.Type {
	case model.OutboundHTTP:
		return sagernet.HTTPSpec{Server: o.Server, Port: o.Port, Username: o.Username, Password: o.Password, TLS: tls()}
	case model.OutboundSOCKS:
		return sagernet.SOCKSSpec{Server: o.Server, Port: o.Port, Username: o.Username, Password: o.Password}
	case model.OutboundShadowsocks:
		return sagernet.ShadowsocksSpec{Server: o.Server, Port: o.Port, Method: o.Method, Password: o.Password}
	case model.OutboundVLESS:
		return sagernet.VLESSSpec{Server: o.Server, Port: o.Port, UUID: o.UUID, Flow: o.Flow, TLS: tls(), Options: protocolOptions(o)}
	}
	return sagernet.DirectSpec{}
}

// FlowInfo is attached to every routed connection.
type FlowInfo struct {
	Generation  uint64   `json:"generation"`
	Revision    uint64   `json:"revision"`
	RuleIndex   int      `json:"rule_index"`
	RuleID      string   `json:"rule_id,omitempty"`
	Rule        string   `json:"rule,omitempty"`
	Chain       []string `json:"chain,omitempty"`
	Outbound    string   `json:"outbound"`
	Fingerprint string   `json:"fingerprint"`
}

// lookupEnv resolves and finds processes for one connection; results are
// cached so a retried evaluation does not look up again.
type lookupEnv struct {
	dns *RD.Service
	e   *Engine
	md  sagernet.Metadata

	resolved bool
	addrs    []netip.Addr
	err      error
	procDone bool
	proc     string
	procOK   bool
}

func (l *lookupEnv) Resolve(ctx context.Context, domain string) ([]netip.Addr, error) {
	if !l.resolved {
		l.resolved = true
		ctx, cancel := context.WithTimeout(ctx, defaultLookup)
		defer cancel()
		if l.dns != nil {
			l.addrs, l.err = l.dns.Lookup(ctx, domain, "normal")
		} else {
			l.addrs, l.err = l.e.opts.Resolver.LookupNetIP(ctx, "ip", domain)
		}
	}
	return l.addrs, l.err
}

func (l *lookupEnv) Process(ctx context.Context) (string, bool) {
	if !l.procDone {
		l.procDone = true
		l.proc, l.procOK = l.e.backend.FindProcess(ctx, l.md)
	}
	return l.proc, l.procOK
}

func routerMetadata(md sagernet.Metadata) router.Metadata {
	return router.Metadata{
		Inbound: md.Inbound,
		Network: md.Network,
		Source:  md.Source,
		Domain:  router.NormalizeDomain(md.Destination.Domain),
		Addr:    md.Destination.Addr,
		Port:    md.Destination.Port,
	}
}

func (e *Engine) route(ctx context.Context, md sagernet.Metadata) sagernet.Route {
	var fakeRelease func()
	if md.Destination.Addr.IsValid() {
		if domain, release, ok := e.fake.Acquire(md.Destination.Addr); ok {
			fakeRelease = release
			md.Destination.Domain = domain
			md.Destination.Addr = netip.Addr{}
		} else {
			unknown := e.fake.Contains(md.Destination.Addr)
			_, active := e.current()
			if active.dns != nil {
				cfg := active.dns.Config()
				if cfg.Mode == "fake-ip" {
					for _, text := range []string{cfg.FakeRange, cfg.FakeRange6} {
						prefix, err := netip.ParsePrefix(text)
						if err == nil && prefix.Contains(md.Destination.Addr) {
							unknown = true
						}
					}
				}
			}
			if unknown {
				return sagernet.Route{}
			}
		}
	}
	env := &lookupEnv{e: e, md: md}
	var (
		dec router.Decision
		g   *generation
	)
	genNo, out, release, ok, err := e.rt.Acquire(func(s *runtime.Snapshot[*sagernet.Outbound]) (*sagernet.Outbound, bool) {
		g = s.Value.(*generation)
		if g.router == nil {
			return nil, false
		}
		udpAllowed := g.inUDP[md.Inbound]
		if md.InboundType == "tun" {
			udpAllowed = g.eff.Network.Mode == "tun"
		}
		if md.Network == "udp" && !udpAllowed {
			dec = router.Decision{RuleIndex: -1, Outbound: model.OutboundReject}
			return nil, false
		}
		env.dns = g.dns
		dec = g.router.Route(ctx, routerMetadata(md), env)
		g.resolveObserved(&dec, routerMetadata(md), true)
		if g.policies != nil {
			g.policies.MarkUsed(dec.Outbound)
		}
		if md.Network == "udp" {
			for _, id := range dec.Chain {
				if g.eff.GroupUDPDisabled[id] {
					return nil, false
				}
			}
		}
		if md.Network == "udp" && !g.outUDP[dec.Outbound] {
			return nil, false
		}
		o, ok := s.Resources[dec.Outbound]
		return o, ok
	})
	if err != nil {
		slog.Error("route", "err", err)
	}
	info := &FlowInfo{Generation: genNo, RuleIndex: dec.RuleIndex, Chain: dec.Chain, Outbound: dec.Outbound}
	if g != nil {
		info.Revision = g.revision
		info.Fingerprint = fingerprintOf(g, dec.Outbound)
		if dec.RuleIndex >= 0 {
			info.RuleID = dec.Rule.ID
			info.Rule = dec.Rule.String()
		}
	}
	if !ok {
		if fakeRelease != nil {
			fakeRelease()
		}
		return sagernet.Route{Info: info}
	}
	baseRelease := release
	release = func() {
		baseRelease()
		if fakeRelease != nil {
			fakeRelease()
		}
	}
	result := sagernet.Route{Outbound: out, Release: release, Info: info}
	if fakeRelease != nil {
		d := md.Destination
		result.Destination = &d
	}
	if g.dns != nil {
		result.Lookup = func(ctx context.Context, d string) ([]netip.Addr, error) {
			scope := "proxy"
			if out.Type() == "direct" {
				scope = "direct"
			}
			return g.dns.Lookup(ctx, d, scope)
		}
	}
	return result
}

// ExplainRequest describes a hypothetical connection.
type ExplainRequest struct {
	Inbound string `json:"inbound,omitempty"`
	Network string `json:"network,omitempty"`
	Source  string `json:"source,omitempty"`
	// Destination is "host:port" or "address:port".
	Destination string `json:"destination"`
	// Addresses are used for ip rules instead of resolving the domain.
	Addresses []string `json:"addresses,omitempty"`
	// Resolve allows a DNS lookup when an ip rule needs one. Without it
	// the explanation stops there and says so.
	Resolve bool `json:"resolve,omitempty"`
	// Process stands in for the owning process.
	Process string `json:"process,omitempty"`
}

// Explanation is the answer to ExplainRoute.
type Explanation struct {
	Generation   uint64   `json:"generation"`
	Revision     uint64   `json:"revision"`
	Matched      bool     `json:"matched"`
	RuleIndex    int      `json:"rule_index"`
	RuleID       string   `json:"rule_id,omitempty"`
	Rule         string   `json:"rule,omitempty"`
	Final        bool     `json:"final,omitempty"`
	Chain        []string `json:"chain,omitempty"`
	Outbound     string   `json:"outbound,omitempty"`
	OutboundType string   `json:"outbound_type,omitempty"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	Resolved     []string `json:"resolved,omitempty"`
	ResolveError string   `json:"resolve_error,omitempty"`
	Undetermined string   `json:"undetermined,omitempty"`
}

type explainEnv struct {
	addrs   []netip.Addr
	resolve bool
	l       *lookupEnv
	process string
}

func (x *explainEnv) Resolve(ctx context.Context, domain string) ([]netip.Addr, error) {
	if x.addrs != nil {
		return x.addrs, nil
	}
	if !x.resolve {
		return nil, router.ErrNoLookup
	}
	return x.l.Resolve(ctx, domain)
}

func (x *explainEnv) Process(context.Context) (string, bool) { return x.process, x.process != "" }

// Explain routes a hypothetical connection against the active generation
// without making a connection (and without DNS unless allowed).
func (e *Engine) Explain(ctx context.Context, req ExplainRequest) (Explanation, error) {
	snap, g := e.current()
	if g.router == nil {
		return Explanation{}, errors.New("no active configuration")
	}
	md := router.Metadata{Inbound: req.Inbound, Network: req.Network}
	if md.Network == "" {
		md.Network = "tcp"
	}
	if md.Network != "tcp" && md.Network != "udp" {
		return Explanation{}, fmt.Errorf("network must be tcp or udp")
	}
	host, port, err := net.SplitHostPort(req.Destination)
	if err != nil {
		return Explanation{}, fmt.Errorf("destination: %w", err)
	}
	pn, err := netip.ParseAddrPort(net.JoinHostPort("0.0.0.0", port))
	if err != nil {
		return Explanation{}, fmt.Errorf("destination port: %w", err)
	}
	md.Port = pn.Port()
	if a, err := netip.ParseAddr(host); err == nil {
		md.Addr = a.Unmap()
	} else {
		md.Domain = router.NormalizeDomain(host)
	}
	if req.Source != "" {
		if md.Source, err = netip.ParseAddrPort(req.Source); err != nil {
			return Explanation{}, fmt.Errorf("source: %w", err)
		}
	}
	env := &explainEnv{resolve: req.Resolve, l: &lookupEnv{e: e, dns: g.dns}, process: req.Process}
	for _, s := range req.Addresses {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return Explanation{}, fmt.Errorf("address %q: %w", s, err)
		}
		env.addrs = append(env.addrs, a)
	}
	x := g.router.Explain(ctx, md, env)
	if !x.Undetermined {
		g.resolveObserved(&x.Decision, md, false)
	}
	out := Explanation{Generation: snap.Generation, Revision: g.revision, RuleIndex: x.RuleIndex}
	if x.Undetermined {
		out.Undetermined = fmt.Sprintf("rule %d (%s) needs the destination address; pass resolve or addresses", x.StoppedAt, g.router.Rules().Rule(x.StoppedAt))
		return out, nil
	}
	out.Matched = x.RuleIndex >= 0
	out.Final = !out.Matched
	out.Chain, out.Outbound = x.Chain, x.Outbound
	if out.Matched {
		out.RuleID, out.Rule = x.Rule.ID, x.Rule.String()
	}
	if o, ok := g.eff.Outbound(x.Outbound); ok {
		out.OutboundType, out.Fingerprint = o.Type, o.Fingerprint
	}
	for _, a := range x.Resolved {
		out.Resolved = append(out.Resolved, a.String())
	}
	if x.ResolveError != nil {
		out.ResolveError = x.ResolveError.Error()
	}
	return out, nil
}

// Connection is one active connection for listings.
type Connection struct {
	ID          uint64    `json:"id"`
	Inbound     string    `json:"inbound"`
	Network     string    `json:"network"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Outbound    string    `json:"outbound"`
	Start       time.Time `json:"start"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	FlowInfo
}

// Connections lists active connections.
func (e *Engine) Connections() []Connection {
	cs := e.backend.Connections()
	out := make([]Connection, 0, len(cs))
	for _, c := range cs {
		conn := Connection{
			ID: c.ID, Inbound: c.Metadata.Inbound, Network: c.Metadata.Network,
			Source: c.Metadata.Source.String(), Destination: c.Metadata.Destination.String(),
			Outbound: c.Outbound, Start: c.Start, Upload: c.Upload, Download: c.Download,
		}
		if fi, ok := c.Info.(*FlowInfo); ok {
			conn.FlowInfo = *fi
		}
		out = append(out, conn)
	}
	return out
}

// CloseConnections closes connections by ID (all when ids is nil).
func (e *Engine) CloseConnections(ids []uint64) int { return e.backend.CloseConnections(ids) }

// Status is a summary of the running state.
type Status struct {
	Network     platform.NetworkStatus `json:"network"`
	Generation  uint64                 `json:"generation"`
	Revision    uint64                 `json:"revision"`
	Connections int                    `json:"connections"`
	Outbounds   []string               `json:"outbounds"`
	Listeners   []ResourceChange       `json:"listeners"`
	Draining    int64                  `json:"draining"`
	Forced      int64                  `json:"forced_closes"`
	Retries     int64                  `json:"acquire_retries"`
}

// Status reports the running state.
func (e *Engine) Status() Status {
	snap, g := e.current()
	st := e.rt.Stats()
	s := Status{Generation: snap.Generation, Revision: g.revision, Connections: e.backend.ConnectionCount(),
		Draining: st.Retiring, Forced: st.Forced, Retries: st.Retries}
	for id := range snap.Resources {
		s.Outbounds = append(s.Outbounds, id)
	}
	slices.Sort(s.Outbounds)
	e.mu.Lock()
	for _, l := range e.listeners {
		s.Listeners = append(s.Listeners, ResourceChange{ID: l.cfg.ID, Action: l.cfg.Type, Listen: l.cfg.Listen.String()})
	}
	e.mu.Unlock()
	if e.takeover != nil {
		s.Network = e.takeover.Status()
	} else {
		s.Network = platform.NetworkStatus{Mode: "off", State: "Stopped"}
	}
	sortChanges(s.Listeners)
	return s
}

// Close stops listeners, closes every connection and waits for the
// outbound instances to close.
func (e *Engine) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	if e.takeover != nil {
		if err := e.takeover.Close(); err != nil {
			slog.Error("network recovery incomplete", "err", err)
		}
	}
	e.guard.Close()
	_, g := e.current()
	if g.policies != nil {
		g.policies.Close()
	}
	if e.dnsListener != nil {
		e.dnsListener.Close()
	}
	for _, l := range e.listeners {
		l.in.Close()
	}
	e.listeners = nil
	e.mu.Unlock()
	e.backend.CloseConnections(nil)
	e.rt.Close()
	e.backend.Close()
}

// ListenerAddr returns where a listener is bound (for tests and status).
func (e *Engine) ListenerAddr(id string) (netip.AddrPort, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	l, ok := e.listeners[id]
	if !ok {
		return netip.AddrPort{}, false
	}
	return l.cfg.Listen, true
}

// OutboundInstance returns the instance serving id in the active
// generation, for tests that check reuse.
func (e *Engine) OutboundInstance(id string) *sagernet.Outbound {
	snap, _ := e.current()
	return snap.Resources[id]
}

// ListenerInstance returns the running listener object for id, so tests
// can check that a commit did not rebind it.
func (e *Engine) ListenerInstance(id string) any {
	e.mu.Lock()
	defer e.mu.Unlock()
	if l, ok := e.listeners[id]; ok {
		return l.in
	}
	return nil
}

func protocolOptions(o compile.Outbound) json.RawMessage {
	values := map[string]any{}
	if o.Type == "vmess" {
		values["security"], values["packet_encoding"] = "auto", o.PacketEncoding
	}
	if p := o.Protocol; p != nil {
		switch o.Type {
		case "vmess":
			if p.Security != "" {
				values["security"] = p.Security
			}
			values["alter_id"] = p.AlterID
		case "hysteria2":
			values["up_mbps"], values["down_mbps"] = p.UpMbps, p.DownMbps
			if p.Obfs != nil {
				values["obfs"] = map[string]any{"type": p.Obfs.Type, "password": p.Obfs.Password}
			}
		case "tuic":
			values["congestion_control"], values["udp_relay_mode"], values["zero_rtt_handshake"] = p.Congestion, p.UDPMode, p.ZeroRTT
			if p.Heartbeat > 0 {
				values["heartbeat"] = fmt.Sprintf("%dms", p.Heartbeat)
			}
		case "snell":
			version := p.Version
			if version == 5 {
				version = 4
			}
			values["version"], values["userkey"], values["reuse"] = version, p.UserKey, p.Reuse
			if p.Version == 6 {
				values["mode"] = p.Mode
			} else if p.Obfs != nil {
				values["obfs_mode"], values["obfs_host"] = p.Obfs.Type, p.Obfs.Host
			}
		}
	}
	if o.Type == "vless" {
		values["flow"], values["packet_encoding"] = o.Flow, o.PacketEncoding
	}
	if t := o.Transport; t != nil {
		headers := map[string][]string{}
		for _, h := range t.Headers {
			key := http.CanonicalHeaderKey(h.Name)
			headers[key] = append(headers[key], h.Value)
		}
		if t.Host != "" {
			headers["Host"] = []string{t.Host}
		}
		transport := map[string]any{"type": t.Type}
		switch t.Type {
		case "ws":
			transport["path"], transport["headers"], transport["max_early_data"], transport["early_data_header_name"] = t.Path, headers, t.EarlyData, t.EarlyHeader
		case "grpc":
			transport["service_name"] = t.Service
		case "httpupgrade":
			host := t.Host
			if host == "" && len(headers["Host"]) > 0 {
				host = headers["Host"][0]
			}
			transport["host"], transport["path"], transport["headers"] = host, t.Path, headers
		}
		values["transport"] = transport
	}
	if m := o.Multiplex; m != nil {
		values["multiplex"] = map[string]any{"enabled": m.Enabled, "protocol": m.Protocol, "max_connections": m.MaxConnections, "min_streams": m.MinStreams, "max_streams": m.MaxStreams, "padding": m.Padding}
	}
	raw, _ := json.Marshal(values)
	return raw
}

// CheckNetwork detects external ownership changes without retaking settings.
func (e *Engine) CheckNetwork() {
	if e.takeover != nil {
		_ = e.takeover.Check()
	}
}

// SubscriptionClient shares socket bypass and the active explicit bootstrap.
func (e *Engine) SubscriptionClient() *http.Client {
	return subscription.HTTPClientWithControl(e.guard.Control, func(ctx context.Context, host string) ([]net.IP, error) {
		_, g := e.current()
		var ips []netip.Addr
		var err error
		if g.dns != nil {
			ips, err = g.dns.Lookup(ctx, host, "bootstrap")
		} else {
			ips, err = e.opts.Resolver.LookupNetIP(ctx, "ip", host)
		}
		out := make([]net.IP, len(ips))
		for i, a := range ips {
			out[i] = net.IP(a.AsSlice())
		}
		return out, err
	})
}

func (e *Engine) SetTUNFD(fd int)   { e.mu.Lock(); defer e.mu.Unlock(); e.opts.TUNFD = fd }
func (e *Engine) TUNSerial() uint64 { e.mu.Lock(); defer e.mu.Unlock(); return e.tunSerial }
func (e *Engine) RebuildTUN() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.takeover == nil {
		return errors.New("TUN unavailable")
	}
	return e.takeover.Rebuild()
}

func proxyEndpoint(eff *compile.Effective) string {
	if eff == nil {
		return ""
	}
	for _, l := range eff.Listeners {
		if l.ID == eff.Network.ProxyListener {
			return l.Listen.String()
		}
	}
	return ""
}

func (e *Engine) TUNStacks() []string { return sagernet.TUNStacks() }
