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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/platform"
	"github.com/MimoProxy/reka/internal/policy"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/subscription"
	D "github.com/miekg/dns"
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
	ProfileID    string
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
	historyScope history.Scope
	policies     *policy.Manager
	dns          *RD.Service
	revision     uint64
	eff          *compile.Effective
	router       *router.Router
	outUDP       map[string]bool
	packetAddr   map[string]bool
	inUDP        map[string]bool
}

// Engine turns effective configurations into running generations: it
// computes what changes, prepares new instances and listeners, and
// switches atomically. Commits are serialized by the caller (ConfigService)
// and additionally by an internal lock.
type Engine struct {
	temporary         atomic.Pointer[temporaryRules]
	temporarySequence uint64
	sceneObservation  atomic.Pointer[sceneObservation]
	sceneManual       atomic.Pointer[manualScene]
	history           *history.Store
	probeOnce         sync.Once
	probeSlots        chan struct{}
	tunSerial         uint64
	takeover          *platform.Takeover
	networkErr        error
	guard             *sagernet.SocketGuard
	fake              *RD.FakePool
	dnsListener       *sagernet.DNSListener
	dnsAddress        string
	opts              EngineOptions
	backend           *sagernet.Backend
	rt                *runtime.Runtime[*sagernet.Outbound]

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

	e := &Engine{history: history.New(), fake: RD.NewFakePool(65536), opts: opts, listeners: map[string]*listener{}}
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
	opts.Backend.History = e.history
	opts.Backend.HistoryScope = func() history.Scope {
		_, active := e.current()
		return active.historyScope
	}
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
	e.rt = runtime.NewValue[*sagernet.Outbound](nil, &generation{historyScope: history.Scope{ProfileID: opts.ProfileID}}, runtime.Options{
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
	e.backend.SetPrepareFlow(e.prepareFlow)
	return e
}

// ProcessLookup reports whether process-name rules can match here.
func (e *Engine) ProcessLookup() bool { return e.backend.CanFindProcess() }

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
	p.RoutingChanged = gen.eff == nil && eff.Routing.Mode != "rule" || gen.eff != nil && !reflect.DeepEqual(gen.eff.Routing, eff.Routing)
	p.ProcessChanged = gen.eff == nil && eff.Process.Mode != "rule" || gen.eff != nil && !reflect.DeepEqual(gen.eff.Process, eff.Process)
	p.SniffChanged = gen.eff == nil && eff.Sniff.Enabled || gen.eff != nil && !reflect.DeepEqual(gen.eff.Sniff, eff.Sniff)
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
		if o.Type == model.OutboundReject || o.Type == "pass" {
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
	ready       atomic.Bool
	detours     []*outboundDetour
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
		if o.Type == model.OutboundReject || o.Type == "pass" {
			continue
		}
		if old, ok := snap.Resources[o.ID]; ok && fingerprintOf(gen, o.ID) == o.Fingerprint {
			p.outbounds[o.ID] = old
			continue
		}
		spec := specFor(o)
		var owner atomic.Pointer[sagernet.Outbound]

		lookupECH := func(ctx context.Context, name string) ([]byte, error) {
			if !p.ready.Load() {
				return nil, errors.New("ECH resolver is not prepared")
			}
			resolver := p.dns
			current, g := e.current()
			if current.Resources[o.ID] == owner.Load() {
				resolver = g.dns
			}
			if resolver == nil {
				return nil, errors.New("automatic ECH requires configured proxy-server DNS")
			}
			return sagernet.ResolveECH(ctx, name, func(ctx context.Context, q *D.Msg) (*D.Msg, error) { return resolver.Exchange(ctx, q, "proxy", false) })
		}
		if proxy, ok := spec.(sagernet.ProxySpec); ok {
			proxy.ECHLookup = lookupECH
			tlsSpecs := []*sagernet.TLSSpec{proxy.TLS}
			if proxy.Plugin != nil {
				tlsSpecs = append(tlsSpecs, proxy.Plugin.TLS)
			}
			for _, tlsSpec := range tlsSpecs {
				if tlsSpec != nil && tlsSpec.ECH != nil {
					tlsSpec.ECH.Lookup = lookupECH
				}
			}
			spec = proxy
		} else if vless, ok := spec.(sagernet.VLESSSpec); ok {
			vless.ECHLookup = lookupECH
			if vless.TLS != nil && vless.TLS.ECH != nil {
				vless.TLS.ECH.Lookup = lookupECH
			}
			spec = vless
		}

		var detour *outboundDetour
		if o.Dialer != nil && o.Dialer.Proxy != "" {
			detour = e.newDetour(p, o)
			spec = setSpecDetour(spec, detour.spec())
		}
		out, err := e.backend.NewOutbound(o.ID, spec)
		if err != nil {
			return fail(&PrepareError{Path: "/outbounds/" + o.ID, Err: err})
		}
		owner.Store(out)
		if detour != nil {
			detour.owner.Store(out)
			p.detours = append(p.detours, detour)
		}
		p.created = append(p.created, out)
		p.outbounds[o.ID] = out
	}
	for _, detour := range p.detours {
		if err := detour.attach(); err != nil {
			return fail(&PrepareError{Path: "/outbounds/" + detour.node + "/dialer/proxy", Err: err})
		}
	}
	if err := e.prepareDNS(p); err != nil {
		return fail(&PrepareError{Path: "/dns", Err: err})
	}
	e.preparePolicies(p)
	p.ready.Store(true)
	for _, detour := range p.detours {
		detour.ready.Store(true)
	}
	p.changes = e.listenerChanges(eff)
	for _, ch := range p.changes {
		if ch.Action != ActionCreate && ch.Action != ActionRebind {
			continue
		}
		in, err := e.newInbound(ch.cfg)
		if err != nil {
			return fail(&PrepareError{Path: "/listeners/" + ch.cfg.ID + "/listen", Err: err})
		}
		p.bound[ch.cfg.ID] = in
	}
	return p, nil
}

func (e *Engine) release(p *Prepared) {
	if p.dns != nil {
		p.dns.Retire()
	}
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
	_, previous := e.current()
	return e.ActivateProfile(p, revision, previous.historyScope.ProfileID)
}

// ActivateProfile tags the new generation before it can receive traffic.
func (e *Engine) ActivateProfile(p *Prepared, revision uint64, profileID string) (uint64, error) {
	if p.done {
		return 0, errors.New("preparation already used")
	}
	defer e.mu.Unlock()
	p.done = true
	eff := p.eff
	previousSnapshot, previousGeneration := e.current()
	scope := history.Scope{ProfileID: profileID, Generation: previousSnapshot.Generation + 1, Revision: revision}
	if p.dns != nil {
		p.dns.SetHistoryScope(scope)
	}
	g := &generation{historyScope: scope, policies: p.policies, dns: p.dns, revision: revision, eff: eff, router: eff.RoutingRouter(), outUDP: map[string]bool{}, inUDP: map[string]bool{}, packetAddr: map[string]bool{}}
	for _, o := range eff.Outbounds {
		g.outUDP[o.ID] = o.UDP
		g.packetAddr[o.ID] = o.Type == "vless" && o.PacketEncoding == "packetaddr"
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
		if p.dns != nil {
			p.dns.Retire()
		}
		return 0, &ActivateError{Err: err}
	}
	if profileID != previousGeneration.historyScope.ProfileID {
		e.backend.StopHTTPSDebug()
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
	if previousGeneration.dns != nil {
		previousGeneration.dns.Retire()
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
		in, err := e.newInbound(ch.cfg)
		if err != nil {
			errs = append(errs, fmt.Errorf("listener %s: %w", ch.ID, err))
			// Put the previous listener back if we can.
			if ch.old != nil {
				if back, err2 := e.newInbound(ch.old.cfg); err2 == nil {
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
	if rules := e.temporary.Load(); rules != nil && rules.profile != profileID {
		e.temporary.Store(nil)
	}
	if scene := e.sceneManual.Load(); scene != nil && (scene.profile != profileID || !networkSceneExists(g, scene.id)) {
		e.sceneManual.Store(nil)
	}
	e.refreshSceneObservation(g)
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

// usesUpstreamOutbound reports whether an outbound is built from the
// upstream protocol packages with generic options. REALITY keeps Reka's own
// handshake client; all other TLS protocols use the scoped component adapter.
func usesUpstreamOutbound(o compile.Outbound) bool {
	if o.Multiplex != nil && o.Multiplex.Enabled && !(o.Type == "vless" && o.TLS != nil && o.TLS.Reality != nil) {
		return true
	}
	if (o.TLS != nil && o.TLS.Carrier != nil || o.Plugin != nil || o.Dialer != nil || o.UDPOverTCP || len(o.Headers) > 0 || (o.Type == "socks" && o.TLS != nil)) && !(o.Type == "vless" && o.TLS != nil && o.TLS.Reality != nil) {
		return true
	}
	switch o.Type {
	case "http", "socks", "vmess", "trojan", "hysteria2", "tuic", "snell":
		return true
	case "vless":
		return o.TLS == nil || o.TLS.Reality == nil
	}
	return false
}

func specFor(o compile.Outbound) any {
	tls := func() *sagernet.TLSSpec {
		if o.TLS == nil {
			return nil
		}
		t := &sagernet.TLSSpec{Carrier: tlsCarrierSpec(o.TLS.Carrier), CertificatePin: o.TLS.CertificatePin, VerifyName: o.TLS.VerifyName, Certificate: o.TLS.Certificate, PrivateKey: o.TLS.PrivateKey, ServerName: o.TLS.ServerName, Insecure: o.TLS.Insecure, Fingerprint: o.TLS.Fingerprint, ALPN: o.TLS.ALPN}
		if ech := o.TLS.ECH; ech != nil && ech.Enabled {
			t.ECH = &sagernet.ECHSpec{Config: ech.Config, QueryServerName: ech.QueryServerName}
		}
		if r := o.TLS.Reality; r != nil {
			t.Reality = &sagernet.RealitySpec{PublicKey: r.PublicKey, ShortID: r.ShortID, X25519MLKEM768: r.X25519MLKEM768}
		}
		return t
	}
	if usesUpstreamOutbound(o) {
		var up, down *uint64
		var realm *sagernet.RealmSpec
		if p := o.Protocol; p != nil && o.Type == "hysteria2" {
			up, down = p.UpBPS, p.DownBPS
			if r := p.Realm; r != nil && r.Enabled {
				realm = &sagernet.RealmSpec{ServerURL: r.ServerURL, Token: r.Token, RealmID: r.RealmID, STUNServers: r.STUNServers}
				if t := r.TLS; t != nil {
					realm.TLS = &sagernet.TLSSpec{ServerName: t.ServerName, Insecure: t.Insecure, ALPN: t.ALPN, CertificatePin: t.CertificatePin, VerifyName: t.VerifyName, Certificate: t.Certificate, PrivateKey: t.PrivateKey}
				}
			}
		}
		return sagernet.ProxySpec{
			Realm: realm, UpBPS: up, DownBPS: down, Plugin: ssPluginSpec(o.Plugin),
			Encryption: o.Encryption,
			Type:       o.Type, Server: o.Server, Port: o.Port, UUID: o.UUID, Password: o.Password, Username: o.Username, Method: o.Method,
			TLS: tls(), Options: protocolOptions(o),
		}
	}
	switch o.Type {
	case "reject-drop":
		return sagernet.DropSpec{}
	case model.OutboundHTTP:
		return sagernet.HTTPSpec{Server: o.Server, Port: o.Port, Username: o.Username, Password: o.Password, TLS: tls()}
	case model.OutboundSOCKS:
		return sagernet.SOCKSSpec{Server: o.Server, Port: o.Port, Username: o.Username, Password: o.Password}
	case model.OutboundShadowsocks:
		return sagernet.ShadowsocksSpec{Server: o.Server, Port: o.Port, Method: o.Method, Password: o.Password}
	case model.OutboundVLESS:
		return sagernet.VLESSSpec{Encryption: o.Encryption, Server: o.Server, Port: o.Port, UUID: o.UUID, Flow: o.Flow, TLS: tls(), Options: protocolOptions(o)}
	}
	return sagernet.DirectSpec{}
}

// lookupEnv resolves and finds processes for one connection; results are
// cached so a retried evaluation does not look up again.
type lookupEnv struct {
	dns *RD.Service
	e   *Engine
	md  sagernet.Metadata

	resolved   bool
	addrs      []netip.Addr
	err        error
	processOff bool
	procDone   bool
	proc       string
	procOK     bool
	owner      router.ProcessInfo
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
	info, ok := l.ProcessInfo(ctx)
	return info.Path, ok && info.Path != ""
}

func (l *lookupEnv) ProcessInfo(ctx context.Context) (router.ProcessInfo, bool) {
	if l.processOff {
		return router.ProcessInfo{}, false
	}
	if !l.procDone {
		l.procDone = true
		info, ok := l.e.backend.FindProcessInfo(ctx, l.md)
		l.owner = router.ProcessInfo{PID: info.PID, Path: info.Path, UID: info.UID, UIDKnown: info.UIDKnown}
		l.proc, l.procOK = info.Path, ok
	}
	return l.owner, l.procOK
}

func routerMetadata(md sagernet.Metadata) router.Metadata {
	domain := md.Destination.Domain
	if domain == "" {
		domain = md.SniffedDomain
	}
	return router.Metadata{
		InboundType: md.InboundProtocol,
		InboundUser: md.InboundUser,
		InboundPort: md.InboundPort,
		Inbound:     md.Inbound,
		Network:     md.Network,
		Source:      md.Source,
		Domain:      router.NormalizeDomain(domain),
		Addr:        md.Destination.Addr,
		Port:        md.Destination.Port,
	}
}

func (e *Engine) StartHTTPSDebug(request api.HTTPSDebugRequest) (api.HTTPSDebugStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return api.HTTPSDebugStatus{}, errors.New("engine closed")
	}
	return e.backend.StartHTTPSDebug(request)
}

func (e *Engine) HTTPSDebugStatus() api.HTTPSDebugStatus { return e.backend.HTTPSDebugStatus() }
func (e *Engine) StopHTTPSDebug()                        { e.backend.StopHTTPSDebug() }

func (e *Engine) History() (*history.Store, history.Scope) {
	_, active := e.current()
	return e.history, active.historyScope
}

func (e *Engine) route(ctx context.Context, md sagernet.Metadata) sagernet.Route {
	return e.routeWithAcquire(ctx, md, e.rt.Acquire, nil, routingState{})
}

type snapshotAcquirer func(func(*runtime.Snapshot[*sagernet.Outbound]) (*sagernet.Outbound, bool)) (uint64, *sagernet.Outbound, func(), bool, error)

func (e *Engine) isFakeIP(g *generation, addr netip.Addr) bool {
	if e.fake.Contains(addr) {
		return true
	}
	if g.dns != nil {
		cfg := g.dns.Config()
		if cfg.Mode == "fake-ip" {
			for _, text := range []string{cfg.FakeRange, cfg.FakeRange6} {
				if prefix, err := netip.ParsePrefix(text); err == nil && prefix.Contains(addr) {
					return true
				}
			}
		}
	}
	return false
}

func (e *Engine) routeWithAcquire(ctx context.Context, md sagernet.Metadata, acquire snapshotAcquirer, fixed *runtime.Snapshot[*sagernet.Outbound], state routingState) sagernet.Route {
	var fakeRelease func()
	if md.Destination.Addr.IsValid() {
		if domain, release, ok := e.fake.Acquire(md.Destination.Addr); ok {
			fakeRelease = release
			md.Destination.Domain = domain
			md.Destination.Addr = netip.Addr{}
		} else {
			_, active := e.current()
			if fixed != nil {
				active = fixed.Value.(*generation)
			}
			if e.isFakeIP(active, md.Destination.Addr) {
				return sagernet.Route{Scope: active.historyScope}
			}
		}
	}
	env := &lookupEnv{e: e, md: md}
	var (
		dec router.Decision
		g   *generation
	)
	genNo, out, release, ok, err := acquire(func(s *runtime.Snapshot[*sagernet.Outbound]) (*sagernet.Outbound, bool) {
		g = s.Value.(*generation)
		if g.router == nil {
			return nil, false
		}
		if fixed == nil {
			state = e.routingState(g)
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
		env.processOff = g.eff.Process.Mode == "off"
		if g.eff.Process.Mode == "always" {
			env.ProcessInfo(ctx)
		}
		routeMD := routerMetadata(md)
		routeMD.NetworkScene = state.scene
		if routeMD.InboundPort == 0 && md.InboundType != "tun" {
			for _, listener := range g.eff.Listeners {
				if listener.ID == md.Inbound {
					routeMD.InboundPort = listener.Listen.Port()
					break
				}
			}
		}
		resolve := func(dec *router.Decision) { g.resolveObserved(dec, routeMD, true) }
		if len(state.temporary) == 0 {
			dec = g.router.RouteWithResolver(ctx, routeMD, env, resolve)
		} else {
			dec = g.router.ExplainWithOverrides(ctx, routeMD, env, resolve, state.temporary, state.at).Decision
		}
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
	info := &FlowInfo{
		Generation: genNo, RuleIndex: dec.RuleIndex, Chain: dec.Chain, Outbound: dec.Outbound,
		DestinationDomain: md.Destination.Domain, SniffedDomain: md.SniffedDomain, Protocol: md.Protocol,
		NetworkScene: state.scene,
	}
	if dec.Temporary {
		info.RuleSource = "temporary"
	}
	if !env.processOff && env.procDone && env.procOK {
		info.ProcessPID = env.owner.PID
		info.ProcessPath = env.owner.Path
		if env.owner.UIDKnown {
			uid := env.owner.UID
			info.ProcessUID = &uid
		}
	}
	if g != nil {
		info.Revision = g.revision
		info.Fingerprint = fingerprintOf(g, dec.Outbound)
		if dec.RuleIndex >= 0 || dec.Temporary {
			info.RuleID = dec.Rule.ID
			info.Rule = dec.Rule.String()
		}
	}
	scope := history.Scope{}
	if g != nil {
		scope = g.historyScope
	}
	if !ok {
		if fakeRelease != nil {
			fakeRelease()
		}
		return sagernet.Route{Info: info, Scope: scope}
	}
	baseRelease := release
	release = func() {
		baseRelease()
		if fakeRelease != nil {
			fakeRelease()
		}
	}
	result := sagernet.Route{Outbound: out, Release: release, Info: info, Scope: scope}
	if !env.processOff && env.procDone && env.procOK {
		result.Owner = sagernet.ProcessInfo{PID: env.owner.PID, Path: env.owner.Path, UID: env.owner.UID, UIDKnown: env.owner.UIDKnown}
	}
	if md.Network == "udp" && md.Destination.Domain != "" && g.packetAddr[dec.Outbound] {
		addresses, err := env.Resolve(ctx, md.Destination.Domain)
		if err != nil || len(addresses) == 0 {
			release()
			return sagernet.Route{Info: info, Scope: scope}
		}
		addr := addresses[0]
		for _, a := range addresses {
			if a.Unmap().Is4() {
				addr = a.Unmap()
				break
			}
		}
		destination := md.Destination
		destination.Domain = ""
		destination.Addr = addr
		result.Destination = &destination
	}
	if fakeRelease != nil && result.Destination == nil {
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

type explainEnv struct {
	addrs   []netip.Addr
	resolve bool
	l       *lookupEnv
	process string
	uid     *uint32
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

func (x *explainEnv) ProcessInfo(context.Context) (router.ProcessInfo, bool) {
	info := router.ProcessInfo{Path: x.process}
	if x.uid != nil {
		info.UID, info.UIDKnown = *x.uid, true
	}
	return info, info.Path != "" || info.UIDKnown
}

// Explain routes a hypothetical connection against the active generation
// without making a connection (and without DNS unless allowed).
func (e *Engine) Explain(ctx context.Context, req ExplainRequest) (Explanation, error) {
	snap, g := e.current()
	if g.router == nil {
		return Explanation{}, errors.New("no active configuration")
	}
	md := router.Metadata{Inbound: req.Inbound, Network: req.Network, InboundType: req.InboundType, InboundPort: req.InboundPort, InboundUser: req.InboundUser}
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
	env := &explainEnv{resolve: req.Resolve, l: &lookupEnv{e: e, dns: g.dns}, process: req.Process, uid: req.ProcessUID}
	for _, s := range req.Addresses {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return Explanation{}, fmt.Errorf("address %q: %w", s, err)
		}
		env.addrs = append(env.addrs, a)
	}
	state := e.routingState(g)
	md.NetworkScene = state.scene
	x := g.router.ExplainWithOverrides(ctx, md, env, func(dec *router.Decision) { g.resolveObserved(dec, md, false) }, state.temporary, state.at)
	out := Explanation{Generation: snap.Generation, Revision: g.revision, RuleIndex: x.RuleIndex, NetworkScene: state.scene}
	if x.Undetermined {
		if x.StoppedAt >= 0 {
			out.Undetermined = fmt.Sprintf("rule %d (%s) needs the destination address; pass resolve or addresses", x.StoppedAt, x.StoppedRule)
		} else {
			out.Undetermined = fmt.Sprintf("temporary rule %s (%s) needs the destination address; pass resolve or addresses", x.StoppedRule.ID, x.StoppedRule)
		}
		return out, nil
	}
	if x.Temporary {
		out.RuleSource = "temporary"
	}
	out.Matched = x.RuleIndex >= 0 || x.Temporary
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

// Connections lists active connections.
func (e *Engine) Connections() []Connection {
	cs := e.backend.Connections()
	out := make([]Connection, 0, len(cs))
	for _, c := range cs {
		conn := Connection{
			ID: c.ID, Inbound: c.Metadata.Inbound, Network: c.Metadata.Network,
			Source: c.Metadata.Source.String(), Destination: c.Metadata.Destination.String(),
			Outbound: c.Outbound, Start: c.Start, Upload: c.Upload, Download: c.Download,
			OriginalDestination: c.OriginalDestination,
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
	if g.dns != nil {
		g.dns.Retire()
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
	if d := o.Dialer; d != nil {
		values["bind_interface"], values["routing_mark"], values["tcp_fast_open"], values["tcp_multi_path"] = d.Interface, d.RoutingMark, d.TFO, d.MPTCP
		strategy := map[string]string{"ipv4": "ipv4_only", "ipv6": "ipv6_only", "ipv4-prefer": "prefer_ipv4", "ipv6-prefer": "prefer_ipv6"}[d.IPVersion]
		if strategy != "" {
			values["domain_strategy"] = strategy
		}
	}
	if o.UDPOverTCP {
		values["udp_over_tcp"] = map[string]any{"enabled": true, "version": o.UDPOverTCPVersion}
	}
	if len(o.Headers) > 0 {
		headers := map[string][]string{}
		for _, h := range o.Headers {
			key := http.CanonicalHeaderKey(h.Name)
			headers[key] = append(headers[key], h.Value)
		}
		if o.Username != "" {
			delete(headers, "Proxy-Authorization")
		}
		values["headers"] = headers
	}
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
			if len(p.ServerPorts) > 0 {
				values["server_ports"] = p.ServerPorts
				interval := p.HopInterval
				if interval == 0 {
					interval = 30
				} else if interval < 5 {
					interval = 5
				}
				maximum := max(p.HopIntervalMax, interval)
				values["hop_interval"], values["hop_interval_max"] = fmt.Sprintf("%ds", interval), fmt.Sprintf("%ds", maximum)
			}
			values["up_mbps"], values["down_mbps"] = p.UpMbps, p.DownMbps
			if p.Obfs != nil {
				values["obfs"] = map[string]any{"type": p.Obfs.Type, "password": p.Obfs.Password, "min_packet_size": p.Obfs.MinPacketSize, "max_packet_size": p.Obfs.MaxPacketSize}
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
		encoding := o.PacketEncoding
		if encoding == "none" {
			encoding = ""
		}
		values["flow"], values["packet_encoding"] = o.Flow, encoding
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
		case "xhttp":
			values["reka_xhttp"] = xhttpOptions(o)
		case "http":
			values["reka_http"] = map[string]any{"method": t.Method, "paths": t.Paths, "host": t.Host, "headers": headers}
		case "h2":
			transport["type"], transport["host"], transport["path"] = "http", t.Hosts, t.Path
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
		if t.Type != "http" && t.Type != "xhttp" {
			values["transport"] = transport
		}
	}
	if m := o.Multiplex; m != nil {
		values["multiplex"] = map[string]any{
			"only_tcp":        m.OnlyTCP,
			"enabled":         m.Enabled,
			"protocol":        m.Protocol,
			"max_connections": m.MaxConnections,
			"min_streams":     m.MinStreams,
			"max_streams":     m.MaxStreams,
			"padding":         m.Padding,
		}
		if m.Brutal != nil {
			values["multiplex"].(map[string]any)["brutal"] = map[string]any{"enabled": m.Brutal.Enabled, "up_bps": m.Brutal.UpBPS, "down_bps": m.Brutal.DownBPS}
		}
	}
	raw, _ := json.Marshal(values)
	return raw
}

// CheckNetwork detects external ownership changes without retaking settings.
func (e *Engine) CheckNetwork() {
	if e.takeover != nil {
		_ = e.takeover.Check()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed {
		_, g := e.current()
		e.refreshSceneObservation(g)
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

func (e *Engine) SetTUNFD(fd int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.opts.TUNFD = fd
}
func (e *Engine) TUNSerial() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tunSerial
}
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

func ssPluginSpec(p *model.SSPlugin) *sagernet.SSPluginSpec {
	if p == nil {
		return nil
	}
	out := &sagernet.SSPluginSpec{Username: p.Username, ClientFingerprint: p.ClientFingerprint, VersionHint: p.VersionHint, RestlsScript: p.RestlsScript, ForceTLS12: p.ForceTLS12, ALPN: p.ALPN, KCP: p.KCP, Type: p.Type, Mode: p.Mode, Host: p.Host, Path: p.Path, Password: p.Password, Version: p.Version, HTTPUpgrade: p.HTTPUpgrade, FastOpen: p.FastOpen, Headers: http.Header{}}
	out.Mux = p.Mux == nil || *p.Mux
	for _, h := range p.Headers {
		out.Headers.Add(h.Name, h.Value)
	}
	if t := p.TLS; t != nil {
		out.TLS = &sagernet.TLSSpec{ServerName: t.ServerName, Insecure: t.Insecure, Fingerprint: t.Fingerprint, ALPN: t.ALPN, CertificatePin: t.CertificatePin, VerifyName: t.VerifyName, Certificate: t.Certificate, PrivateKey: t.PrivateKey}
		if t.ECH != nil && t.ECH.Enabled {
			out.TLS.ECH = &sagernet.ECHSpec{Config: t.ECH.Config, QueryServerName: t.ECH.QueryServerName}
		}
	}
	return out
}

func tlsCarrierSpec(c *model.TLSCarrier) *sagernet.TLSCarrierSpec {
	if c == nil {
		return nil
	}
	return &sagernet.TLSCarrierSpec{Type: c.Type, Username: c.Username, Password: c.Password, Version: c.Version, VersionHint: c.VersionHint, Script: c.Script}
}
