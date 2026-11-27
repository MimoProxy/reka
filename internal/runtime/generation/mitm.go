package generation

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/runtime"
)

// No equivalent MITM bypass was found in sing-box or mihomo. Keep the
// requested retry window and cap the table to the size of sing-box's process cache.
const (
	mitmBypassDuration = 10 * time.Minute
	mitmBypassCapacity = 256
	mitmQUIC           = "mitm-quic"
	// The default HTTP port in sing-box common/urltest and mihomo listener/http.
	plainHTTPPort = 80
)

// Each generation owns one reference to its issuer, which can be shared.
type mitmIssuer struct {
	*ca.Issuer
	fingerprint string
	notAfter    time.Time
	refs        atomic.Int64
}

func retainMITMRef(counter *atomic.Int64) bool {
	for refs := counter.Load(); refs > 0; refs = counter.Load() {
		if counter.CompareAndSwap(refs, refs+1) {
			return true
		}
	}
	return false
}

func (i *mitmIssuer) release() {
	if i != nil && i.refs.Add(-1) == 0 {
		i.Close()
		i.Issuer = nil
	}
}

// Prepared sniffs and HTTP connections retain the generation across reloads.
// Rewrites and script fetches share outbound pins. Only TLS needs an issuer.
type httpGeneration struct {
	issuer                  *mitmIssuer
	pins                    map[*sagernet.Outbound]*sagernet.PinnedOutbound
	reroute                 bool
	plainHTTP, plainScripts bool
	// routeRequests is set when rules match request URLs or headers.
	routeRequests bool
	refs          atomic.Int64
}

func (m *httpGeneration) retain() bool { return m != nil && retainMITMRef(&m.refs) }

func (m *httpGeneration) outboundPins() map[*sagernet.Outbound]*sagernet.PinnedOutbound {
	return m.pins
}

func (m *httpGeneration) release() {
	if m != nil && m.refs.Add(-1) == 0 {
		closeSniffPins(m.pins)
		m.pins = nil
		m.issuer.release()
	}
}

func (g *generation) loadHTTPEngine(previous *generation, outbounds map[string]*sagernet.Outbound, scriptsSupported bool) {
	if g.eff == nil {
		return
	}
	issuer := g.loadMITMIssuer(previous)
	scriptRouting := scriptsSupported && g.scripts.count() != 0
	routeRequests := g.router != nil && g.router.Rules() != nil && g.router.Rules().MatchesHTTP()
	if issuer == nil && g.eff.HTTPRewrite == nil && !scriptRouting && !routeRequests {
		return
	}
	httpEnabled := canSniffHTTP(g.eff)
	plainScripts := httpEnabled && scriptRouting && g.scripts.MayMatchHTTP("", 0)
	plainHTTP := plainScripts || httpEnabled && (routeRequests || g.eff.HTTPRewrite.MayMatchHTTP("", 0))
	tls := issuer != nil && len(g.eff.MITM.Hostnames) != 0
	m := &httpGeneration{issuer: issuer, plainHTTP: plainHTTP, plainScripts: plainScripts, routeRequests: routeRequests}
	if tls || plainHTTP {
		requestScripts := tls && scriptRouting && len(g.scripts.requests) != 0 || plainScripts && g.scripts.mayMatchHTTPRequest("", 0)
		// A request routed by its URL may leave through any outbound.
		m.reroute = g.eff.HTTPRewrite.MayChangeRequestURL() || requestScripts || routeRequests
		needed := sniffDNSDependencies(g, outbounds)
		// Both request and response scripts may use the routed HTTP client.
		if m.reroute || tls && scriptRouting || plainScripts {
			for _, out := range outbounds {
				needed[out] = true
			}
		}
		if len(needed) != 0 {
			m.pins = make(map[*sagernet.Outbound]*sagernet.PinnedOutbound, len(needed))
		}
		for out := range needed {
			pin, err := out.Pin()
			if err != nil {
				closeSniffPins(m.pins)
				issuer.release()
				g.mitmCAError = "HTTP routing generation unavailable"
				return
			}
			m.pins[out] = pin
		}
	}
	m.refs.Store(1)
	g.httpEngine = m
}

func (g *generation) loadMITMIssuer(previous *generation) *mitmIssuer {
	if !g.eff.MITM.Enabled {
		return nil
	}
	store := g.eff.MITMCAStore()
	if store == nil {
		g.mitmCAError = "MITM CA store unavailable"
		return nil
	}
	authority, err := ca.Load(store)
	if err != nil {
		g.mitmCAError = err.Error()
		if errors.Is(err, ca.ErrNotFound) {
			g.mitmCAError = "no MITM CA installed"
		}
		return nil
	}
	info := authority.Info()
	if !time.Now().Before(info.NotAfter) {
		g.mitmCAError = "MITM CA has expired"
		return nil
	}
	if previous.httpEngine != nil && previous.httpEngine.issuer != nil && previous.httpEngine.issuer.fingerprint == info.FingerprintSHA256 {
		issuer := previous.httpEngine.issuer
		issuer.refs.Add(1)
		return issuer
	}
	issuer := &mitmIssuer{
		Issuer:      ca.NewIssuer(authority, ca.IssuerOptions{}),
		fingerprint: info.FingerprintSHA256,
		notAfter:    info.NotAfter,
	}
	issuer.refs.Store(1)
	return issuer
}

func (g *generation) mayMatchPlainHTTP(host string, port uint16) bool {
	if strings.Contains(host, ":") {
		if addr, err := netip.ParseAddr(host); err == nil {
			return g.mayMatchPlainHTTPAddr(addr.Unmap(), port)
		}
	}
	return g.eff.HTTPRewrite.MayMatchHTTP(host, port) || g.httpEngine.plainScripts && g.scripts.MayMatchHTTP(host, port)
}

// Surge notes that sniffing may miss cleartext HTTP on other ports. Rules
// that name no host match any port, so they only extend sniffing to port 80.
// A flow sniffed for another reason is still admitted by mayMatchPlainHTTP.
func (g *generation) maySniffPlainHTTP(host string, port uint16) bool {
	if port == plainHTTPPort {
		return g.httpEngine.routeRequests || g.mayMatchPlainHTTP(host, port)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.Unmap().String()
	}
	return g.eff.HTTPRewrite.NamesHTTP(host, port) || g.httpEngine.plainScripts && g.scripts.NamesHTTP(host, port)
}

func (g *generation) mayMatchPlainHTTPAddr(addr netip.Addr, port uint16) bool {
	return g.eff.HTTPRewrite.MayMatchHTTPAddr(addr, port) || g.httpEngine.plainScripts && g.scripts.MayMatchHTTPAddr(addr, port)
}

func (g *generation) mitmAvailable() bool {
	return g.httpEngine != nil && g.httpEngine.issuer != nil && time.Now().Before(g.httpEngine.issuer.notAfter)
}

func httpHostHint(md sagernet.Metadata) string {
	// A DNS answer for a shared address cannot authorize interception.
	// Keep using the observed Host or SNI on real IP connections.
	host := md.Destination.Domain
	if host == "" || md.Destination.DNSMapped {
		host = md.SniffedDomain
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}

func mitmHostname(md sagernet.Metadata) string {
	host := httpHostHint(md)
	if strings.Contains(host, ":") {
		if addr, err := netip.ParseAddr(host); err == nil {
			return addr.Unmap().String()
		}
	}
	return router.NormalizeDomain(host)
}

func (e *Engine) mitmMatches(g *generation, md sagernet.Metadata, host string) bool {
	if md.SkipMITM || host == "" || !g.mitmAvailable() {
		return false
	}
	cfg := g.eff.MITM
	return cfg.ClientSourceMatcher.Match(mitmClientAddress(md)) &&
		cfg.Matcher.Match(host, md.Destination.Port) && !e.mitmBypasses.contains(host)
}

func mitmClientAddress(md sagernet.Metadata) netip.Addr {
	if md.ClientSource.IsValid() {
		return md.ClientSource
	}
	return md.Source.Addr()
}

func (e *Engine) mitmBlocksQUIC(g *generation, md sagernet.Metadata) bool {
	return isQUICFlow(md) && g.eff.MITM.QUICBlock && e.mitmMatches(g, md, mitmHostname(md))
}

// newMITMRoute admits a connection to the HTTP engine. out and dec are the
// connection's route; when dec depended on a request, each request is
// routed again.
func (e *Engine) newMITMRoute(snap *runtime.Snapshot[*sagernet.Outbound], state routingState, md sagernet.Metadata, out *sagernet.Outbound, dec router.Decision) *sagernet.MITMRoute {
	g := snap.Value.(*generation)
	if g.httpEngine == nil || md.Network != "tcp" || md.SkipMITM {
		return nil
	}
	routeRequests := dec.HTTPPending && g.httpEngine.routeRequests
	if out.Type() == "reject-drop" && !routeRequests {
		return nil
	}
	var host string
	plain := md.Protocol == "http"
	switch md.Protocol {
	case "http":
		// Plain HTTP requires sniffing; disabling sniffing disables admission.
		if !g.httpEngine.plainHTTP {
			return nil
		}
		port := md.Destination.Port
		if hint := httpHostHint(md); hint != "" {
			if !routeRequests && !g.mayMatchPlainHTTP(hint, port) {
				return nil
			}
			host = mitmHostname(md)
		} else {
			addr := md.Destination.Addr.Unmap()
			if !addr.IsValid() || !routeRequests && !g.mayMatchPlainHTTPAddr(addr, port) {
				return nil
			}
			host = addr.String()
		}
	case "", "tls":
		if g.httpEngine.issuer == nil {
			return nil
		}
		host = mitmHostname(md)
		if !e.mitmMatches(g, md, host) {
			return nil
		}
	default:
		return nil
	}
	if !g.httpEngine.retain() {
		return nil
	}
	route := &sagernet.MITMRoute{
		Host: host, PlainHTTP: plain, Rewrite: g.eff.HTTPRewrite, MaxBodySize: compile.MITMMaxBodySize,
	}
	if plain {
		route.OnConnection = func() { e.plainHTTPConnections.Add(1) }
		route.OnRequest = func() { e.plainHTTPRequests.Add(1) }
	} else {
		route.Issuer = g.httpEngine.issuer.Issuer
		route.H2 = g.eff.MITM.H2
		route.SkipServerCertVerify = g.eff.MITM.SkipServerCertVerify
		route.OnPinFailure = func(_, reason string) { e.mitmBypasses.insert(host, reason) }
		route.OnConnection = func() { e.mitmConnections.Add(1) }
		route.OnRequest = func() { e.mitmRequests.Add(1) }
	}
	if g.scripts.count() != 0 && (!plain || e.scriptHost != nil) {
		route.MatchScript = e.mitmScriptMatcher(snap, state)
		route.OnScript = e.scriptRuns.record
	}
	if g.httpEngine.reroute {
		// Capture metadata only on routes that can change the destination.
		original := md
		reroute := func(ctx context.Context, target sagernet.Metadata) sagernet.Route {
			withPins := func(ctx context.Context) context.Context {
				return sagernet.WithPinnedOutbounds(ctx, g.httpEngine.pins)
			}
			acquire := func(pick func(*runtime.Snapshot[*sagernet.Outbound]) (*sagernet.Outbound, bool)) (uint64, *sagernet.Outbound, func(), bool, error) {
				out, ok := pick(snap)
				if !ok {
					return snap.Generation, nil, nil, false, nil
				}
				release, borrowed := g.httpEngine.pins[out].Borrow()
				return snap.Generation, out, release, borrowed, nil
			}
			rt := e.routeWithAcquire(withPins(ctx), target, acquire, snap, state, false)
			if rt.Outbound != nil {
				if rt.Destination == nil {
					rt.Destination = &target.Destination
				}
				rt.Context = withPins
				rt = retainSniffSnapshot(rt, snap)
			}
			return rt
		}
		route.Reroute = func(ctx context.Context, dest sagernet.Destination, request *sagernet.HTTPRequestInfo) sagernet.Route {
			target := original
			target.Destination, target.SniffedDomain = dest, ""
			if routeRequests {
				target.HTTPRequest = request
			}
			return reroute(ctx, target)
		}
		if routeRequests {
			route.RouteRequest = func(ctx context.Context, request sagernet.HTTPRequestInfo) (sagernet.Route, bool) {
				target := original
				target.HTTPRequest = &request
				rt := reroute(ctx, target)
				if rt.Outbound == out {
					// The request keeps the connection's outbound and origin.
					if rt.Release != nil {
						rt.Release()
					}
					return sagernet.Route{}, false
				}
				return rt, true
			}
		}
	}
	return route
}

func (e *Engine) MITMStatus() api.MITMStatus {
	_, g := e.current()
	status := api.MITMStatus{
		CALoaded:             g.mitmAvailable(),
		CAError:              g.mitmCAError,
		H2:                   "disabled",
		PinningBypasses:      e.mitmBypasses.list(),
		Connections:          e.mitmConnections.Load(),
		Requests:             e.mitmRequests.Load(),
		PlainHTTPConnections: e.plainHTTPConnections.Load(),
		PlainHTTPRequests:    e.plainHTTPRequests.Load(),
		Scripts:              e.scriptStatus(g),
	}
	if g.httpEngine != nil && g.httpEngine.issuer != nil && !status.CALoaded {
		status.CAError = "MITM CA has expired"
	}
	if g.eff != nil {
		status.Enabled = g.eff.MITM.Enabled
		status.HostnameCount = len(g.eff.MITM.Hostnames)
		if g.eff.MITM.H2 {
			status.H2 = "enabled"
		}
	}
	return status
}

type mitmBypassTable struct {
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]api.MITMBypassInfo
}

func (b *mitmBypassTable) contains(host string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, found := b.entries[host]
	if found && !b.now().Before(entry.ExpiresAt) {
		delete(b.entries, host)
		return false
	}
	return found
}

func (b *mitmBypassTable) insert(host, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if _, exists := b.entries[host]; !exists && len(b.entries) >= mitmBypassCapacity {
		var first api.MITMBypassInfo
		for _, entry := range b.entries {
			if first.Hostname == "" || entry.ExpiresAt.Before(first.ExpiresAt) ||
				entry.ExpiresAt.Equal(first.ExpiresAt) && entry.Hostname < first.Hostname {
				first = entry
			}
		}
		delete(b.entries, first.Hostname)
	}
	if b.entries == nil {
		b.entries = make(map[string]api.MITMBypassInfo)
	}
	b.entries[host] = api.MITMBypassInfo{Hostname: host, Reason: reason, ExpiresAt: now.Add(mitmBypassDuration)}
}

func (b *mitmBypassTable) list() []api.MITMBypassInfo {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	active := make([]api.MITMBypassInfo, 0, len(b.entries))
	for host, entry := range b.entries {
		if now.Before(entry.ExpiresAt) {
			active = append(active, entry)
		} else {
			delete(b.entries, host)
		}
	}
	slices.SortFunc(active, func(a, b api.MITMBypassInfo) int {
		return strings.Compare(a.Hostname, b.Hostname)
	})
	return active
}
