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
	if i.refs.Add(-1) == 0 {
		i.Close()
		i.Issuer = nil
	}
}

// The active generation, prepared sniffs and intercepted connections keep
// this state alive. Transparent URL rewrites can select any rule target, so
// those generations keep one shared pin per outbound until their flows end.
type mitmGeneration struct {
	issuer  *mitmIssuer
	pins    map[*sagernet.Outbound]*sagernet.PinnedOutbound
	reroute bool
	refs    atomic.Int64
}

func (m *mitmGeneration) retain() bool { return m != nil && retainMITMRef(&m.refs) }

func (m *mitmGeneration) release() {
	if m != nil && m.refs.Add(-1) == 0 {
		closeSniffPins(m.pins)
		m.pins = nil
		m.issuer.release()
	}
}

func (g *generation) loadMITM(previous *generation, outbounds map[string]*sagernet.Outbound) {
	if g.eff == nil || !g.eff.MITM.Enabled {
		return
	}
	store := g.eff.MITMCAStore()
	if store == nil {
		g.mitmCAError = "MITM CA store unavailable"
		return
	}
	authority, err := ca.Load(store)
	if err != nil {
		g.mitmCAError = err.Error()
		if errors.Is(err, ca.ErrNotFound) {
			g.mitmCAError = "no MITM CA installed"
		}
		return
	}
	info := authority.Info()
	if !time.Now().Before(info.NotAfter) {
		g.mitmCAError = "MITM CA has expired"
		return
	}
	var pins map[*sagernet.Outbound]*sagernet.PinnedOutbound
	reroute := len(g.eff.MITM.Hostnames) != 0 && g.eff.HTTPRewrite.MayChangeRequestURL()
	if len(g.eff.MITM.Hostnames) != 0 {
		needed := sniffDNSDependencies(g, outbounds)
		if reroute {
			for _, out := range outbounds {
				needed[out] = true
			}
		}
		if len(needed) != 0 {
			pins = make(map[*sagernet.Outbound]*sagernet.PinnedOutbound, len(needed))
		}
		for out := range needed {
			pin, err := out.Pin()
			if err != nil {
				closeSniffPins(pins)
				g.mitmCAError = "MITM routing generation unavailable"
				return
			}
			pins[out] = pin
		}
	}
	var i *mitmIssuer
	if previous.mitm != nil && previous.mitm.issuer.fingerprint == info.FingerprintSHA256 {
		i = previous.mitm.issuer
		i.refs.Add(1)
	} else {
		i = &mitmIssuer{
			Issuer:      ca.NewIssuer(authority, ca.IssuerOptions{}),
			fingerprint: info.FingerprintSHA256,
			notAfter:    info.NotAfter,
		}
		i.refs.Store(1)
	}
	g.mitm = &mitmGeneration{issuer: i, pins: pins, reroute: reroute}
	g.mitm.refs.Store(1)
}

func (g *generation) mitmAvailable() bool {
	return g.mitm != nil && time.Now().Before(g.mitm.issuer.notAfter)
}

func mitmHostname(md sagernet.Metadata) string {
	// The destination can already carry a domain from fake IP or an
	// explicit proxy target. A sniffed hint covers address-only connections.
	host := md.Destination.Domain
	if host == "" {
		host = md.SniffedDomain
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
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

func (e *Engine) newMITMRoute(snap *runtime.Snapshot[*sagernet.Outbound], state routingState, md sagernet.Metadata) *sagernet.MITMRoute {
	g := snap.Value.(*generation)
	if md.Network != "tcp" || md.Protocol != "" && md.Protocol != "tls" {
		return nil
	}
	host := mitmHostname(md)
	if !e.mitmMatches(g, md, host) || !g.mitm.retain() {
		return nil
	}
	route := &sagernet.MITMRoute{
		Host: host, Issuer: g.mitm.issuer.Issuer, Rewrite: g.eff.HTTPRewrite,
		MaxBodySize: compile.MITMMaxBodySize, SkipServerCertVerify: g.eff.MITM.SkipServerCertVerify,
		OnPinFailure: func(_, reason string) { e.mitmBypasses.insert(host, reason) },
		OnConnection: func() { e.mitmConnections.Add(1) },
		OnRequest:    func() { e.mitmRequests.Add(1) },
	}
	if g.mitm.reroute {
		route.Reroute = func(ctx context.Context, dest sagernet.Destination) sagernet.Route {
			target := md
			target.Destination, target.SniffedDomain = dest, ""
			withPins := func(ctx context.Context) context.Context {
				return sagernet.WithPinnedOutbounds(ctx, g.mitm.pins)
			}
			acquire := func(pick func(*runtime.Snapshot[*sagernet.Outbound]) (*sagernet.Outbound, bool)) (uint64, *sagernet.Outbound, func(), bool, error) {
				out, ok := pick(snap)
				if !ok {
					return snap.Generation, nil, nil, false, nil
				}
				release, borrowed := g.mitm.pins[out].Borrow()
				return snap.Generation, out, release, borrowed, nil
			}
			rt := e.routeWithAcquire(withPins(ctx), target, acquire, snap, state, false)
			if rt.Outbound != nil {
				if rt.Destination == nil {
					rt.Destination = &dest
				}
				rt.Context = withPins
				rt = retainSniffSnapshot(rt, snap)
			}
			return rt
		}
	}
	return route
}

func (e *Engine) MITMStatus() api.MITMStatus {
	_, g := e.current()
	status := api.MITMStatus{
		CALoaded:        g.mitmAvailable(),
		CAError:         g.mitmCAError,
		H2:              "disabled",
		PinningBypasses: e.mitmBypasses.list(),
		Connections:     e.mitmConnections.Load(),
		Requests:        e.mitmRequests.Load(),
	}
	if g.mitm != nil && !status.CALoaded {
		status.CAError = "MITM CA has expired"
	}
	if g.eff != nil {
		status.Enabled = g.eff.MITM.Enabled
		status.HostnameCount = len(g.eff.MITM.Hostnames)
		if g.eff.MITM.H2 {
			status.H2 = "not supported yet"
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
