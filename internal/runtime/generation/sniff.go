package generation

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/runtime"
)

// prepareFlow pins routing resources during bounded sniffing. Selecting an
// outbound transfers its lease to the resulting flow; only its resolver's
// possible transports retain separate dependency pins until that flow ends.
// Both remain usable if a concurrent commit retires the captured generation.
func (e *Engine) prepareFlow(ctx context.Context, md sagernet.Metadata) sagernet.PreparedFlow {
	for {
		if ctx.Err() != nil {
			return sagernet.PreparedFlow{Route: func(context.Context, sagernet.Metadata) sagernet.Route { return sagernet.Route{} }}
		}
		snap, g := e.current()
		state := e.routingState(g)
		options := flowSniffOptions(ctx, g.eff, md, state.scene)
		if !e.flowMaySniff(g, md, state, options) {
			return sagernet.PreparedFlow{Route: e.route}
		}
		var mitm *mitmGeneration
		if g.mitm.retain() {
			mitm = g.mitm
		} else if e.rt.Current() != snap {
			continue
		}
		pins := map[*sagernet.Outbound]*sagernet.PinnedOutbound{}
		dnsPins := map[*sagernet.Outbound]*sagernet.PinnedOutbound{}
		valid := true
		for _, outbound := range snap.Resources {
			if pins[outbound] != nil {
				continue
			}
			pin, err := outbound.Pin()
			if err != nil {
				valid = false
				break
			}
			pins[outbound] = pin
		}
		if valid {
			for outbound := range sniffDNSDependencies(g, snap.Resources) {
				pin, err := outbound.Pin()
				if err != nil {
					valid = false
					break
				}
				dnsPins[outbound] = pin
			}
		}
		if !valid {
			closeSniffPins(pins)
			closeSniffPins(dnsPins)
			mitm.release()
			// Retirement without a newer snapshot is shutdown (or an invalid
			// resource), not a publication race. Do not spin waiting for one.
			if e.rt.Current() == snap {
				return sagernet.PreparedFlow{Route: func(context.Context, sagernet.Metadata) sagernet.Route { return sagernet.Route{} }}
			}
			continue
		}
		var mu sync.Mutex
		borrowPins := make(map[*sagernet.Outbound]*sagernet.PinnedOutbound, len(pins))
		for outbound, pin := range pins {
			borrowPins[outbound] = pin
		}
		closed := false
		release := func() {
			mu.Lock()
			defer mu.Unlock()
			if closed {
				return
			}
			closed = true
			for outbound, pin := range pins {
				_ = pin.Close()
				delete(pins, outbound)
			}
			closeSniffPins(dnsPins)
			dnsPins = nil
			mitm.release()
		}
		acquire := func(pick func(*runtime.Snapshot[*sagernet.Outbound]) (*sagernet.Outbound, bool)) (uint64, *sagernet.Outbound, func(), bool, error) {
			outbound, ok := pick(snap)
			mu.Lock()
			defer mu.Unlock()
			if closed || !ok || pins[outbound] == nil {
				return snap.Generation, nil, nil, false, nil
			}
			release, transferred := pins[outbound].TransferToFlow()
			if !transferred {
				return snap.Generation, nil, nil, false, nil
			}
			delete(pins, outbound)
			return snap.Generation, outbound, release, true, nil
		}
		return sagernet.PreparedFlow{
			Sniff: options,
			Route: func(ctx context.Context, md sagernet.Metadata) sagernet.Route {
				ctx = sniffSnapshotContext(ctx, snap)
				result := e.routeWithAcquire(sagernet.WithPinnedOutbounds(ctx, borrowPins), md, acquire, snap, state, true)
				if result.Outbound == nil {
					return result
				}
				mu.Lock()
				if closed {
					mu.Unlock()
					result.Release()
					return sagernet.Route{Info: result.Info, Scope: result.Scope}
				}
				flowPins := dnsPins
				dnsPins = nil
				mu.Unlock()
				return retainSniffSnapshot(retainFlowDNS(result, flowPins), snap)
			},
			Release: release,
		}
	}
}

func (e *Engine) flowMaySniff(g *generation, md sagernet.Metadata, state routingState, options sagernet.SniffOptions) bool {
	return options.Enabled && (!g.eff.SniffForRouting || e.routingNeedsDomain(g, md, state) || e.mitmNeedsDomain(g, md, options))
}

func (e *Engine) mitmNeedsDomain(g *generation, md sagernet.Metadata, options sagernet.SniffOptions) bool {
	if md.SkipMITM || !g.mitmAvailable() || mitmHostname(md) != "" || !md.Destination.Addr.IsValid() || e.isFakeIP(g, md.Destination.Addr) {
		return false
	}
	cfg := g.eff.MITM
	if !cfg.ClientSourceMatcher.Match(mitmClientAddress(md)) || !cfg.Matcher.MayMatchPort(md.Destination.Port) {
		return false
	}
	switch md.Network {
	case "tcp":
		return slices.Contains(options.Protocols, "tls")
	case "udp":
		return cfg.QUICBlock && slices.Contains(options.Protocols, "quic")
	default:
		return false
	}
}

func (e *Engine) routingNeedsDomain(g *generation, md sagernet.Metadata, state routingState) bool {
	if g.router == nil || md.Destination.Domain != "" || md.SniffedDomain != "" || !md.Destination.Addr.IsValid() {
		return false
	}
	usesDomain := g.router.Rules().MatchesDomain() || slices.ContainsFunc(state.temporary, func(rule router.TimedRule) bool {
		return rule.Match.MatchesDomain() && g.router.OverrideActive(rule, state.at)
	})
	return usesDomain && !e.isFakeIP(g, md.Destination.Addr)
}

func flowSniffOptions(ctx context.Context, eff *compile.Effective, md sagernet.Metadata, scene string) sagernet.SniffOptions {
	if eff == nil || !eff.Sniff.Enabled {
		return sagernet.SniffOptions{}
	}
	cfg := eff.Sniff
	excluded := eff.SniffSkipDomains
	var skip func(string) bool
	if excluded != nil {
		skip = func(domain string) bool {
			return domain != "" && excluded.Route(ctx, router.Metadata{Domain: router.NormalizeDomain(domain)}, nil).Outbound == "yes"
		}
		if skip(md.Destination.Domain) || skip(md.SniffedDomain) {
			return sagernet.SniffOptions{}
		}
	}
	if eff.SniffRules != nil {
		m := router.Metadata{
			NetworkScene: scene,
			Inbound:      md.Inbound, InboundType: md.InboundProtocol, InboundUser: md.InboundUser, InboundPort: md.InboundPort,
			Network: md.Network, Source: md.Source, Domain: router.NormalizeDomain(md.Destination.Domain),
			Addr: md.Destination.Addr, Port: md.Destination.Port,
		}
		if m.Domain == "" {
			m.Domain = router.NormalizeDomain(md.SniffedDomain)
		}
		index := eff.SniffRules.Route(ctx, m, nil).RuleIndex
		if index < 0 || cfg.Rules[index].Action == "skip" {
			return sagernet.SniffOptions{}
		}
		rule := cfg.Rules[index]
		if len(rule.Protocols) > 0 {
			cfg.Protocols = rule.Protocols
		}
		if rule.OverrideDestination != nil {
			cfg.OverrideDestination = *rule.OverrideDestination
		}
	}
	return sagernet.SniffOptions{
		Enabled: true, Protocols: cfg.Protocols, Timeout: time.Duration(cfg.TimeoutMS) * time.Millisecond,
		MaxBytes: cfg.MaxBytes, MaxPackets: cfg.MaxPackets, OverrideDestination: cfg.OverrideDestination, SkipDomain: skip,
	}
}
