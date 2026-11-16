package generation

import (
	"context"
	"net/netip"
	"sync"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	RD "github.com/MimoProxy/reka/internal/dns"
)

// sniffDNSDependencies identifies the transports the captured resolver may
// need after route selection. Parent transports are already pinned by their
// owning child. A DNS group retains every possible member, not just its current
// health choice. respect-rules can route a later DNS query to any rule target.
func sniffDNSDependencies(g *generation, resources map[string]*sagernet.Outbound) map[*sagernet.Outbound]bool {
	needed := map[*sagernet.Outbound]bool{}
	if g.dns == nil || g.eff == nil || g.eff.DNS == nil {
		return needed
	}
	cfg := g.eff.DNS
	if cfg.RespectRules {
		for _, outbound := range resources {
			needed[outbound] = true
		}
		return needed
	}
	lists := [][]string{cfg.Nameservers, cfg.Bootstrap, cfg.Proxy, cfg.Direct, cfg.Fallback}
	for _, policy := range cfg.Policies {
		lists = append(lists, policy.Servers)
	}
	for _, list := range lists {
		for _, raw := range list {
			endpoint, err := RD.ParseEndpoint(raw)
			if err != nil || endpoint.Scheme == "system" {
				continue
			}
			via := endpoint.Via
			if via == "" {
				via = "direct"
			}
			for _, id := range g.eff.DetourLeaves(via) {
				if outbound := resources[id]; outbound != nil {
					needed[outbound] = true
				}
			}
		}
	}
	return needed
}

func closeSniffPins(pins map[*sagernet.Outbound]*sagernet.PinnedOutbound) {
	for _, pin := range pins {
		_ = pin.Close()
	}
}

// retainFlowDNS gives the routed flow its resolver dependencies. They remain
// hidden dependency leases, even if the selected outbound is also a resolver.
// Applying the map to the whole dialing context covers automatic ECH as well
// as address lookups; the independent Lookup wrapper also supports callers
// that invoke a route's resolver directly. Caller cancellation is preserved.
func retainFlowDNS(result sagernet.Route, pins map[*sagernet.Outbound]*sagernet.PinnedOutbound) sagernet.Route {
	if len(pins) == 0 {
		return result
	}
	baseContext := result.Context
	result.Context = func(ctx context.Context) context.Context {
		if baseContext != nil {
			ctx = baseContext(ctx)
		}
		return sagernet.WithPinnedOutbounds(ctx, pins)
	}
	if lookup := result.Lookup; lookup != nil {
		result.Lookup = func(ctx context.Context, domain string) ([]netip.Addr, error) {
			return lookup(sagernet.WithPinnedOutbounds(ctx, pins), domain)
		}
	}
	baseRelease := result.Release
	var once sync.Once
	result.Release = func() {
		once.Do(func() {
			if baseRelease != nil {
				baseRelease()
			}
			closeSniffPins(pins)
		})
	}
	return result
}
