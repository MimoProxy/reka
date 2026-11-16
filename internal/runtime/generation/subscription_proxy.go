package generation

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/router"
)

// SubscriptionProxyClient uses only the active generation. Unknown/rejected
// routes fail closed; a provider cannot silently bypass its declared proxy.
func (e *Engine) SubscriptionProxyClient(source, name string) (*http.Client, error) {
	client := e.SubscriptionClient()
	transport := client.Transport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		snap, g := e.current()
		if g.eff == nil {
			return nil, errors.New("provider_proxy_unavailable")
		}
		target := name
		switch name {
		case "DIRECT":
			target = "direct"
		case "REJECT":
			target = "reject"
		default:
			candidates, local := []string{}, []string{}
			add := func(id, display string) {
				if display != name && id != name {
					return
				}
				candidates = append(candidates, id)
				if strings.HasPrefix(id, source+"/") {
					local = append(local, id)
				}
			}
			for _, out := range g.eff.Outbounds {
				add(out.ID, out.Name)
			}
			for _, group := range g.eff.Groups {
				add(group.ID, g.eff.GroupMetadata[group.ID].Name)
			}
			if len(local) > 0 {
				candidates = local
			}
			if len(candidates) != 1 {
				return nil, errors.New("provider_proxy_unavailable")
			}
			target = candidates[0]
		}
		id, _, err := g.router.ResolveDynamic(target, func(group router.Group) string {
			if g.policies != nil {
				return g.policies.Choose(group.ID, "subscription:"+address, group.Selected)
			}
			return group.Selected
		})
		if err != nil {
			return nil, errors.New("provider_proxy_unavailable")
		}
		out := snap.Resources[id]
		if out == nil {
			return nil, errors.New("provider_proxy_unavailable")
		}
		ctx = sagernet.WithLookup(ctx, func(ctx context.Context, host string) ([]netip.Addr, error) {
			if g.dns != nil {
				return g.dns.Lookup(ctx, host, "proxy")
			}
			return e.opts.Resolver.LookupNetIP(ctx, "ip", host)
		})
		return out.Dial(ctx, network, address)
	}
	client.Transport = transport
	return client, nil
}
