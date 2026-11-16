package generation

import (
	"context"
	"errors"
	"fmt"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/policy"
	"github.com/MimoProxy/reka/internal/router"
	"golang.org/x/net/publicsuffix"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
)

func (e *Engine) preparePolicies(p *Prepared) {
	if len(p.eff.AutoGroups) == 0 {
		return
	}
	var manager *policy.Manager
	probe := func(ctx context.Context, member, url string) error {
		target, _, err := p.eff.Router.ResolveDynamic(member, func(g router.Group) string { return manager.Choose(g.ID, "health-check", g.Selected) })
		if err != nil {
			return err
		}
		out := p.outbounds[target]
		if out == nil {
			return errors.New("probe outbound rejected")
		}
		tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if p.dns != nil {
				ctx = sagernet.WithLookup(ctx, func(ctx context.Context, host string) ([]netip.Addr, error) {
					scope := "proxy"
					if out.Type() == "direct" {
						scope = "direct"
					}
					return p.dns.Lookup(ctx, host, scope)
				})
			}
			return out.Dial(ctx, network, address)
		}}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return err
		}
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		if !policy.ExpectedStatusAllows(ctx, res.StatusCode) {
			return fmt.Errorf("health HTTP status %d", res.StatusCode)
		}
		return nil
	}
	manager = policy.New(p.eff.AutoGroups, probe)
	_, old := e.current()
	same := old.eff != nil && reflect.DeepEqual(old.eff.Groups, p.eff.Groups) && len(old.eff.Outbounds) == len(p.eff.Outbounds)
	if same {
		for _, out := range p.eff.Outbounds {
			previous, ok := old.eff.Outbound(out.ID)
			if !ok || previous.Fingerprint != out.Fingerprint {
				same = false
				break
			}
		}
	}
	if same {
		manager.Inherit(old.policies)
	}
	p.policies = manager
}
func (g *generation) resolveObserved(dec *router.Decision, md router.Metadata, touch bool) {
	if g.policies == nil {
		return
	}
	key := md.Domain
	if host, err := publicsuffix.EffectiveTLDPlusOne(md.Domain); err == nil {
		key = host
	} else if md.Addr.IsValid() {
		key = md.Addr.String()
	}
	out, chain, err := g.router.ResolveDynamic(dec.Target, func(group router.Group) string {
		if touch {
			return g.policies.Choose(group.ID, key, group.Selected)
		}
		return g.policies.Peek(group.ID, key, group.Selected)
	})
	if err != nil {
		dec.Outbound = ""
		dec.Chain = chain
		return
	}
	dec.Outbound, dec.Chain = out, chain
}
func (e *Engine) GroupStatus() []policy.Status {
	_, g := e.current()
	if g.policies == nil {
		return nil
	}
	return g.policies.Statuses()
}
