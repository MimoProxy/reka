package generation

import (
	"context"
	"errors"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/router"
	D "github.com/miekg/dns"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
)

var dnsSequence atomic.Uint64

func (e *Engine) prepareDNS(p *Prepared) error {
	cfg := p.eff.DNS
	if cfg == nil {
		return nil
	}
	match := func(pattern, domain string, addr netip.Addr) bool {
		r := p.eff.DNSMatches[pattern]
		return r != nil && r.Route(context.Background(), router.Metadata{Domain: router.NormalizeDomain(domain), Addr: addr}, nil).Outbound == "yes"
	}
	var resolver *RD.Service
	dial := func(ctx context.Context, network, address, via string) (net.Conn, error) {
		if via == "" {
			via = "direct"
		}
		id, _, err := p.eff.Router.ResolveDynamic(via, func(g router.Group) string {
			if p.policies != nil {
				return p.policies.Choose(g.ID, "DNS:"+address, g.Selected)
			}
			return g.Selected
		})
		if err != nil {
			return nil, err
		}
		out := p.outbounds[id]
		if out == nil {
			return nil, errors.New("DNS outbound unavailable or rejected")
		}
		if p.policies != nil {
			p.policies.MarkUsed(id)
		}
		ctx = sagernet.WithLookup(ctx, func(ctx context.Context, host string) ([]netip.Addr, error) {
			return resolver.Lookup(ctx, host, "proxy")
		})
		return out.Dial(ctx, network, address)
	}
	route := func(ctx context.Context, ep RD.Endpoint) string {
		host := ep.Host
		var addr netip.Addr
		if a, err := netip.ParseAddr(host); err == nil {
			addr = a
		} else {
			ips, err := resolver.Lookup(ctx, host, "bootstrap")
			if err != nil || len(ips) == 0 {
				return ""
			}
			addr = ips[0]
		}
		port, _ := net.LookupPort("tcp", ep.Port)
		network := "tcp"
		if ep.Scheme == "udp" {
			network = "udp"
		}
		dec := p.eff.Router.Explain(ctx, router.Metadata{Domain: host, Addr: addr, Port: uint16(port), Network: network}, noDNS{})
		if dec.Undetermined {
			return ""
		}
		if p.policies != nil {
			out, _, err := p.eff.Router.ResolveDynamic(dec.Target, func(g router.Group) string { return p.policies.Choose(g.ID, "DNS:"+ep.Host, g.Selected) })
			if err != nil {
				return ""
			}
			return out
		}
		return dec.Outbound
	}
	var err error
	_, old := e.current()
	sequence := dnsSequence.Add(1)
	same := old.dns != nil && old.eff != nil && old.eff.DNSFingerprint == p.eff.DNSFingerprint
	if same {
		sequence = old.dns.Generation()
	}
	resolver, err = RD.New(*cfg, RD.Options{Generation: sequence, Pool: e.fake, Match: match, System: func(ctx context.Context, d string) ([]netip.Addr, error) {
		return e.opts.Resolver.LookupNetIP(ctx, "ip", d)
	}, Route: route, Exchange: func(ctx context.Context, ep RD.Endpoint, q *D.Msg, lookup func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		return sagernet.ExchangeDNS(ctx, ep, q, lookup, dial)
	}})
	if err != nil {
		return err
	}
	networkSame := same && reflect.DeepEqual(old.eff.Groups, p.eff.Groups) && len(old.eff.Outbounds) == len(p.eff.Outbounds)
	if networkSame {
		for _, out := range p.eff.Outbounds {
			previous, ok := old.eff.Outbound(out.ID)
			if !ok || previous.Fingerprint != out.Fingerprint {
				networkSame = false
				break
			}
		}
	}
	if networkSame && (!cfg.RespectRules || old.eff.RulesFingerprint == p.eff.RulesFingerprint) {
		resolver.InheritCache(old.dns)
	}
	p.dns = resolver
	if cfg.Listen != "" && cfg.Listen != e.dnsAddress {
		listener, err := sagernet.NewDNSListener(cfg.Listen, e.ExchangeDNS)
		if err != nil {
			return err
		}
		p.dnsListener = listener
		p.dnsBound = true
	} else if cfg.Listen != "" {
		p.dnsListener = e.dnsListener
	}
	return nil
}

type noDNS struct{}

func (noDNS) Resolve(context.Context, string) ([]netip.Addr, error) { return nil, router.ErrNoLookup }
func (noDNS) Process(context.Context) (string, bool)                { return "", false }
func (e *Engine) ExchangeDNS(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	_, g := e.current()
	if g.dns == nil {
		return nil, errors.New("DNS disabled")
	}
	return g.dns.Exchange(ctx, q, "normal", true)
}

func (e *Engine) DNSState(path string) error { return e.fake.UseFile(path) }
