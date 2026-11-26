package generation

import (
	"context"
	"errors"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/model"
	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/router"
	D "github.com/miekg/dns"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
)

var dnsSequence atomic.Uint64

// Most proxies resolve only their own server locally. WireGuard resolves the
// inner destination on each flow and resolves its peer separately at handshake.
func outboundLookupScope(typ, directScope string) string {
	switch typ {
	case model.OutboundDirect:
		return directScope
	case model.OutboundWireGuard:
		return "normal"
	default:
		return "proxy"
	}
}

var errDNSDisabled = errors.New("DNS disabled")

func (e *Engine) lookupEndpointPeer(ctx context.Context, name string) ([]netip.Addr, error) {
	// A handshake can outlive the flow that triggered it. Capture the current
	// DNS generation for this lookup, including across DNS-only reloads.
	ctx, release, resolver, err := e.retainCurrentDNS(ctx)
	if errors.Is(err, errDNSDisabled) {
		return e.backend.Resolver().LookupNetIP(ctx, "ip", name)
	}
	if err != nil {
		return nil, err
	}
	defer release()
	// Proxy-server resolvers are validated to use direct transport.
	return resolver.Lookup(ctx, name, "proxy")
}

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
	resolveOutbound := func(via, address string) (string, error) {
		if via == "" {
			via = "direct"
		}
		id, _, err := p.eff.Router.ResolveDynamic(via, func(g router.Group) string {
			if p.policies != nil {
				return p.policies.Choose(g.ID, "DNS:"+address, g.Selected)
			}
			return g.Selected
		})
		return id, err
	}
	dial := func(ctx context.Context, network, address, via string) (net.Conn, error) {
		id, err := resolveOutbound(via, address)
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
		// The transport has already bootstrapped the DNS endpoint to an IP.
		// Additional proxy-server lookups must use a direct resolver here.
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
		dec := p.eff.RoutingRouter().ExplainWithResolver(ctx, router.Metadata{Domain: host, Addr: addr, Port: uint16(port), Network: network}, noDNS{}, func(dec *router.Decision) {
			if p.policies != nil {
				dec.Outbound, dec.Chain, _ = p.eff.Router.ResolveDynamic(dec.Target, func(g router.Group) string { return p.policies.Choose(g.ID, "DNS:"+ep.Host, g.Selected) })
			}
		})
		if dec.Undetermined {
			return ""
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
	pool := sagernet.NewDNSPool()
	dhcp := new(sagernet.DHCPDNS)
	resetIdle := func() { pool.ResetIdle(); dhcp.Reset() }
	resolver, err = RD.New(*cfg, RD.Options{History: e.history, Generation: sequence, Pool: e.fake, Match: match, Retire: pool.Retire, ResetIdle: resetIdle, Background: func(ctx context.Context) (context.Context, func(), error) {
		retained, release, active, err := e.retainCurrentDNS(ctx)
		if err == nil && active != resolver {
			release()
			return ctx, func() {}, errors.New("DNS generation retired")
		}
		return retained, release, err
	}, SystemExchange: e.systemDNSExchange(), System: func(ctx context.Context, d string) ([]netip.Addr, error) {
		return e.opts.Resolver.LookupNetIP(ctx, "ip", d)
	}, Route: route, Exchange: func(ctx context.Context, ep RD.Endpoint, q *D.Msg, lookup func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		if ep.Scheme == "dhcp" {
			return dhcp.Exchange(ctx, ep, q)
		}
		id, err := resolveOutbound(ep.Via, net.JoinHostPort(ep.Host, ep.Port))
		if err != nil {
			return nil, err
		}
		ep.Via = id
		RD.ReportUpstream(ctx, id, "")
		return pool.Exchange(ctx, ep, q, lookup, dial)
	}})
	if err != nil {
		pool.Retire()
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
	if networkSame && (!cfg.RespectRules || old.eff.RulesFingerprint == p.eff.RulesFingerprint && reflect.DeepEqual(old.eff.Routing, p.eff.Routing)) {
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
	ctx, release, resolver, err := e.retainCurrentDNS(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return resolver.Exchange(ctx, q, "normal", !e.packetFlowRealDNS.Load())
}

// A foreground DNS operation owns its captured dependencies until all racing
// upstream attempts finish. This also covers native API queries and listeners.
func (e *Engine) retainCurrentDNS(ctx context.Context) (context.Context, func(), *RD.Service, error) {
	for ctx.Err() == nil {
		snapshot, g := e.current()
		if g.dns == nil {
			return ctx, func() {}, nil, errDNSDisabled
		}
		pins := map[*sagernet.Outbound]*sagernet.PinnedOutbound{}
		valid := true
		for outbound := range sniffDNSDependencies(g, snapshot.Resources) {
			pin, err := outbound.Pin()
			if err != nil {
				valid = false
				break
			}
			pins[outbound] = pin
		}
		if valid {
			return sniffSnapshotContext(sagernet.WithPinnedOutbounds(ctx, pins), snapshot), func() { closeSniffPins(pins) }, g.dns, nil
		}
		closeSniffPins(pins)
		if e.rt.Current() == snapshot {
			return ctx, func() {}, nil, errors.New("DNS runtime stopped")
		}
	}
	return ctx, func() {}, nil, ctx.Err()
}

func (e *Engine) DNSState(path string) error { return e.fake.UseFile(path) }
