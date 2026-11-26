package dns

import (
	"context"
	"errors"
	"fmt"
	D "github.com/miekg/dns"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/history"
)

type ExchangeFunc func(context.Context, Endpoint, *D.Msg, func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error)
type MatchFunc func(pattern, domain string, addr netip.Addr) bool
type SystemExchangeFunc func(context.Context, *D.Msg) (*D.Msg, netip.Addr, error)

type Options struct {
	History        *history.Store
	Exchange       ExchangeFunc
	System         func(context.Context, string) ([]netip.Addr, error)
	SystemExchange SystemExchangeFunc
	Match          MatchFunc
	Pool           *FakePool
	Mapping        *HostMapping
	Generation     uint64
	Route          func(context.Context, Endpoint) string
	Background     func(context.Context) (context.Context, func(), error)
	Retire         func()
	ResetIdle      func()
}
type cached struct {
	msg       *D.Msg
	at, until time.Time
	noStale   bool
}
type Service struct {
	historyScope   history.Scope
	systemHosts    []Host
	cfg            Config
	opts           Options
	mu             sync.Mutex
	cache          map[string]cached
	flights        map[string]*queryFlight
	cacheEpoch     uint64
	retired        bool
	background     context.Context
	stopBackground context.CancelFunc
	refreshSlots   chan struct{}
	hits, misses   atomic.Uint64
}

func New(c Config, o Options) (*Service, error) {
	if err := Validate(&c); err != nil {
		return nil, err
	}
	if c.CacheSize == 0 {
		c.CacheSize = 4096
	}
	systemHosts := []Host{}
	if c.SystemHosts {
		path := "/etc/hosts"
		if runtime.GOOS == "windows" {
			root := os.Getenv("SystemRoot")
			if root == "" {
				root = `C:\Windows`
			}
			path = filepath.Join(root, "System32", "drivers", "etc", "hosts")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read system hosts: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			text, _, _ := strings.Cut(line, "#")
			parts := strings.Fields(text)
			if len(parts) < 2 {
				continue
			}
			a, err := netip.ParseAddr(parts[0])
			if err != nil {
				continue
			}
			for _, name := range parts[1:] {
				systemHosts = append(systemHosts, Host{ID: strings.ToLower(name), Addresses: []string{a.String()}})
			}
		}
	}
	if o.Pool == nil {
		o.Pool = NewFakePool(65536)
	}
	if o.Mapping == nil {
		o.Mapping = NewHostMapping()
	}
	if c.FakeRange == "" {
		c.FakeRange = "198.18.0.0/16"
	}
	if c.FakeRange6 == "" {
		c.FakeRange6 = "fc00::/18"
	}
	background, stop := context.WithCancel(context.Background())
	return &Service{systemHosts: systemHosts, cfg: c, opts: o, cache: map[string]cached{}, flights: map[string]*queryFlight{}, background: background, stopBackground: stop, refreshSlots: make(chan struct{}, 16)}, nil
}
func (s *Service) Config() Config { return s.cfg }
func (s *Service) Match(pattern, domain string, a netip.Addr) bool {
	if s.opts.Match != nil {
		return s.opts.Match(pattern, domain, a)
	}
	return pattern == domain
}
func (s *Service) Lookup(ctx context.Context, domain, scope string) ([]netip.Addr, error) {
	return s.lookup(ctx, domain, scope, map[string]bool{})
}
func (s *Service) lookup(ctx context.Context, domain, scope string, seen map[string]bool) ([]netip.Addr, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if seen[domain] || len(seen) >= 8 {
		return nil, errors.New("DNS CNAME loop or depth exceeded")
	}
	seen[domain] = true
	cname := ""

	var addrs []netip.Addr
	var last error
	types := []uint16{D.TypeA}
	if s.cfg.IPv6 {
		types = append(types, D.TypeAAAA)
	}
	for _, typ := range types {
		q := new(D.Msg)
		q.SetQuestion(D.Fqdn(domain), typ)
		m, err := s.ExchangeResolver(history.WithDNSOrigin(ctx, history.DNSOrigin{Kind: "resolver"}), q, scope, false)
		if err != nil {
			last = err
			continue
		}
		for _, rr := range m.Answer {
			switch a := rr.(type) {
			case *D.CNAME:
				cname = strings.TrimSuffix(a.Target, ".")
			case *D.A:
				if ip, ok := netip.AddrFromSlice(a.A); ok {
					addrs = append(addrs, ip.Unmap())
				}
			case *D.AAAA:
				if ip, ok := netip.AddrFromSlice(a.AAAA); ok {
					addrs = append(addrs, ip)
				}
			}
		}
	}
	if len(addrs) == 0 {
		if cname != "" {
			return s.lookup(ctx, cname, scope, seen)
		}
		if last != nil {
			return nil, last
		}
		return nil, fmt.Errorf("DNS returned no address")
	}
	return addrs, nil
}

// Exchange answers a client query and remembers the real addresses it returns.
func (s *Service) Exchange(ctx context.Context, q *D.Msg, scope string, fake bool) (*D.Msg, error) {
	return s.exchangeRecorded(ctx, q, scope, exchangeOptions{client: true, fake: fake})
}

// ExchangeResolver serves internal lookups and diagnostics.
func (s *Service) ExchangeResolver(ctx context.Context, q *D.Msg, scope string, fake bool) (*D.Msg, error) {
	return s.exchangeRecorded(ctx, q, scope, exchangeOptions{fake: fake})
}

type exchangeOptions struct {
	client      bool
	fake        bool
	skipHosts   bool
	includeIPv6 bool
}

func (s *Service) exchangeRecorded(ctx context.Context, q *D.Msg, scope string, opts exchangeOptions) (*D.Msg, error) {
	id, start := queryID.Add(1), time.Now()
	var outcome resolutionHistory
	observe := history.DNSObserver(ctx)
	exchangeCtx := ctx
	if observe != nil {
		// Bootstrap queries and background refreshes have their own results.
		exchangeCtx = history.WithDNSObserver(ctx, nil)
	}
	m, err := s.exchange(exchangeCtx, q, scope, opts, id, &outcome)
	if opts.client && err == nil && m.Rcode == D.RcodeSuccess && outcome.ResultSource != "fake_ip" {
		s.opts.Mapping.recordAnswers(q.Question[0].Name, m.Answer)
	}
	if observe != nil {
		defer observe(exchangeObservation(q, m, start, outcome.ResultSource, err))
	}
	s.record(ctx, id, 0, start, scope, q, m, outcome, err)
	return m, err
}

func (s *Service) exchange(ctx context.Context, q *D.Msg, scope string, opts exchangeOptions, id uint64, outcome *resolutionHistory) (*D.Msg, error) {
	if len(q.Question) != 1 || q.Opcode != D.OpcodeQuery || q.IsTsig() != nil {
		return nil, errors.New("unsupported DNS query shape")
	}
	question := q.Question[0]
	domain := strings.ToLower(strings.TrimSuffix(question.Name, "."))
	typ := question.Qtype
	if question.Qclass != D.ClassINET {
		return nil, errors.New("unsupported DNS class")
	}
	reply := func() *D.Msg { m := new(D.Msg); m.SetReply(q); m.RecursionAvailable = true; return m }
	if typ == D.TypeAAAA && !s.cfg.IPv6 && !opts.includeIPv6 {
		outcome.ResultSource = "filtered"
		return reply(), nil
	}
	if !opts.skipHosts && s.cfg.UseHosts && (typ == D.TypeA || typ == D.TypeAAAA || typ == D.TypeCNAME) {
		host, alias, err := s.resolveHost(domain, typ)
		if err != nil {
			return nil, err
		}
		if host != nil {
			outcome.ResultSource = "hosts"
			m := reply()
			m.Authoritative = true
			if typ == D.TypeCNAME {
				if alias != "" {
					m.Answer = []D.RR{hostCNAME(question.Name, alias)}
				}
			} else {
				for _, text := range host.Addresses {
					a, _ := netip.ParseAddr(text)
					if rr := addressRR(question.Name, typ, a, 10); rr != nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			}
			return m, nil
		}
		if alias != "" {
			request := q.Copy()
			request.Question[0].Name = D.Fqdn(alias)
			// The alias chain has already been resolved. Skip the host table
			// for this exchange so wildcard aliases cannot recurse forever.
			opts.skipHosts = true
			m, err := s.exchange(ctx, request, scope, opts, id, outcome)
			if err != nil {
				return nil, err
			}
			m.Question = q.Question
			m.Answer = append([]D.RR{hostCNAME(question.Name, alias)}, m.Answer...)
			return m, nil
		}
	}
	for _, h := range s.systemHosts {
		if h.ID == domain {
			outcome.ResultSource = "system_hosts"
			m := reply()
			for _, text := range h.Addresses {
				a, _ := netip.ParseAddr(text)
				if rr := addressRR(question.Name, typ, a, 60); rr != nil {
					m.Answer = append(m.Answer, rr)
				}
			}
			return m, nil
		}
	}
	if opts.fake && s.cfg.Mode == "fake-ip" && (typ == D.TypeA || typ == D.TypeAAAA) && s.usesFakeIP(domain) {
		outcome.ResultSource = "fake_ip"
		r := s.cfg.FakeRange
		if typ == D.TypeAAAA {
			r = s.cfg.FakeRange6
		}
		prefix, _ := netip.ParsePrefix(r)
		ip, err := s.opts.Pool.Allocate(s.opts.Generation, domain, prefix)
		if err != nil {
			return nil, err
		}
		m := reply()
		m.Answer = []D.RR{addressRR(question.Name, typ, ip, uint32(s.cfg.FakeTTL()))}
		return m, nil
	}
	if opts.fake && s.cfg.Mode == "fake-ip" && (typ == D.TypeHTTPS || typ == D.TypeSVCB) && s.usesFakeIP(domain) {
		// Clients ask for service bindings next to every address lookup. A
		// faked domain is resolved where its connection is made, so forwarding
		// the query would only reveal the name to the configured resolvers, and
		// its address hints would let clients bypass the fake mapping.
		outcome.ResultSource = "fake_ip_empty"
		return reply(), nil
	}
	request := q.Copy()
	request.Id = 0
	wire, e := request.Pack()
	if e != nil {
		return nil, e
	}
	key := scope + "\x00" + string(wire)
	return s.cachedExchange(ctx, q, scope, key, id, outcome)
}

// usesFakeIP reports whether fake-ip mode answers domain with a fake address.
func (s *Service) usesFakeIP(domain string) bool {
	matched := false
	for _, p := range s.cfg.FakeFilter {
		if s.Match(p, domain, netip.Addr{}) {
			matched = true
			break
		}
	}
	if s.cfg.FakeFilterMode == "whitelist" {
		return matched
	}
	return !matched
}

func (s *Service) resolve(ctx context.Context, q *D.Msg, scope string, outcome *resolutionHistory) (*D.Msg, error) {
	servers := s.cfg.Nameservers
	domain := strings.ToLower(strings.TrimSuffix(q.Question[0].Name, "."))
	policy := scope == "normal" || scope == "direct" && s.cfg.DirectPolicy
	switch scope {
	case "bootstrap":
		servers = s.cfg.Bootstrap
		if len(servers) == 0 {
			servers = []string{"system"}
		}
	case "proxy":
		servers = s.cfg.Proxy
		if len(servers) == 0 {
			// Without proxy-server-nameserver, resolve proxy servers with the
			// main nameservers and nameserver-policy, as mihomo does.
			servers = directServers(s.cfg.Nameservers)
			for _, p := range s.cfg.Policies {
				if s.Match(p.Pattern, domain, netip.Addr{}) {
					if direct := directServers(p.Servers); len(direct) > 0 {
						servers = direct
					}
					break
				}
			}
		}
		if len(servers) == 0 {
			servers = s.cfg.Bootstrap
		}
		if len(servers) == 0 {
			servers = []string{"system"}
		}
	case "direct":
		if len(s.cfg.Direct) > 0 {
			servers = s.cfg.Direct
		}
	}
	policyMatched := false
	if policy {
		for _, p := range s.cfg.Policies {
			if s.Match(p.Pattern, domain, netip.Addr{}) {
				servers = p.Servers
				policyMatched = true
				break
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	primaryCtx := ctx
	primaryCancel := func() {}
	useFallback := scope == "normal" && !policyMatched && len(s.cfg.Fallback) > 0
	if useFallback {
		// Leave half the remaining budget for fallback when a primary stalls.
		deadline, _ := ctx.Deadline()
		primaryCtx, primaryCancel = context.WithTimeout(ctx, time.Until(deadline)/2)
	}
	m, err := s.query(primaryCtx, servers, q, scope, outcome)
	primaryCancel()
	fallback := err != nil || m != nil && m.Rcode != D.RcodeSuccess
	if useFallback {
		for _, p := range s.cfg.Filter.GeoSite {
			if !strings.HasPrefix(p, "rule-set:") && !strings.HasPrefix(p, "geosite:") {
				p = "geosite:" + strings.ToLower(p)
			}
			fallback = fallback || s.Match(p, domain, netip.Addr{})
		}
		for _, p := range s.cfg.Filter.Domain {
			fallback = fallback || s.Match(p, domain, netip.Addr{})
		}
		if m != nil {
			for _, rr := range m.Answer {
				var a netip.Addr
				switch v := rr.(type) {
				case *D.A:
					a, _ = netip.AddrFromSlice(v.A)
				case *D.AAAA:
					a, _ = netip.AddrFromSlice(v.AAAA)
				}
				if !a.IsValid() {
					continue
				}
				a = a.Unmap()
				for _, text := range s.cfg.Filter.IPCIDR {
					p, _ := netip.ParsePrefix(text)
					fallback = fallback || p.Contains(a)
				}
				if s.cfg.Filter.GeoIP != nil && *s.cfg.Filter.GeoIP {
					code := s.cfg.Filter.Code
					if code == "" {
						code = "cn"
					}
					pattern := "geoip:" + strings.ToLower(code)
					if s.cfg.Filter.GeoIPSet != "" {
						pattern = "rule-set:" + s.cfg.Filter.GeoIPSet
					}
					fallback = fallback || !s.Match(pattern, domain, a)
				}
			}
		}
		if fallback {
			m, err = s.query(ctx, s.cfg.Fallback, q, scope, outcome)
			outcome.Fallback = true
		}
	}
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("empty DNS response")
	}
	return m, nil
}

func (s *Service) queryOne(ctx context.Context, servers []string, q *D.Msg, scope string, outcome *resolutionHistory) (*D.Msg, error) {
	var last error
	for _, raw := range servers {
		ep, err := ParseEndpoint(raw)
		if err != nil {
			return nil, err
		}
		ep.Scope = scope
		ep.PreferH3 = s.cfg.PreferH3 && ep.Scheme == "https"
		if ep.Disabled(q.Question[0].Qtype) {
			outcome.ResultSource, outcome.Upstream, outcome.SystemServers = "filtered", nil, nil
			m := new(D.Msg)
			m.SetReply(q)
			return m, nil
		}
		if ep.Scheme == "system" {
			outcome.ResultSource, outcome.Upstream, outcome.SystemServers = "system", nil, nil
			m, err := s.querySystem(ctx, q, outcome)
			if err == nil {
				return m, nil
			}
			last = err
			continue
		}
		if ep.Scheme != "dhcp" && ep.Via == "" && scope == "normal" && s.cfg.RespectRules && s.opts.Route != nil {
			ep.Via = s.opts.Route(ctx, ep)
			if ep.Via == "" {
				last = errors.New("DNS routing could not determine a target")
				continue
			}
		}
		if s.opts.Exchange == nil {
			return nil, errors.New("DNS exchange unavailable")
		}
		attempt, upstream := attemptContext(ctx, ep)
		outcome.ResultSource, outcome.Upstream, outcome.SystemServers = "upstream", upstream, nil
		m, err := s.opts.Exchange(attempt, ep, ep.Request(q), func(ctx context.Context, d string) ([]netip.Addr, error) {
			if scope == "bootstrap" {
				return nil, errors.New("DNS bootstrap cycle")
			}
			return s.Lookup(ctx, d, "bootstrap")
		})
		if err == nil && m != nil {
			return m, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("no DNS upstream")
	}
	return nil, last
}
func addressRR(name string, typ uint16, a netip.Addr, ttl uint32) D.RR {
	h := D.RR_Header{Name: name, Rrtype: typ, Class: D.ClassINET, Ttl: ttl}
	if typ == D.TypeA && a.Is4() {
		return &D.A{Hdr: h, A: a.AsSlice()}
	}
	if typ == D.TypeAAAA && a.Is6() {
		return &D.AAAA{Hdr: h, AAAA: a.AsSlice()}
	}
	return nil
}
func (s *Service) Stats() (uint64, uint64) { return s.hits.Load(), s.misses.Load() }

func (s *Service) Generation() uint64 { return s.opts.Generation }
func (s *Service) InheritCache(old *Service) {
	if old == nil {
		return
	}
	old.mu.Lock()
	defer old.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, entry := range old.cache {
		if time.Now().Before(entry.until) {
			s.cache[key] = entry
		}
	}
	s.hits.Store(old.hits.Load())
	s.misses.Store(old.misses.Load())
}

func hostCNAME(name, alias string) D.RR {
	return &D.CNAME{Hdr: D.RR_Header{Name: name, Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 10}, Target: D.Fqdn(alias)}
}

// As in Clash, aliases ending in a hosts IP entry produce IP answers under
// the original question; unresolved aliases rewrite the upstream question.
func (s *Service) resolveHost(domain string, typ uint16) (*Host, string, error) {
	seen := map[string]bool{}
	alias := ""
	for depth := 0; depth < 32; depth++ {
		if seen[domain] {
			return nil, "", errors.New("hosts alias cycle")
		}
		seen[domain] = true
		var found *Host
		for i := range s.cfg.Hosts {
			if s.Match(s.cfg.Hosts[i].ID, domain, netip.Addr{}) {
				found = &s.cfg.Hosts[i]
				break
			}
		}
		if found == nil {
			return nil, alias, nil
		}
		if len(found.Addresses) == 1 {
			if _, err := netip.ParseAddr(found.Addresses[0]); err != nil {
				alias = strings.ToLower(strings.Trim(found.Addresses[0], "."))
				if typ == D.TypeCNAME {
					return found, alias, nil
				}
				domain = alias
				continue
			}
		}
		if typ == D.TypeCNAME {
			return nil, "", nil
		}
		return found, "", nil
	}
	return nil, "", errors.New("hosts alias depth exceeded")
}

// directServers drops nameservers that are reached through an outbound. A
// proxy server lookup through another proxy could depend on itself.
func directServers(servers []string) []string {
	var direct []string
	for _, raw := range servers {
		if ep, err := ParseEndpoint(raw); err == nil && (ep.Via == "" || ep.Via == "direct") {
			direct = append(direct, raw)
		}
	}
	return direct
}
