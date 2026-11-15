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
)

type ExchangeFunc func(context.Context, Endpoint, *D.Msg, func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error)
type MatchFunc func(pattern, domain string, addr netip.Addr) bool
type Options struct {
	Exchange   ExchangeFunc
	System     func(context.Context, string) ([]netip.Addr, error)
	Match      MatchFunc
	Pool       *FakePool
	Generation uint64
	Route      func(context.Context, Endpoint) string
}
type cached struct {
	msg       *D.Msg
	at, until time.Time
}
type Service struct {
	systemHosts  []Host
	cfg          Config
	opts         Options
	mu           sync.Mutex
	cache        map[string]cached
	hits, misses atomic.Uint64
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
	if c.TTL == 0 {
		c.TTL = 60
	}
	if o.Pool == nil {
		o.Pool = NewFakePool(65536)
	}
	if c.FakeRange == "" {
		c.FakeRange = "198.18.0.0/16"
	}
	if c.FakeRange6 == "" {
		c.FakeRange6 = "fc00::/18"
	}
	return &Service{systemHosts: systemHosts, cfg: c, opts: o, cache: map[string]cached{}}, nil
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
		m, err := s.Exchange(ctx, q, scope, false)
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
func (s *Service) Exchange(ctx context.Context, q *D.Msg, scope string, fake bool) (*D.Msg, error) {
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
	if typ == D.TypeAAAA && !s.cfg.IPv6 {
		return reply(), nil
	}
	if s.cfg.UseHosts {
		for _, h := range s.cfg.Hosts {
			if s.Match(h.ID, domain, netip.Addr{}) {
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
	}
	for _, h := range s.systemHosts {
		if h.ID == domain {
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
	if fake && s.cfg.Mode == "fake-ip" && (typ == D.TypeA || typ == D.TypeAAAA) {
		matched := false
		for _, p := range s.cfg.FakeFilter {
			if s.Match(p, domain, netip.Addr{}) {
				matched = true
				break
			}
		}
		useFake := !matched
		if s.cfg.FakeFilterMode == "whitelist" {
			useFake = matched
		}
		if useFake {
			r := s.cfg.FakeRange
			if typ == D.TypeAAAA {
				r = s.cfg.FakeRange6
			}
			prefix, _ := netip.ParsePrefix(r)
			ip, err := s.opts.Pool.Allocate(s.opts.Generation, domain, prefix, time.Duration(s.cfg.TTL)*time.Second)
			if err != nil {
				return nil, err
			}
			m := reply()
			m.Answer = []D.RR{addressRR(question.Name, typ, ip, uint32(s.cfg.TTL))}
			return m, nil
		}
	}
	request := q.Copy()
	request.Id = 0
	wire, e := request.Pack()
	if e != nil {
		return nil, e
	}
	key := scope + "\x00" + string(wire)
	now := time.Now()
	s.mu.Lock()
	entry, ok := s.cache[key]
	if ok && !now.Before(entry.until) {
		delete(s.cache, key)
		ok = false
	}
	s.mu.Unlock()
	if ok {
		s.hits.Add(1)
		m := entry.msg.Copy()
		m.Id = q.Id
		age := uint32(now.Sub(entry.at) / time.Second)
		for _, rr := range append(append(m.Answer, m.Ns...), m.Extra...) {
			if rr.Header().Rrtype != D.TypeOPT {
				if rr.Header().Ttl > age {
					rr.Header().Ttl -= age
				} else {
					rr.Header().Ttl = 0
				}
			}
		}
		return m, nil
	}
	s.misses.Add(1)
	servers := s.cfg.Nameservers
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
	m, err := s.query(primaryCtx, servers, q, scope)
	primaryCancel()
	fallback := err != nil || m != nil && m.Rcode != D.RcodeSuccess
	if useFallback {
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
			m, err = s.query(ctx, s.cfg.Fallback, q, scope)
		}
	}
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("empty DNS response")
	}
	m = m.Copy()
	m.Id = q.Id
	ttl := uint32(3600)
	hasTTL := false
	for _, rr := range append(append([]D.RR{}, m.Answer...), m.Ns...) {
		v := rr.Header().Ttl
		if soa, ok := rr.(*D.SOA); ok {
			v = min(v, soa.Minttl)
		}
		ttl = min(ttl, v)
		hasTTL = true
	}
	if hasTTL && ttl > 0 && (m.Rcode == D.RcodeSuccess || m.Rcode == D.RcodeNameError) && !m.Truncated {
		s.mu.Lock()
		if len(s.cache) >= s.cfg.CacheSize {
			for k := range s.cache {
				delete(s.cache, k)
				break
			}
		}
		s.cache[key] = cached{m.Copy(), time.Now(), time.Now().Add(time.Duration(ttl) * time.Second)}
		s.mu.Unlock()
	}
	return m, nil
}
func (s *Service) query(ctx context.Context, servers []string, q *D.Msg, scope string) (*D.Msg, error) {
	var last error
	for _, raw := range servers {
		ep, err := ParseEndpoint(raw)
		if err != nil {
			return nil, err
		}
		if ep.Scheme == "system" {
			if s.opts.System == nil {
				last = errors.New("system resolver unavailable")
				continue
			}
			if q.Question[0].Qtype != D.TypeA && q.Question[0].Qtype != D.TypeAAAA {
				last = errors.New("system resolver supports address lookups only")
				continue
			}
			a, err := s.opts.System(ctx, strings.TrimSuffix(q.Question[0].Name, "."))
			if err != nil {
				last = err
				continue
			}
			m := new(D.Msg)
			m.SetReply(q)
			for _, ip := range a {
				if rr := addressRR(q.Question[0].Name, q.Question[0].Qtype, ip, 30); rr != nil {
					m.Answer = append(m.Answer, rr)
				}
			}
			return m, nil
		}
		if ep.Via == "" && scope == "normal" && s.cfg.RespectRules && s.opts.Route != nil {
			ep.Via = s.opts.Route(ctx, ep)
			if ep.Via == "" {
				last = errors.New("DNS routing could not determine a target")
				continue
			}
		}
		if s.opts.Exchange == nil {
			return nil, errors.New("DNS exchange unavailable")
		}
		m, err := s.opts.Exchange(ctx, ep, q, func(ctx context.Context, d string) ([]netip.Addr, error) {
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
