package dns

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

type mapping struct {
	domain     string
	generation uint64
	expires    time.Time
	refs       int
}
type FakePool struct {
	path    string
	mu      sync.Mutex
	limit   int
	entries map[netip.Addr]*mapping
	next    map[netip.Prefix]netip.Addr
	ranges  map[netip.Prefix]bool
}

func NewFakePool(limit int) *FakePool {
	return &FakePool{limit: limit, entries: map[netip.Addr]*mapping{}, next: map[netip.Prefix]netip.Addr{}, ranges: map[netip.Prefix]bool{}}
}
func (p *FakePool) Allocate(gen uint64, domain string, r netip.Prefix, ttl time.Duration) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for ip, m := range p.entries {
		if m.refs == 0 && now.After(m.expires) {
			delete(p.entries, ip)
		} else if m.generation == gen && m.domain == domain && r.Contains(ip) {
			old := m.expires
			m.expires = now.Add(ttl)
			if err := p.save(); err != nil {
				m.expires = old
				return netip.Addr{}, err
			}
			return ip, nil
		}
	}
	if !r.IsValid() || len(p.entries) >= p.limit {
		return netip.Addr{}, errors.New("fake IP pool full or invalid")
	}
	r = r.Masked()
	if !p.ranges[r] && len(p.ranges) >= 1024 {
		return netip.Addr{}, errors.New("fake IP range history full")
	}
	p.ranges[r] = true
	next := p.next[r]
	if !next.IsValid() || !r.Contains(next) {
		next = r.Addr().Next()
	}
	for i := 0; i < p.limit+2; i++ {
		if !r.Contains(next) {
			next = r.Addr().Next()
		}
		if _, ok := p.entries[next]; !ok {
			p.entries[next] = &mapping{domain, gen, now.Add(ttl), 0}
			if err := p.save(); err != nil {
				delete(p.entries, next)
				return netip.Addr{}, err
			}
			p.next[r] = next.Next()
			return next, nil
		}
		next = next.Next()
	}
	return netip.Addr{}, errors.New("fake IP range exhausted")
}
func (p *FakePool) Acquire(ip netip.Addr) (string, func(), bool) {
	p.mu.Lock()
	m := p.entries[ip]
	if m == nil || m.refs == 0 && time.Now().After(m.expires) {
		p.mu.Unlock()
		return "", nil, false
	}
	m.refs++
	domain := m.domain
	p.mu.Unlock()
	var once sync.Once
	return domain, func() { once.Do(func() { p.mu.Lock(); m.refs--; p.mu.Unlock() }) }, true
}
func (p *FakePool) Contains(ip netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for r := range p.ranges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
func (p *FakePool) Size() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.entries) }
