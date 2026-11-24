package dns

import (
	"container/list"
	"errors"
	"net/netip"
	"slices"
	"sync"
)

const maxFakeRanges = 1024

var errFakePoolClosed = errors.New("fake IP pool closed")

type mappingKey struct {
	domain     string
	generation uint64
}

type mapping struct {
	ip   netip.Addr
	key  mappingKey
	refs int
	lru  *list.Element
}

type FakePool struct {
	mu       sync.Mutex
	limit    int
	entries  map[netip.Addr]*mapping
	byDomain map[mappingKey][]*mapping
	lru      list.List
	next     map[netip.Prefix]netip.Addr
	ranges   map[netip.Prefix]bool
	closed   bool
	file     fakeStateFile
}

func NewFakePool(limit int) *FakePool {
	return &FakePool{
		limit:    limit,
		entries:  make(map[netip.Addr]*mapping),
		byDomain: make(map[mappingKey][]*mapping),
		next:     make(map[netip.Prefix]netip.Addr),
		ranges:   make(map[netip.Prefix]bool),
	}
}

func (p *FakePool) Allocate(gen uint64, domain string, r netip.Prefix) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return netip.Addr{}, errFakePoolClosed
	}
	if !r.IsValid() || p.limit <= 0 {
		return netip.Addr{}, errors.New("fake IP pool full or invalid")
	}
	r = r.Masked()
	key := mappingKey{domain: domain, generation: gen}
	for _, m := range p.byDomain[key] {
		if r.Contains(m.ip) {
			p.touch(m)
			return m.ip, nil
		}
	}
	if !p.ranges[r] && len(p.ranges) >= maxFakeRanges {
		return netip.Addr{}, errors.New("fake IP range history full")
	}

	// Find a free address before eviction to keep advancing the cursor.
	ip := p.nextFree(r)
	full := len(p.entries) >= p.limit
	if full || !ip.IsValid() {
		var victim *mapping
		for entry := p.lru.Front(); entry != nil; entry = entry.Next() {
			m := entry.Value.(*mapping)
			// A saturated range can only reuse an address from that range.
			if m.refs == 0 && (ip.IsValid() || r.Contains(m.ip) && m.ip != r.Addr()) {
				victim = m
				break
			}
		}
		if victim == nil {
			if full {
				return netip.Addr{}, errors.New("fake IP pool full or invalid")
			}
			return netip.Addr{}, errors.New("fake IP range exhausted")
		}
		if !ip.IsValid() {
			ip = victim.ip
		}
		p.removeMapping(victim)
	}
	p.addMapping(&mapping{ip: ip, key: key})
	p.ranges[r] = true
	p.next[r] = advanceFakeIP(r, ip)
	p.markDirty()
	return ip, nil
}

func (p *FakePool) nextFree(r netip.Prefix) netip.Addr {
	first := r.Addr().Next()
	if !r.Contains(first) {
		return netip.Addr{}
	}
	start := p.next[r]
	if !r.Contains(start) {
		start = first
	}
	for ip := start; ; {
		if p.entries[ip] == nil {
			return ip
		}
		ip = advanceFakeIP(r, ip)
		if ip == start {
			return netip.Addr{}
		}
	}
}

func advanceFakeIP(r netip.Prefix, ip netip.Addr) netip.Addr {
	if next := ip.Next(); r.Contains(next) {
		return next
	}
	return r.Addr().Next()
}

func (p *FakePool) addMapping(m *mapping) {
	p.entries[m.ip] = m
	p.byDomain[m.key] = append(p.byDomain[m.key], m)
	m.lru = p.lru.PushBack(m)
}

func (p *FakePool) removeMapping(m *mapping) {
	delete(p.entries, m.ip)
	p.lru.Remove(m.lru)
	byDomain := p.byDomain[m.key]
	if len(byDomain) == 1 {
		delete(p.byDomain, m.key)
	} else {
		p.byDomain[m.key] = slices.DeleteFunc(byDomain, func(entry *mapping) bool { return entry == m })
	}
}

func (p *FakePool) touch(m *mapping) {
	if m.lru != p.lru.Back() {
		p.lru.MoveToBack(m.lru)
		p.markDirty()
	}
}

func (p *FakePool) Acquire(ip netip.Addr) (string, func(), bool) {
	p.mu.Lock()
	m := p.entries[ip]
	if m == nil || p.closed {
		p.mu.Unlock()
		return "", nil, false
	}
	m.refs++
	p.touch(m)
	domain := m.key.domain
	p.mu.Unlock()
	var once sync.Once
	return domain, func() { once.Do(func() { p.mu.Lock(); m.refs--; p.mu.Unlock() }) }, true
}

// Peek returns the domain mapped to ip without leasing the mapping or
// changing its recency, so a look that does not keep the flow leaves the
// pool as it was.
func (p *FakePool) Peek(ip netip.Addr) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.entries[ip]
	if m == nil || p.closed {
		return "", false
	}
	return m.key.domain, true
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
func (p *FakePool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}
