package history

import (
	"net/netip"
	"sync"
)

type DNSAddresses struct {
	IPv4, IPv6 netip.Addr
	Counts     [2]int // IPv4, IPv6
}

// SummarizeDNSAddresses keeps the first usable address of each family.
func SummarizeDNSAddresses(addrs []netip.Addr) DNSAddresses {
	var summary DNSAddresses
	for _, addr := range addrs {
		addr = addr.Unmap()
		switch {
		case addr.Is4():
			summary.Counts[0]++
			if !summary.IPv4.IsValid() {
				summary.IPv4 = addr
			}
		case addr.Is6():
			summary.Counts[1]++
			if !summary.IPv6.IsValid() {
				summary.IPv6 = addr
			}
		}
	}
	return summary
}

// DNSLookupSources retains the source that supplied the first address of
// each family. A reply containing only an alias cannot supply an address.
type DNSLookupSources struct {
	mu      sync.Mutex
	sources [2]string
}

func (s *DNSLookupSources) Observe(obs DNSObservation) {
	if obs.Err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, count := range obs.AddressAnswers {
		if count > 0 && s.sources[i] == "" {
			s.sources[i] = obs.Source
		}
	}
}

func (s *DNSLookupSources) ForAddress(addr netip.Addr) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case addr.Unmap().Is4():
		return s.sources[0]
	case addr.Is6():
		return s.sources[1]
	}
	return ""
}
