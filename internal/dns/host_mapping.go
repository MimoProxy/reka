package dns

import (
	"container/list"
	"net"
	"net/netip"
	"sync"

	"github.com/MimoProxy/reka/internal/router"
	D "github.com/miekg/dns"
)

// hostMappingCapacity matches the size of mihomo's DNS enhancer mapping.
const hostMappingCapacity = 4096

// HostMapping remembers the most recently used real addresses returned to DNS clients.
type HostMapping struct {
	mu      sync.Mutex
	byAddr  map[netip.Addr]*list.Element
	recency list.List
}

type hostEntry struct {
	addr   netip.Addr
	domain string
}

func NewHostMapping() *HostMapping {
	return &HostMapping{byAddr: make(map[netip.Addr]*list.Element)}
}

func (m *HostMapping) recordAnswers(domain string, answers []D.RR) {
	domain = router.NormalizeDomain(domain)
	if domain == "" || len(answers) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rr := range answers {
		var ip net.IP
		switch record := rr.(type) {
		case *D.A:
			ip = record.A
		case *D.AAAA:
			ip = record.AAAA
		default:
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if element := m.byAddr[addr]; element != nil {
			element.Value.(*hostEntry).domain = domain
			m.recency.MoveToFront(element)
			continue
		}
		m.byAddr[addr] = m.recency.PushFront(&hostEntry{addr, domain})
		if len(m.byAddr) > hostMappingCapacity {
			oldest := m.recency.Back()
			delete(m.byAddr, oldest.Value.(*hostEntry).addr)
			m.recency.Remove(oldest)
		}
	}
}

func (m *HostMapping) Lookup(addr netip.Addr) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	element := m.byAddr[addr.Unmap()]
	if element == nil {
		return "", false
	}
	m.recency.MoveToFront(element)
	return element.Value.(*hostEntry).domain, true
}
