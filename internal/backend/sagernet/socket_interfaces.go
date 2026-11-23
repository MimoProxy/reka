package sagernet

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/history"
)

const (
	interfaceRefreshInterval = 5 * time.Second
	// Limit retained addresses even on hosts with many virtual interfaces.
	maxInterfaceAddresses = 256
)

type interfaceSnapshot struct {
	mu          sync.Mutex
	nextRefresh time.Time
	names       map[netip.Addr]string
}

var localInterfaces interfaceSnapshot

func (s *interfaceSnapshot) lookup(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	ip = ip.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	name := s.names[ip]
	if name != "" || time.Now().Before(s.nextRefresh) {
		return name
	}
	if names, err := snapshotInterfaceNames(); err == nil {
		s.names = names
	}
	s.nextRefresh = time.Now().Add(interfaceRefreshInterval)
	return s.names[ip]
}

func snapshotInterfaceNames() (map[netip.Addr]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	names := make(map[netip.Addr]string)
	add := func(ip netip.Addr, name string) {
		if previous, exists := names[ip]; exists {
			if previous != name {
				// An unscoped address can be assigned to multiple interfaces.
				names[ip] = ""
			}
		} else if len(names) < maxInterfaceAddresses {
			names[ip] = name
		}
	}
	for _, iface := range ifaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		name := history.Text(iface.Name, connectionLabelBytes)
		for _, addr := range addresses {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			add(ip, name)
			if ip.Is6() {
				add(ip.WithZone(iface.Name), name)
			}
		}
	}
	return names, nil
}
