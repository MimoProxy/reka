package generation

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	RD "github.com/MimoProxy/reka/internal/dns"
	D "github.com/miekg/dns"
	"github.com/sagernet/sing-tun/dnsinfo"
)

func systemDNSServers(config *dnsinfo.Configuration, index int, excluded []netip.Prefix) []netip.AddrPort {
	if config == nil || index == 0 {
		return nil
	}
	// Use only the physical interface's scoped resolvers. While the tunnel is
	// up, the unscoped default resolver is the tunnel's own DNS server, which
	// need not lie inside the tunnel's address prefixes. dnsinfo's Select falls
	// back to that resolver, so it is not used here.
	for _, resolver := range config.ScopedResolvers {
		if resolver.InterfaceIndex != index || resolver.Domain != "" {
			continue
		}
		var servers []netip.AddrPort
		for _, server := range resolver.Servers {
			addr := server.Addr().Unmap()
			if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || server.Port() == 0 {
				continue
			}
			if slices.ContainsFunc(excluded, func(prefix netip.Prefix) bool { return prefix.Contains(addr.WithZone("")) }) {
				continue
			}
			server = netip.AddrPortFrom(addr, server.Port())
			if !slices.Contains(servers, server) {
				servers = append(servers, server)
			}
		}
		if len(servers) > 0 {
			return servers
		}
	}
	return nil
}

func exchangeSystemDNS(ctx context.Context, q *D.Msg, servers []netip.AddrPort, dial sagernet.DNSDial) (*D.Msg, netip.Addr, error) {
	var response *D.Msg
	var responder netip.Addr
	var lastErr error
	for _, server := range servers {
		if err := ctx.Err(); err != nil {
			return nil, netip.Addr{}, err
		}
		attempt, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		m, err := sagernet.ExchangeDNS(attempt, RD.Endpoint{
			Scheme: "udp", Host: server.Addr().String(), Port: strconv.Itoa(int(server.Port())),
		}, q, nil, dial)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if m.Rcode == D.RcodeSuccess || m.Rcode == D.RcodeNameError {
			return m, server.Addr(), nil
		}
		response, responder = m, server.Addr()
	}
	if response != nil {
		return response, responder, nil
	}
	if lastErr == nil {
		lastErr = RD.ErrSystemDNSUnavailable
	}
	return nil, netip.Addr{}, lastErr
}
