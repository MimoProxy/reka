package sagernet

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	"github.com/miekg/dns"
)

// dnsRouter answers the upstream dialer's lookups for domain server
// addresses. For now it uses the system resolver; Reka's DNS service
// (nameserver policy, fake IP, bootstrap) will replace it.
type dnsRouter struct {
	resolver *net.Resolver
}

var _ adapter.DNSRouter = (*dnsRouter)(nil)

func (r *dnsRouter) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (r *dnsRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	network := "ip"
	switch options.Strategy {
	case C.DomainStrategyIPv4Only:
		network = "ip4"
	case C.DomainStrategyIPv6Only:
		network = "ip6"
	}
	addrs, err := r.resolver.LookupNetIP(ctx, network, domain)
	if err != nil {
		return nil, err
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	switch options.Strategy {
	case C.DomainStrategyPreferIPv4:
		sortFamily(addrs, true)
	case C.DomainStrategyPreferIPv6:
		sortFamily(addrs, false)
	}
	if len(addrs) == 0 {
		return nil, errors.New("no address for " + domain)
	}
	return addrs, nil
}

// sortFamily moves one address family to the front and keeps the resolver's
// order otherwise.
func sortFamily(addrs []netip.Addr, ipv4First bool) {
	front := make([]netip.Addr, 0, len(addrs))
	back := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.Is4() == ipv4First {
			front = append(front, a)
		} else {
			back = append(back, a)
		}
	}
	copy(addrs, append(front, back...))
}

var errDNSNotImplemented = errors.New("reka: DNS exchange is not implemented yet")

func (r *dnsRouter) Exchange(context.Context, *dns.Msg, adapter.DNSQueryOptions) (*dns.Msg, error) {
	return nil, errDNSNotImplemented
}

func (r *dnsRouter) ExchangeAsync(_ context.Context, _ *dns.Msg, _ adapter.DNSQueryOptions, callback func(*dns.Msg, error)) {
	callback(nil, errDNSNotImplemented)
}

func (r *dnsRouter) ClearCache()                                    {}
func (r *dnsRouter) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
func (r *dnsRouter) ResetNetwork()                                  {}

// dnsTransportManager has no transports. With fewer than two transports the
// upstream dialer asks for Default(), gets nil, and passes the empty query
// options to dnsRouter.Lookup, which ignores the transport.
type dnsTransportManager struct{}

var _ adapter.DNSTransportManager = (*dnsTransportManager)(nil)

func (m *dnsTransportManager) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (m *dnsTransportManager) Transports() []adapter.DNSTransport             { return nil }
func (m *dnsTransportManager) Transport(string) (adapter.DNSTransport, bool)  { return nil, false }
func (m *dnsTransportManager) Default() adapter.DNSTransport                  { return nil }
func (m *dnsTransportManager) FakeIP() adapter.FakeIPTransport                { return nil }
func (m *dnsTransportManager) Create(context.Context, log.ContextLogger, string, string, any) error {
	return errors.New("reka: DNS transports are not supported yet")
}
