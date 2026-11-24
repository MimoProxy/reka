//go:build ios && cgo

package generation

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"

	RD "github.com/MimoProxy/reka/internal/dns"
	D "github.com/miekg/dns"
	"github.com/sagernet/sing-box/dns/transport/mdns"
	"github.com/sagernet/sing-tun/dnsinfo"
	"github.com/sagernet/sing/common/control"
)

// Serialize access to sing-tun's lazily bound Darwin DNS configuration API.
var dnsConfigAccess sync.Mutex

func (e *Engine) systemDNSExchange() RD.SystemExchangeFunc {
	if !e.opts.HostPacketFlow {
		return nil
	}
	return e.exchangePacketFlowSystemDNS
}

func (e *Engine) exchangePacketFlowSystemDNS(ctx context.Context, q *D.Msg) (*D.Msg, netip.Addr, error) {
	question := q.Question[0]
	name := strings.TrimSuffix(question.Name, ".")
	// Keep link-local names and the native address lookup's search domains
	// with the OS resolver.
	if mdns.IsLocalDomain(question.Name) || strings.EqualFold(name, "localhost") ||
		(name != "" && !strings.Contains(name, ".") && (question.Qtype == D.TypeA || question.Qtype == D.TypeAAAA)) {
		return nil, netip.Addr{}, RD.ErrSystemDNSUnavailable
	}
	iface, err := e.sceneInterface()
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || strings.HasPrefix(iface.Name, "utun") {
		return nil, netip.Addr{}, RD.ErrSystemDNSUnavailable
	}
	networks := e.packetNetworks.Load()
	if networks == nil {
		return nil, netip.Addr{}, RD.ErrSystemDNSUnavailable
	}
	dnsConfigAccess.Lock()
	config := dnsinfo.Copy()
	dnsConfigAccess.Unlock()
	servers := systemDNSServers(config, iface.Index, networks[:])
	dialer := net.Dialer{Control: control.BindToInterface(nil, iface.Name, iface.Index)}
	return exchangeSystemDNS(ctx, q, servers, func(ctx context.Context, network, address, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	})
}
