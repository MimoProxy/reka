package compile

import (
	"github.com/MimoProxy/reka/internal/config/model"
	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/platform"
)

func (c *compiler) network(e *Effective) {
	n, err := platform.Normalize(c.local.Network)
	if err != nil {
		c.errorf(model.DocLocal, "/network", "network.invalid", "%v", err)
		return
	}
	e.Network = n
	e.setOrigin("/network", Origin{Layer: LayerDefault})
	for path, pos := range c.lpos {
		if path == "/network" || len(path) > 9 && path[:9] == "/network/" {
			e.setOrigin(path, Origin{Layer: LayerLocal, Document: model.DocLocal, Path: path, Line: pos.Line, Column: pos.Column})
		}
	}
	if n.Mode == "system-proxy" {
		found := false
		for _, l := range e.Listeners {
			if l.ID == n.ProxyListener && l.Type == "mixed" && l.Listen.Addr().IsLoopback() {
				found = true
			}
		}
		if !found {
			c.errorf(model.DocLocal, "/network/proxy-listener", "network.proxy", "requires a loopback mixed listener")
		}
	}
	if n.Mode == "tun" && n.TUN.DNSHijack {
		if e.DNS == nil {
			c.errorf(model.DocLocal, "/network/tun/dns-hijack", "network.dns", "DNS must be configured for hijacking")
		}
		if n.Service != "" && n.TUN.Address4 == "" {
			c.errorf(model.DocLocal, "/network/service", "network.dns", "system DNS requires IPv4")
		}
	}
	if n.Mode == "tun" && len(n.TUN.Routes) == 0 && e.DNS != nil {
		if len(e.DNS.Bootstrap) == 0 {
			c.errorf(model.DocLocal, "/network", "network.bootstrap", "full takeover requires explicit default-nameserver")
		}
		servers := append(append(append(append(append([]string{}, e.DNS.Nameservers...), e.DNS.Proxy...), e.DNS.Bootstrap...), e.DNS.Direct...), e.DNS.Fallback...)
		for _, policy := range e.DNS.Policies {
			servers = append(servers, policy.Servers...)
		}
		for _, v := range servers {
			if endpoint, err := RD.ParseEndpoint(v); err == nil && endpoint.Scheme == "system" {
				c.errorf(model.DocLocal, "/network", "network.bootstrap", "full takeover requires explicit DNS upstreams instead of system")
			}
		}
	}

}
