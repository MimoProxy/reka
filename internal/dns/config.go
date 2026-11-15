// Package dns owns resolver policy, scoped caches and fake-address lifetimes.
package dns

import (
	"fmt"
	"github.com/MimoProxy/reka/internal/router"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

type Config struct {
	From           string         `yaml:"from" json:"from,omitempty"`
	Listen         string         `yaml:"listen" json:"listen,omitempty"`
	Nameservers    []string       `yaml:"nameserver" json:"nameserver,omitempty"`
	Bootstrap      []string       `yaml:"default-nameserver" json:"default-nameserver,omitempty"`
	Proxy          []string       `yaml:"proxy-server-nameserver" json:"proxy-server-nameserver,omitempty"`
	Direct         []string       `yaml:"direct-nameserver" json:"direct-nameserver,omitempty"`
	DirectPolicy   bool           `yaml:"direct-nameserver-follow-policy" json:"direct-nameserver-follow-policy,omitempty"`
	Policies       []Policy       `yaml:"nameserver-policy" json:"nameserver-policy,omitempty"`
	Fallback       []string       `yaml:"fallback" json:"fallback,omitempty"`
	Filter         FallbackFilter `yaml:"fallback-filter" json:"fallback-filter,omitempty"`
	Hosts          []Host         `yaml:"hosts" json:"hosts,omitempty"`
	UseHosts       bool           `yaml:"use-hosts" json:"use-hosts,omitempty"`
	SystemHosts    bool           `yaml:"use-system-hosts" json:"use-system-hosts,omitempty"`
	Mode           string         `yaml:"enhanced-mode" json:"enhanced-mode,omitempty"`
	FakeRange      string         `yaml:"fake-ip-range" json:"fake-ip-range,omitempty"`
	FakeRange6     string         `yaml:"fake-ip-range6" json:"fake-ip-range6,omitempty"`
	FakeFilter     []string       `yaml:"fake-ip-filter" json:"fake-ip-filter,omitempty"`
	FakeFilterMode string         `yaml:"fake-ip-filter-mode" json:"fake-ip-filter-mode,omitempty"`
	RespectRules   bool           `yaml:"respect-rules" json:"respect-rules,omitempty"`
	IPv6           bool           `yaml:"ipv6" json:"ipv6"`
	TTL            int            `yaml:"fake-ip-ttl" json:"fake-ip-ttl,omitempty"`
	CacheSize      int            `yaml:"cache-size" json:"cache-size,omitempty"`
}
type Policy struct {
	ID      string   `yaml:"id" json:"id"`
	Pattern string   `yaml:"pattern" json:"pattern"`
	Servers []string `yaml:"servers" json:"servers"`
}
type Host struct {
	ID        string   `yaml:"id" json:"id"`
	Addresses []string `yaml:"addresses" json:"addresses"`
}
type FallbackFilter struct {
	GeoIPSet string   `yaml:"geoip-set" json:"geoip-set,omitempty"`
	GeoIP    *bool    `yaml:"geoip" json:"geoip,omitempty"`
	Code     string   `yaml:"geoip-code" json:"geoip-code,omitempty"`
	IPCIDR   []string `yaml:"ipcidr" json:"ipcidr,omitempty"`
	Domain   []string `yaml:"domain" json:"domain,omitempty"`
}
type Endpoint struct{ Scheme, Host, Port, Path, Via string }

func ParseEndpoint(raw string) (Endpoint, error) {
	if raw == "system" {
		return Endpoint{Scheme: "system"}, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "udp://" + raw
	}
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.User != nil {
		return Endpoint{}, fmt.Errorf("invalid DNS endpoint")
	}
	switch u.Scheme {
	case "udp", "tcp", "tls", "https":
	default:
		return Endpoint{}, fmt.Errorf("unsupported DNS transport %q", u.Scheme)
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "tls":
			port = "853"
		case "https":
			port = "443"
		default:
			port = "53"
		}
	}
	if _, e := net.LookupPort("tcp", port); e != nil {
		return Endpoint{}, fmt.Errorf("invalid DNS port")
	}
	if u.Scheme != "https" && (u.Path != "" || u.RawQuery != "") {
		return Endpoint{}, fmt.Errorf("DNS path is only valid for HTTPS")
	}
	path := u.RequestURI()
	if path == "/" && u.Scheme == "https" {
		path = "/dns-query"
	}
	return Endpoint{u.Scheme, u.Hostname(), port, path, u.Fragment}, nil
}
func Validate(c *Config) error {
	if c == nil {
		return nil
	}
	if c.From != "" {
		return fmt.Errorf("unresolved DNS source")
	}
	if len(c.Nameservers) == 0 {
		return fmt.Errorf("DNS requires nameserver")
	}
	if c.Mode != "" && c.Mode != "redir-host" && c.Mode != "fake-ip" {
		return fmt.Errorf("unknown enhanced-mode")
	}
	if c.FakeFilterMode != "" && c.FakeFilterMode != "blacklist" && c.FakeFilterMode != "whitelist" {
		return fmt.Errorf("invalid fake-ip-filter-mode")
	}
	if c.TTL < 0 || c.TTL > 86400 {
		return fmt.Errorf("fake-ip-ttl must be 0–86400")
	}
	if c.CacheSize < 0 || c.CacheSize > 1_000_000 {
		return fmt.Errorf("invalid DNS cache size")
	}
	if c.Listen != "" {
		if _, e := netip.ParseAddrPort(c.Listen); e != nil {
			return fmt.Errorf("DNS listen must be IP:port")
		}
	}
	for _, list := range [][]string{c.Bootstrap, c.Proxy, c.Direct, c.Nameservers, c.Fallback} {
		for _, v := range list {
			if _, e := ParseEndpoint(v); e != nil {
				return e
			}
		}
	}
	for _, v := range c.Bootstrap {
		ep, _ := ParseEndpoint(v)
		if ep.Scheme != "system" {
			if _, e := netip.ParseAddr(ep.Host); e != nil {
				return fmt.Errorf("bootstrap DNS endpoint must be an IP")
			}
		}
		if ep.Via != "" && ep.Via != "direct" {
			return fmt.Errorf("bootstrap DNS must be direct")
		}
	}
	for _, v := range c.Proxy {
		ep, _ := ParseEndpoint(v)
		if ep.Via != "" && ep.Via != "direct" {
			return fmt.Errorf("proxy-server DNS cannot depend on a proxy (resolution cycle)")
		}
	}
	seen := map[string]bool{}
	for _, p := range c.Policies {
		if p.ID == "" || seen[p.ID] || len(p.Servers) == 0 {
			return fmt.Errorf("invalid or duplicate DNS policy")
		}
		seen[p.ID] = true
		for _, v := range p.Servers {
			if _, e := ParseEndpoint(v); e != nil {
				return e
			}
		}
	}
	for _, v := range c.Filter.IPCIDR {
		if _, e := netip.ParsePrefix(v); e != nil {
			return e
		}
	}
	for _, h := range c.Hosts {
		if h.ID == "" || len(h.Addresses) == 0 {
			return fmt.Errorf("invalid hosts entry")
		}
		for _, a := range h.Addresses {
			if _, e := netip.ParseAddr(a); e != nil {
				return e
			}
		}
	}
	for i, r := range []string{c.FakeRange, c.FakeRange6} {
		if r != "" {
			p, e := netip.ParsePrefix(r)
			if e != nil || i == 0 && !p.Addr().Is4() || i == 1 && !p.Addr().Is6() || p.Bits() > p.Addr().BitLen()-2 {
				return fmt.Errorf("fake range needs at least four addresses")
			}
		}
	}
	for _, p := range append(append([]string{}, c.FakeFilter...), c.Filter.Domain...) {
		if !strings.HasPrefix(p, "geosite:") && !strings.HasPrefix(p, "rule-set:") {
			if e := router.ValidDomainPattern(p); e != nil {
				return e
			}
		}
	}
	return nil
}
