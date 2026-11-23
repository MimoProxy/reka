// Package dns owns resolver policy, scoped caches and fake-address lifetimes.
package dns

import (
	"fmt"
	"github.com/MimoProxy/reka/internal/router"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"unicode"
)

type Config struct {
	PreferH3       bool           `yaml:"prefer-h3" json:"prefer-h3,omitempty"`
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
	TTL            *int           `yaml:"fake-ip-ttl" json:"fake-ip-ttl,omitempty"`
	CacheSize      int            `yaml:"cache-size" json:"cache-size,omitempty"`
	StaleTTL       int            `yaml:"cache-stale-ttl" json:"cache-stale-ttl,omitempty"`
	Concurrency    int            `yaml:"max-concurrent-upstreams" json:"max-concurrent-upstreams,omitempty"`
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
	GeoSite  []string `yaml:"geosite" json:"geosite,omitempty"`
	GeoIPSet string   `yaml:"geoip-set" json:"geoip-set,omitempty"`
	GeoIP    *bool    `yaml:"geoip" json:"geoip,omitempty"`
	Code     string   `yaml:"geoip-code" json:"geoip-code,omitempty"`
	IPCIDR   []string `yaml:"ipcidr" json:"ipcidr,omitempty"`
	Domain   []string `yaml:"domain" json:"domain,omitempty"`
}
type Endpoint struct {
	Scheme, Host, Port, Path, Via string
	Scope                         string
	PreferH3                      bool
	Params                        map[string]string
}

func ParseEndpoint(raw string) (Endpoint, error) {
	if raw == "system" || raw == "system://" || raw == "dhcp://system" {
		return Endpoint{Scheme: "system"}, nil
	}
	if value, found := strings.CutPrefix(raw, "dhcp://"); found {
		name, err := url.PathUnescape(value)
		if err != nil || name == "" || len(name) > 255 || strings.TrimSpace(name) != name ||
			strings.HasPrefix(name, "-") || strings.ContainsAny(name, "/\\#?:@%") || strings.ContainsFunc(name, unicode.IsControl) {
			return Endpoint{}, fmt.Errorf("DHCP DNS requires a physical interface name and no port, path or route")
		}
		return Endpoint{Scheme: "dhcp", Host: name, Port: "53"}, nil
	}
	if !strings.Contains(raw, "://") {
		host, fragment, hasFragment := strings.Cut(raw, "#")
		if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
			raw = "[" + strings.ReplaceAll(host, "%", "%25") + "]"
			if hasFragment {
				raw += "#" + fragment
			}
		}
		raw = "udp://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return Endpoint{}, fmt.Errorf("invalid DNS endpoint")
	}
	switch u.Scheme {
	case "udp", "tcp", "tls", "https", "http", "quic", "h3":
	default:
		return Endpoint{}, fmt.Errorf("unsupported DNS transport %q", u.Scheme)
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "tls", "quic":
			port = "853"
		case "https", "h3":
			port = "443"
		case "http":
			port = "80"
		default:
			port = "53"
		}
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return Endpoint{}, fmt.Errorf("invalid DNS port")
	}
	if u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "h3" && (u.Path != "" || u.RawQuery != "") {
		return Endpoint{}, fmt.Errorf("DNS path is only valid for HTTPS")
	}
	path := u.RequestURI()
	if path == "/" && (u.Scheme == "https" || u.Scheme == "h3" || u.Scheme == "http") {
		path = "/dns-query"
	}
	ep := Endpoint{Scheme: u.Scheme, Host: u.Hostname(), Port: port, Path: path}
	if err := endpointOptions(&ep, u.Fragment); err != nil {
		return Endpoint{}, err
	}
	return ep, nil
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
	if c.TTL != nil && (*c.TTL < 0 || *c.TTL > 86400) {
		return fmt.Errorf("fake-ip-ttl must be 0–86400")
	}
	if c.StaleTTL < 0 || c.StaleTTL > 86400 {
		return fmt.Errorf("cache-stale-ttl must be 0..86400 seconds")
	}
	if c.Concurrency < 0 || c.Concurrency > 16 {
		return fmt.Errorf("max-concurrent-upstreams must be 0..16")
	}
	if c.CacheSize < 0 || c.CacheSize > 1_000_000 {
		return fmt.Errorf("invalid DNS cache size")
	}
	if c.Listen != "" {
		if _, err := netip.ParseAddrPort(c.Listen); err != nil {
			return fmt.Errorf("DNS listen must be IP:port")
		}
	}
	for _, list := range [][]string{c.Bootstrap, c.Proxy, c.Direct, c.Nameservers, c.Fallback} {
		for _, v := range list {
			if _, err := ParseEndpoint(v); err != nil {
				return err
			}
		}
	}
	for _, v := range c.Bootstrap {
		ep, _ := ParseEndpoint(v)
		if ep.Scheme != "system" && ep.Scheme != "dhcp" {
			if _, err := netip.ParseAddr(ep.Host); err != nil {
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
			if _, err := ParseEndpoint(v); err != nil {
				return err
			}
		}
	}
	for _, v := range c.Filter.IPCIDR {
		if _, err := netip.ParsePrefix(v); err != nil {
			return err
		}
	}
	for _, h := range c.Hosts {
		if h.ID == "" || len(h.Addresses) == 0 {
			return fmt.Errorf("invalid hosts entry")
		}
		for _, a := range h.Addresses {
			if _, err := netip.ParseAddr(a); err != nil {
				if len(h.Addresses) != 1 || !validHostAlias(a) {
					return fmt.Errorf("hosts value must contain IP addresses or one domain alias")
				}
			}
		}
	}
	for i, r := range []string{c.FakeRange, c.FakeRange6} {
		if r != "" {
			p, err := netip.ParsePrefix(r)
			if err != nil || i == 0 && !p.Addr().Is4() || i == 1 && !p.Addr().Is6() || p.Bits() > p.Addr().BitLen()-2 {
				return fmt.Errorf("fake range needs at least four addresses")
			}
		}
	}
	for _, p := range append(append([]string{}, c.FakeFilter...), c.Filter.Domain...) {
		if !strings.HasPrefix(p, "geosite:") && !strings.HasPrefix(p, "rule-set:") {
			if err := router.ValidDomainPattern(p); err != nil {
				return err
			}
		}
	}
	return nil
}

// FakeTTL distinguishes an omitted value from an explicit zero response TTL.
func (c Config) FakeTTL() int {
	if c.TTL == nil {
		// Match mihomo's short default so clients refresh addresses after eviction.
		return 1
	}
	return *c.TTL
}
func validHostAlias(s string) bool {
	s = strings.Trim(s, ".")
	if !strings.Contains(s, ".") || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
