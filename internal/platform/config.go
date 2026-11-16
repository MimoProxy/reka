package platform

import (
	"fmt"
	"net/netip"
	"runtime"
	"strings"
)

// Network is local, durable intent. Descriptors and observed OS state never
// belong in a profile or subscription.
type Network struct {
	Mode          string    `yaml:"mode" json:"mode"`
	ProxyListener string    `yaml:"proxy-listener" json:"proxy-listener,omitempty"`
	ProxyBypass   string    `yaml:"proxy-bypass" json:"proxy-bypass,omitempty"`
	Service       string    `yaml:"service" json:"service,omitempty"`
	TUN           TUNConfig `yaml:"tun" json:"tun"`
}
type TUNConfig struct {
	Stack         string   `yaml:"stack" json:"stack"`
	MTU           int      `yaml:"mtu" json:"mtu"`
	Address4      string   `yaml:"address4" json:"address4"`
	Address6      string   `yaml:"address6" json:"address6,omitempty"`
	Routes        []string `yaml:"routes" json:"routes,omitempty"`
	ExcludeRoutes []string `yaml:"exclude-routes" json:"exclude-routes,omitempty"`
	BindInterface string   `yaml:"bind-interface" json:"bind-interface,omitempty"`
	DNSHijack     bool     `yaml:"dns-hijack" json:"dns-hijack"`
	// Android's host consumes these when constructing VpnService.Builder.
	AppMode string   `yaml:"app-mode" json:"app-mode,omitempty"`
	Apps    []string `yaml:"apps" json:"apps,omitempty"`
}

func Normalize(n *Network) (Network, error) {
	c := Network{Mode: "off"}
	if n != nil {
		c = *n
	}
	if c.Mode == "" {
		c.Mode = "off"
	}
	if c.Mode != "off" && c.Mode != "tun" && c.Mode != "system-proxy" {
		return c, fmt.Errorf("mode must be off, tun or system-proxy")
	}
	if c.Mode == "off" {
		return Network{Mode: "off"}, nil
	}
	if c.Mode == "system-proxy" {
		if len(c.ProxyBypass) > 8192 || strings.ContainsAny(c.ProxyBypass, "\r\n\x00") {
			return c, fmt.Errorf("proxy-bypass must be at most 8192 bytes without control characters")
		}
		for _, char := range c.ProxyBypass {
			if char < 32 || char == 127 {
				return c, fmt.Errorf("proxy-bypass cannot contain control characters")
			}
		}
		if runtime.GOOS != "windows" && c.ProxyBypass != "" {
			return c, fmt.Errorf("proxy-bypass is currently Windows-only")
		}
		if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
			return c, fmt.Errorf("system proxy is unavailable on %s", runtime.GOOS)
		}
		if c.ProxyListener == "" {
			return c, fmt.Errorf("proxy-listener is required")
		}
		return c, nil
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" && runtime.GOOS != "android" {
		return c, fmt.Errorf("TUN takeover is unavailable on %s", runtime.GOOS)
	}
	t := &c.TUN
	if t.Stack == "" {
		t.Stack = "mixed"
	}
	if t.Stack != "mixed" && t.Stack != "system" && t.Stack != "gvisor" {
		return c, fmt.Errorf("invalid TUN stack")
	}
	if t.MTU == 0 {
		t.MTU = 1500
	}
	if t.MTU < 1280 || t.MTU > 9000 {
		return c, fmt.Errorf("TUN MTU must be 1280..9000")
	}
	if t.Address4 == "" {
		t.Address4 = "172.19.0.1/30"
	}
	for i, v := range []string{t.Address4, t.Address6} {
		if v == "" {
			continue
		}
		p, err := netip.ParsePrefix(v)
		if err != nil || p.Addr().Is4() != (i == 0) || p.Addr().IsUnspecified() || p.Bits() == p.Addr().BitLen() {
			return c, fmt.Errorf("invalid TUN address %q", v)
		}
	}
	for _, v := range append(append([]string{}, t.Routes...), t.ExcludeRoutes...) {
		p, err := netip.ParsePrefix(v)
		if err != nil || p != p.Masked() {
			return c, fmt.Errorf("invalid route %q", v)
		}
		if p.Addr().Is6() && t.Address6 == "" {
			return c, fmt.Errorf("IPv6 route requires address6")
		}
	}
	if t.AppMode == "" {
		t.AppMode = "all"
	}
	if t.AppMode != "all" && t.AppMode != "include" && t.AppMode != "exclude" {
		return c, fmt.Errorf("app-mode must be all, include or exclude")
	}
	if t.AppMode == "all" && len(t.Apps) > 0 || t.AppMode != "all" && len(t.Apps) == 0 {
		return c, fmt.Errorf("apps must be nonempty only for include/exclude")
	}
	if runtime.GOOS != "android" && t.AppMode != "all" {
		return c, fmt.Errorf("app routing is Android-only")
	}
	if t.DNSHijack == false && len(t.Routes) == 0 {
		return c, fmt.Errorf("full TUN takeover requires dns-hijack")
	}
	return c, nil
}
