package compile

import (
	"github.com/MimoProxy/reka/internal/config/model"
	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/platform"
	"github.com/MimoProxy/reka/internal/router"
	"net/netip"
	"strings"
)

func (c *compiler) dns(eff *Effective) {
	cfg := c.profile.DNS
	if cfg == nil {
		return
	}
	if err := RD.Validate(cfg); err != nil {
		c.errorf(model.DocProfile, "/dns", "dns.config", "%s", err)
		return
	}
	rc := c.prepareRuleResources()
	matchers := map[string]*router.Router{}
	patterns := append(append([]string{}, cfg.FakeFilter...), cfg.Filter.Domain...)
	for _, p := range cfg.Filter.GeoSite {
		if !strings.HasPrefix(p, "rule-set:") && !strings.HasPrefix(p, "geosite:") {
			p = "geosite:" + strings.ToLower(p)
		}
		patterns = append(patterns, p)
	}
	for _, p := range cfg.Policies {
		patterns = append(patterns, p.Pattern)
	}
	for _, h := range cfg.Hosts {
		patterns = append(patterns, h.ID)
	}
	if len(cfg.Fallback) > 0 && cfg.Filter.GeoIP != nil && *cfg.Filter.GeoIP {
		code := cfg.Filter.Code
		if code == "" {
			code = "cn"
		}
		if cfg.Filter.GeoIPSet != "" {
			patterns = append(patterns, "rule-set:"+cfg.Filter.GeoIPSet)
		} else {
			patterns = append(patterns, "geoip:"+strings.ToLower(code))
		}
	}
	for _, pattern := range patterns {
		if matchers[pattern] != nil {
			continue
		}
		kind := router.KindDomainPattern
		value := pattern
		if strings.HasPrefix(pattern, "rule-set:") {
			kind = router.KindRuleSet
			value = strings.TrimPrefix(pattern, "rule-set:")
		}
		if strings.HasPrefix(pattern, "geoip:") || strings.HasPrefix(pattern, "geosite:") {
			behavior, code, _ := strings.Cut(pattern, ":")
			value = ""
			for _, def := range c.profile.RuleSets {
				if def.Behavior == behavior && strings.EqualFold(def.Code, code) {
					if value != "" {
						c.errorf(model.DocProfile, "/dns", "dns.geo", "ambiguous geodata selector")
						return
					}
					value = def.ID
				}
			}
			if value == "" {
				value = pattern
			}
			kind = router.KindRuleSet
		}
		spec := router.RuleSpec{Kind: kind, Values: []string{value}, Target: "yes"}
		if kind == router.KindRuleSet {
			ref, err := rc.resource(value, 0)
			if err != nil {
				c.errorf(model.DocProfile, "/dns", "dns.reference", "%s", err)
				continue
			}
			spec.Set = ref.set
			spec.ResourceHash = ref.hash
		}
		set, err := router.CompileRules([]router.RuleSpec{spec})
		if err != nil {
			c.errorf(model.DocProfile, "/dns", "dns.pattern", "%s", err)
			continue
		}
		r, err := router.New(set, router.Options{Outbounds: []string{"yes", "no"}, Final: "no"})
		if err != nil {
			c.errorf(model.DocProfile, "/dns", "dns.pattern", "%s", err)
			continue
		}
		matchers[pattern] = r
	}
	targets := map[string]bool{}
	for _, o := range eff.Outbounds {
		targets[o.ID] = true
	}
	for _, g := range eff.Groups {
		targets[g.ID] = true
	}
	lists := [][]string{cfg.Nameservers, cfg.Bootstrap, cfg.Proxy, cfg.Direct, cfg.Fallback}
	for _, p := range cfg.Policies {
		lists = append(lists, p.Servers)
	}
	for _, list := range lists {
		for _, v := range list {
			ep, err := RD.ParseEndpoint(v)
			if err == nil && ep.Scheme == "dhcp" && !platform.DHCPDNSSupported() {
				c.errorf(model.DocProfile, "/dns", "dns.dhcp", "DHCP DNS is unavailable on this platform")
			}
			if err == nil && ep.Via != "" && !targets[ep.Via] {
				c.errorf(model.DocProfile, "/dns", "dns.target", "unknown DNS outbound %q", ep.Via)
			}
		}
	}
	if cfg.Mode == "fake-ip" {
		for _, text := range []string{cfg.FakeRange, cfg.FakeRange6} {
			if text == "" {
				continue
			}
			p, _ := netip.ParsePrefix(text)
			for _, o := range eff.Outbounds {
				a, err := netip.ParseAddr(o.Server)
				if err == nil && p.Contains(a) {
					c.errorf(model.DocProfile, "/dns", "dns.cycle", "node address overlaps fake-IP range")
				}
			}
		}
	}
	eff.DNS = cfg
	eff.DNSMatches = matchers
	eff.DNSFingerprint = eff.dnsFingerprint()
}

func (e *Effective) dnsFingerprint() string {
	hashes := map[string]string{}
	for name, r := range e.DNSMatches {
		hashes[name] = fingerprint(r.Rules().Rule(0))
	}
	return fingerprint(struct {
		Config  *RD.Config
		Matches map[string]string
	}{e.DNS, hashes})
}
