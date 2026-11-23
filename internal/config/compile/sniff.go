package compile

import (
	"fmt"
	"slices"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

func (c *compiler) sniff(eff *Effective) {
	value, doc, positions := c.profile.Sniff, model.DocProfile, c.ppos
	if c.local.Sniff != nil || hasKey(c.lpos, "/sniff") {
		c.override(eff, "/sniff")
		value, doc, positions = c.local.Sniff, model.DocLocal, c.lpos
	}
	var v model.Sniff
	if value != nil {
		v = *value
	} else if hasKey(positions, "/sniff") {
		return // An explicit null disables sniffing.
	}
	if !hasKey(positions, "/sniff/enabled") {
		v.Enabled = true
		eff.SniffForRouting = len(v.Rules) == 0 && !v.OverrideDestination
		eff.setOrigin("/sniff/enabled", Origin{Layer: LayerDefault})
	}
	v.Protocols = slices.Clone(v.Protocols)
	if len(v.Protocols) == 0 {
		v.Protocols = []string{"http", "tls", "quic"}
	}
	c.sniffProtocols(doc, "/sniff/protocols", v.Protocols)
	if v.TimeoutMS == 0 {
		v.TimeoutMS = 300
	}
	if v.MaxBytes == 0 {
		v.MaxBytes = 65536
	}
	if v.MaxPackets == 0 {
		v.MaxPackets = 8
	}
	for _, limit := range []struct {
		name            string
		value, min, max int
	}{
		{"timeout-ms", v.TimeoutMS, 10, 2000},
		{"max-bytes", v.MaxBytes, 512, 262144},
		{"max-packets", v.MaxPackets, 1, 32},
	} {
		if limit.value < limit.min || limit.value > limit.max {
			c.errorf(doc, "/sniff/"+limit.name, "sniff.budget", "%s must be between %d and %d", limit.name, limit.min, limit.max)
		}
	}
	eff.Sniff = v
	if len(v.Rules) > 128 || len(v.SkipDomains) > 256 {
		c.errorf(doc, "/sniff", "sniff.limit", "at most 128 sniff rules and 256 excluded domains are allowed")
		return
	}
	var specs []router.RuleSpec
	for i, rule := range v.Rules {
		path := fmt.Sprintf("/sniff/rules/#%d", i)
		if rule.Action != "sniff" && rule.Action != "skip" {
			c.errorf(doc, path+"/action", "sniff.action", "action must be sniff or skip")
		}
		if rule.Action == "skip" && (len(rule.Protocols) != 0 || rule.OverrideDestination != nil) {
			c.errorf(doc, path, "sniff.action", "protocols and override-destination require action: sniff")
		}
		c.sniffProtocols(doc, path+"/protocols", rule.Protocols)
		spec, err := sniffCondition(rule.Match)
		if err != nil {
			c.errorf(doc, path+"/match", "sniff.match", "%v", err)
			continue
		}
		spec.Target = "yes"
		if _, err := router.CompileRules([]router.RuleSpec{spec}); err != nil {
			c.errorf(doc, path+"/match", "sniff.match", "%v", err)
		}
		specs = append(specs, spec)
	}
	if len(specs) > 0 {
		eff.SniffRules = c.sniffMatcher(doc, "/sniff/rules", specs)
	}
	if len(v.SkipDomains) > 0 {
		eff.SniffSkipDomains = c.sniffMatcher(doc, "/sniff/skip-domains", []router.RuleSpec{{
			Kind: router.KindDomainPattern, Values: v.SkipDomains, Target: "yes",
		}})
	}
}

func (c *compiler) sniffProtocols(doc, path string, protocols []string) {
	seen := map[string]bool{}
	for i, protocol := range protocols {
		if !slices.Contains([]string{"http", "tls", "quic"}, protocol) || seen[protocol] {
			c.errorf(doc, fmt.Sprintf("%s/#%d", path, i), "sniff.protocol", "sniff protocols must be unique http, tls or quic values")
		}
		seen[protocol] = true
	}
}

func sniffCondition(m model.Match) (router.RuleSpec, error) {
	kind, _ := router.ParseKind(m.Kind)
	switch kind {
	case router.KindMatch, router.KindAnd, router.KindOr, router.KindNot,
		router.KindNetwork, router.KindNetworkScene, router.KindDstPort, router.KindSrcPort,
		router.KindInboundName, router.KindInboundType, router.KindInboundPort, router.KindInboundUser,
		router.KindIPCIDR, router.KindSrcIPCIDR, router.KindDomain, router.KindDomainSuffix, router.KindDomainPattern:
	default:
		return router.RuleSpec{}, fmt.Errorf("condition %q is unavailable before sniffing", m.Kind)
	}
	spec := router.RuleSpec{Kind: kind, Values: m.Values, NoResolve: kind == router.KindIPCIDR}
	for _, child := range m.Children {
		s, err := sniffCondition(child)
		if err != nil {
			return router.RuleSpec{}, err
		}
		spec.Children = append(spec.Children, s)
	}
	return spec, nil
}

func (c *compiler) sniffMatcher(doc, path string, specs []router.RuleSpec) *router.Router {
	rules, err := router.CompileRules(specs)
	if err == nil {
		var r *router.Router
		r, err = router.New(rules, router.Options{Outbounds: []string{"yes", "no"}, Final: "no"})
		if err == nil {
			return r
		}
	}
	c.errorf(doc, path, "sniff.match", "%v", err)
	return nil
}
