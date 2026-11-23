package compile

import (
	"strings"
	"unsafe"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

type RuleMemoryEstimate struct {
	Bytes        uint64
	LargestBytes uint64
	Name         string
	Path         string
}

func (m *RuleMemoryEstimate) contributor(name, path string, bytes uint64) {
	if bytes > m.LargestBytes || bytes == m.LargestBytes && (path < m.Path || path == m.Path && name < m.Name) {
		m.LargestBytes, m.Name, m.Path = bytes, name, path
	}
}

func (m *RuleMemoryEstimate) addRouter(r *router.Router, path, name string) {
	if r == nil {
		return
	}
	rules := r.Rules()
	estimate := rules.EstimateMemory()
	m.Bytes += estimate.Bytes
	if estimate.LargestRule < 0 {
		return
	}
	if path == "/rules" {
		id := seg(rules.Rule(estimate.LargestRule).ID, estimate.LargestRule)
		path = model.JoinPath(path, id)
		name = "Rule " + id
	}
	m.contributor(name, path, estimate.LargestRuleBytes)
}

func (c *compiler) estimateRuleMemory(eff *Effective) RuleMemoryEstimate {
	var m RuleMemoryEstimate
	m.Bytes = uint64(cap(eff.Rules))*uint64(unsafe.Sizeof(router.RuleSpec{})) + uint64(cap(eff.RuleIDs))*uint64(unsafe.Sizeof(""))
	m.addRouter(eff.Router, "/rules", "Routing rules")
	if eff.ActiveRouter != eff.Router {
		m.addRouter(eff.ActiveRouter, "/routing/mode", "Routing mode")
	}
	m.addRouter(eff.SniffRules, "/sniff/rules", "Sniff rule")
	m.addRouter(eff.SniffSkipDomains, "/sniff/skip-domains", "Sniff skip domains")
	for name, r := range eff.DNSMatches {
		m.addRouter(r, "/dns", "DNS pattern "+name)
	}
	if rc := c.ruleResources; rc != nil {
		// Includes unused definitions, which are compiled during startup.
		// DNS and routing references share these same compiled sets.
		for id, entry := range rc.done {
			def := rc.defs[id]
			name, path := "Rule set "+id, model.JoinPath("/rule-sets", id)
			switch def.Behavior {
			case "geosite", "geoip", "asn":
				name = def.Behavior + ":" + def.Code
				if strings.HasPrefix(id, def.Behavior+":") {
					path = model.JoinPath("/geodata", def.Behavior)
				}
			}
			bytes := entry.set.EstimateMemory().Bytes
			m.Bytes += bytes
			m.contributor(name, path, bytes)
		}
	}
	return m
}
