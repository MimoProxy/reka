package compile

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/config/model"
)

type NetworkScene struct {
	ID        string         `json:"id"`
	Interface string         `json:"interface,omitempty"`
	CIDRs     []netip.Prefix `json:"ip-cidr,omitempty"`
}

type TrafficBudget struct {
	Reserve     uint64    `json:"reserve-bytes"`
	ResetAt     time.Time `json:"reset-at,omitzero"`
	WarnPercent int       `json:"warn-remaining-percent"`
}

const DefaultBudgetWarning = 10

func (c *compiler) networkScenes(eff *Effective) {
	const path = "/network-scenes"
	if len(c.local.NetworkScenes) > 64 {
		c.errorf(model.DocLocal, path, "scene.limit", "at most 64 network scenes are allowed")
		return
	}
	c.override(eff, path)
	seen := map[string]bool{}
	for i, cfg := range c.local.NetworkScenes {
		base := model.JoinPath(path, seg(cfg.ID, i))
		if !idRE.MatchString(cfg.ID) || seen[cfg.ID] {
			c.errorf(model.DocLocal, base+"/id", "scene.id", "each scene must have a unique native ID")
			continue
		}
		seen[cfg.ID] = true
		if strings.TrimSpace(cfg.Interface) != cfg.Interface || len(cfg.Interface) > 256 || strings.ContainsAny(cfg.Interface, "\x00\r\n") {
			c.errorf(model.DocLocal, base+"/interface", "scene.interface", "invalid interface name")
		}
		if len(cfg.IPCIDR) > 32 {
			c.errorf(model.DocLocal, base+"/ip-cidr", "scene.limit", "at most 32 prefixes are allowed per scene")
			continue
		}
		scene := NetworkScene{ID: cfg.ID, Interface: cfg.Interface}
		for j, value := range cfg.IPCIDR {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				c.errorf(model.DocLocal, fmt.Sprintf("%s/ip-cidr/#%d", base, j), "scene.prefix", "expected an IPv4 or IPv6 prefix")
				continue
			}
			scene.CIDRs = append(scene.CIDRs, prefix.Masked())
		}
		eff.NetworkScenes = append(eff.NetworkScenes, scene)
	}
}

func (c *compiler) trafficBudgets(eff *Effective) {
	const path = "/traffic-budgets"
	if len(c.local.TrafficBudgets) > 128 {
		c.errorf(model.DocLocal, path, "budget.limit", "at most 128 traffic budgets are allowed")
		return
	}
	c.override(eff, path)
	if len(c.local.TrafficBudgets) == 0 {
		return
	}
	eff.TrafficBudgets = make(map[string]TrafficBudget, len(c.local.TrafficBudgets))
	for i, cfg := range c.local.TrafficBudgets {
		base := fmt.Sprintf("%s/#%d", path, i)
		if _, seen := eff.TrafficBudgets[cfg.Source]; !idRE.MatchString(cfg.Source) || seen {
			c.errorf(model.DocLocal, base+"/source", "budget.source", "each budget needs a unique subscription source ID")
			continue
		}
		budget := TrafficBudget{Reserve: cfg.Reserve, WarnPercent: DefaultBudgetWarning}
		if cfg.ResetAt != "" {
			at, err := time.Parse(time.RFC3339, cfg.ResetAt)
			if err != nil || at.Year() < 1970 || at.Year() > 9999 {
				c.errorf(model.DocLocal, base+"/reset-at", "budget.reset", "expected an RFC3339 time with a timezone")
			} else {
				budget.ResetAt = at.UTC()
			}
		}
		if cfg.WarnPercent != nil {
			budget.WarnPercent = *cfg.WarnPercent
			if budget.WarnPercent < 0 || budget.WarnPercent > 100 {
				c.errorf(model.DocLocal, base+"/warn-remaining-percent", "budget.warning", "warning percentage must be between 0 and 100")
			}
		}
		eff.TrafficBudgets[cfg.Source] = budget
	}
}
