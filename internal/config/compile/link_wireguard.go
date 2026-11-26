package compile

import (
	"slices"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

const (
	wireGuardLinkPath = "/link/wireguard"
	maxWireGuardLinks = 64

	// A leading @ rejects this ID in native rules. Scoped rule IDs always contain a slash.
	wireGuardLinkRulePrefix = "@link-wireguard-"
)

func (c *compiler) wireGuardLinkRules(eff *Effective) []router.RuleSpec {
	if c.local.Link == nil {
		return nil
	}
	entries := c.local.Link.WireGuard
	if len(entries) > maxWireGuardLinks {
		c.errorf(model.DocLocal, wireGuardLinkPath, "link.wireguard.limit", "at most %d WireGuard links are allowed", maxWireGuardLinks)
		return nil
	}
	seen := make(map[string]bool, len(entries))
	var rules []router.RuleSpec
	for i, entry := range entries {
		base := model.JoinPath(wireGuardLinkPath, seg("", i))
		targetPath := base + "/outbound"
		if strings.TrimSpace(entry.Outbound) == "" {
			if !hasKey(c.lpos, targetPath) {
				targetPath = base
			}
			c.errorf(model.DocLocal, targetPath, "link.wireguard.outbound", "outbound is required")
			continue
		}
		if seen[entry.Outbound] {
			c.errorf(model.DocLocal, targetPath, "link.wireguard.duplicate", "duplicate WireGuard link for outbound %q", entry.Outbound)
			continue
		}
		seen[entry.Outbound] = true

		out, exists := eff.Outbound(entry.Outbound)
		isWireGuard := exists && out.Type == model.OutboundWireGuard
		switch {
		case !exists && !slices.ContainsFunc(eff.Groups, func(g router.Group) bool { return g.ID == entry.Outbound }):
			c.warnf(model.DocLocal, targetPath, "link.wireguard.outbound", "WireGuard outbound %q is missing and this link was skipped", entry.Outbound)
		case !isWireGuard:
			c.errorf(model.DocLocal, targetPath, "link.wireguard.type", "outbound %q must be a WireGuard outbound", entry.Outbound)
		}
		routes := entry.Routes
		explicit := hasKey(c.lpos, base+"/routes")
		if !explicit && isWireGuard {
			routes = out.Protocol.AllowedIPs
		}
		values := c.localLinkRoutes(base, "link.wireguard.routes", "WireGuard", routes, explicit)
		if !isWireGuard || len(values) == 0 {
			continue
		}
		id := wireGuardLinkRulePrefix + strconv.Itoa(i)
		rules = append(rules, c.localLinkRule(eff, base, id, out.ID, values))
	}
	return rules
}
