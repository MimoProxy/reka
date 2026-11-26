package compile

import (
	"maps"
	"net/netip"
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

var excludedWireGuardRoutes = [...]netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("ff00::/8"),
}

func (c *compiler) wireGuardLinkRules(eff *Effective) []router.RuleSpec {
	if c.local.Link == nil {
		return nil
	}
	c.override(eff, "/link")
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
		values := c.wireGuardLinkRoutes(base, routes, explicit)
		if !isWireGuard || len(values) == 0 {
			continue
		}
		id := wireGuardLinkRulePrefix + strconv.Itoa(i)
		rules = append(rules, router.RuleSpec{ID: id, Kind: router.KindIPCIDR, Values: values, NoResolve: true, Target: out.ID})
		pos := c.lpos[base]
		eff.setOrigin(model.JoinPath("/rules", id), Origin{
			Layer: LayerLocal, Document: model.DocLocal, Path: base, Line: pos.Line, Column: pos.Column,
		})
	}
	return rules
}

func (c *compiler) wireGuardLinkRoutes(base string, routes []string, explicit bool) []string {
	values := make([]string, 0, len(routes))
	for i, value := range routes {
		path := base
		if explicit {
			path = model.JoinPath(base, "routes", seg("", i))
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			c.errorf(model.DocLocal, path, "link.wireguard.routes", "expected an IPv4 or IPv6 CIDR")
			continue
		}
		prefix = prefix.Masked()
		if addr := prefix.Addr(); addr.Is4In6() {
			prefix = netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
		}
		switch {
		case prefix.Bits() == 0:
			if !explicit {
				c.errorf(model.DocLocal, path, "link.wireguard.routes", "WireGuard allowed-ips includes a default route; set routes explicitly")
				return nil
			}
			c.errorf(model.DocLocal, path, "link.wireguard.routes", "default routes are forbidden in WireGuard links")
		case slices.ContainsFunc(excludedWireGuardRoutes[:], prefix.Overlaps):
			c.errorf(model.DocLocal, path, "link.wireguard.routes", "WireGuard link routes must not overlap loopback, link-local or multicast networks")
		default:
			values = append(values, prefix.String())
		}
	}
	if len(values) != len(routes) {
		return nil
	}
	return values
}

// LocalRuleSource identifies a generated rule's origin even when full
// editor provenance was omitted during compilation.
func LocalRuleSource(id string) string {
	if index, ok := strings.CutPrefix(id, wireGuardLinkRulePrefix); ok {
		if _, err := strconv.ParseUint(index, 10, 6); err == nil {
			return "local.yaml " + wireGuardLinkPath + "/#" + index
		}
	}
	return ""
}

// DescribeRoutingRule renders a routing rule with its local source, if any.
func DescribeRoutingRule(spec router.RuleSpec) string {
	description := spec.String()
	if source := LocalRuleSource(spec.ID); source != "" {
		description += " (" + source + ")"
	}
	return description
}

func shiftAnonymousRuleOrigins(eff *Effective, offset int) {
	if offset == 0 || eff.Provenance == nil {
		return
	}
	shifted := make(map[string]Origin)
	for path, origin := range eff.Provenance {
		rest, ok := strings.CutPrefix(path, "/rules/#")
		if !ok {
			continue
		}
		index, _, _ := strings.Cut(rest, "/")
		i, err := strconv.Atoi(index)
		if err != nil {
			continue
		}
		if origin.Path == "" {
			origin.Document, origin.Path = model.DocProfile, path
		}
		shifted["/rules/"+seg("", i+offset)+rest[len(index):]] = origin
		delete(eff.Provenance, path)
	}
	maps.Copy(eff.Provenance, shifted)
}
