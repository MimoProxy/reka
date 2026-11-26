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

var excludedLocalLinkRoutes = [...]netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("ff00::/8"),
}

func (c *compiler) localLinkRoutes(base, code, name string, routes []string, explicit bool) []string {
	values := make([]string, 0, len(routes))
	for i, value := range routes {
		path := base
		if explicit {
			path = model.JoinPath(base, "routes", seg("", i))
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			c.errorf(model.DocLocal, path, code, "expected an IPv4 or IPv6 CIDR")
			continue
		}
		prefix = prefix.Masked()
		if addr := prefix.Addr(); addr.Is4In6() {
			prefix = netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
		}
		switch {
		case prefix.Bits() == 0:
			if !explicit {
				c.errorf(model.DocLocal, path, code, "%s allowed-ips includes a default route; set routes explicitly", name)
				return nil
			}
			c.errorf(model.DocLocal, path, code, "default routes are forbidden in %s links", name)
		case slices.ContainsFunc(excludedLocalLinkRoutes[:], prefix.Overlaps):
			c.errorf(model.DocLocal, path, code, "%s link routes must not overlap loopback, link-local or multicast networks", name)
		default:
			values = append(values, prefix.String())
		}
	}
	if len(values) != len(routes) {
		return nil
	}
	return values
}

func (c *compiler) localLinkRule(eff *Effective, base, id, target string, values []string) router.RuleSpec {
	pos := c.lpos[base]
	eff.setOrigin(model.JoinPath("/rules", id), Origin{
		Layer: LayerLocal, Document: model.DocLocal, Path: base, Line: pos.Line, Column: pos.Column,
	})
	return router.RuleSpec{ID: id, Kind: router.KindIPCIDR, Values: values, NoResolve: true, Target: target}
}

// LocalRuleSource identifies a generated rule's origin even when full
// editor provenance was omitted during compilation.
func LocalRuleSource(id string) string {
	if index, ok := strings.CutPrefix(id, wireGuardLinkRulePrefix); ok {
		if _, err := strconv.ParseUint(index, 10, 6); err == nil {
			return "local.yaml " + wireGuardLinkPath + "/#" + index
		}
	}
	for _, prefix := range []string{tailscaleAddressRulePrefix, tailscaleRouteRulePrefix} {
		if link, ok := strings.CutPrefix(id, prefix); ok && idRE.MatchString(link) {
			return "local.yaml " + model.JoinPath(tailscaleLinkPath, link)
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
