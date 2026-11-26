package compile

import (
	"net/url"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

const (
	tailscaleLinkPath          = "/link/tailscale"
	tailscaleAddressRulePrefix = "@link-tailscale-addresses-"
	tailscaleRouteRulePrefix   = "@link-tailscale-routes-"
	maxTailscaleRoutes         = 64
)

// Tailscale contains the local node identity and its current routing preferences.
type Tailscale struct {
	TailscaleIdentity
	AcceptRoutes           bool
	ExitNode               string
	ExitNodeAllowLANAccess bool
}

// TailscaleIdentity holds the settings that require a new node when changed.
type TailscaleIdentity struct {
	ID         string
	ControlURL string
	AuthKey    string `json:"-"`
	Hostname   string
	Ephemeral  bool
}

func (c *compiler) tailscaleLink(eff *Effective) []router.RuleSpec {
	if c.local.Link == nil || len(c.local.Link.Tailscale) == 0 {
		return nil
	}
	const doc = model.DocLocal
	if len(c.local.Link.Tailscale) > 1 {
		c.errorf(doc, tailscaleLinkPath, "link.tailscale.limit", "at most one Tailscale link is allowed")
		return nil
	}
	entry := c.local.Link.Tailscale[0]
	base := model.JoinPath(tailscaleLinkPath, seg(entry.ID, 0))
	if !hasKey(c.lpos, base) {
		base = model.JoinPath(tailscaleLinkPath, seg("", 0))
	}
	if entry.ID == "" {
		c.errorf(doc, base, "schema.id", "id is required")
		return nil
	}
	if !idRE.MatchString(entry.ID) {
		c.errorf(doc, base+"/id", "schema.id", "id %q must start with a letter or digit and contain only letters, digits, '.', '_' and '-' (at most 64)", entry.ID)
		return nil
	}
	if entry.ControlURL != "" {
		u, err := url.Parse(entry.ControlURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			c.errorf(doc, base+"/control-url", "link.tailscale.control-url", "expected an HTTPS control URL")
		}
	}
	// Link credentials are reserved everywhere else, so a subscription cannot
	// send a stored auth key to its own server.
	authKey := c.resolveLinkSecret(doc, base+"/auth-key", entry.AuthKey)
	var routes []string
	if len(entry.Routes) > maxTailscaleRoutes {
		c.errorf(doc, base+"/routes", "link.tailscale.routes", "at most %d Tailscale link routes are allowed", maxTailscaleRoutes)
	} else {
		routes = c.localLinkRoutes(base, "link.tailscale.routes", "Tailscale", entry.Routes, true)
	}

	id := "tailscale/" + entry.ID
	// Source imports use the same scoped ID syntax. Existing targets keep
	// their identity, so a local link cannot claim an imported outbound ID.
	if _, exists := eff.Outbound(id); exists {
		c.errorf(doc, base+"/id", "schema.duplicate-id", "id %q is already used by an outbound", id)
		return nil
	}
	out := Outbound{ID: id, Type: model.OutboundTailscale, UDP: true, Tailscale: &Tailscale{
		TailscaleIdentity: TailscaleIdentity{
			ID: entry.ID, ControlURL: entry.ControlURL, AuthKey: authKey,
			Hostname: entry.Hostname, Ephemeral: entry.Ephemeral,
		},
		AcceptRoutes:           entry.AcceptRoutes == nil || *entry.AcceptRoutes,
		ExitNode:               entry.ExitNode,
		ExitNodeAllowLANAccess: entry.ExitNodeAllowLANAccess,
	}}
	out.Fingerprint = outboundFingerprint(out)
	// Each reference and any detours using it must follow a change of node
	// identity. Live preference changes keep the same outbound handles.
	for i := range eff.Outbounds {
		ref := &eff.Outbounds[i]
		if ref.Type == model.OutboundTailscale {
			ref.Fingerprint = fingerprint(ref.Fingerprint, out.Fingerprint)
		}
	}
	eff.Outbounds = append(eff.Outbounds, out)
	pos := c.lpos[base]
	eff.setOrigin(model.JoinPath("/outbounds", id), Origin{
		Layer: LayerLocal, Document: doc, Path: base, Line: pos.Line, Column: pos.Column,
	})

	rules := []router.RuleSpec{c.localLinkRule(eff, base, tailscaleAddressRulePrefix+entry.ID, id,
		[]string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"})}
	if len(routes) != 0 {
		rules = append(rules, c.localLinkRule(eff, base, tailscaleRouteRulePrefix+entry.ID, id, routes))
	}
	return rules
}
