package compile

import (
	"slices"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

func (c *compiler) routing(eff *Effective) {
	value, doc := c.profile.Routing, model.DocProfile
	if c.local.Routing != nil || hasKey(c.lpos, "/routing") {
		c.override(eff, "/routing")
		value, doc = c.local.Routing, model.DocLocal
	}
	if value != nil {
		eff.Routing = *value
	}
	if eff.Routing.Mode == "" {
		eff.Routing.Mode = "rule"
	}
	if eff.Routing.BlockQUIC == "" {
		eff.Routing.BlockQUIC = "off"
	}
	if !slices.Contains([]string{"rule", "global", "direct"}, eff.Routing.Mode) {
		c.errorf(doc, "/routing/mode", "routing.mode", "routing mode must be rule, global or direct")
	}
	if !slices.Contains([]string{"off", "proxy", "all"}, eff.Routing.BlockQUIC) {
		c.errorf(doc, "/routing/block-quic", "routing.block-quic", "block-quic must be off, proxy or all")
	}
	if eff.Routing.Mode == "global" && eff.Routing.Global == "" {
		c.errorf(doc, "/routing/global", "routing.target", "global mode requires an explicit outbound or group ID")
	}
	if target := eff.Routing.Global; target != "" {
		found := false
		for _, o := range eff.Outbounds {
			found = found || o.ID == target
		}
		for _, g := range eff.Groups {
			found = found || g.ID == target
		}
		if !found {
			c.errorf(doc, "/routing/global", "routing.target", "unknown global outbound or group ID")
		}
	}
}

func (e *Effective) RoutingRouter() *router.Router {
	if e.ActiveRouter != nil {
		return e.ActiveRouter
	}
	return e.Router
}
