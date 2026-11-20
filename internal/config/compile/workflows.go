package compile

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
)

type NetworkScene struct {
	ID        string         `json:"id"`
	Interface string         `json:"interface,omitempty"`
	CIDRs     []netip.Prefix `json:"ip-cidr,omitempty"`
}

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
