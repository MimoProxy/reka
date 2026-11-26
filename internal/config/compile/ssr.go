package compile

import (
	"strings"

	"github.com/MimoProxy/reka/internal/compat/ssr"
	"github.com/MimoProxy/reka/internal/config/model"
)

func (c *compiler) ssr(base string, ob model.Outbound, out *Outbound) {
	if err := ssr.ValidateMethod(ob.Method); err != nil {
		c.errorf(model.DocProfile, base+"/method", "outbound.method", "%v", err)
	}
	out.Method = strings.ToLower(ob.Method)
	if out.Password == "" && !c.hasErrorAt(base+"/password") {
		c.errorf(model.DocProfile, base+"/password", "outbound.password", "password is required")
	}

	p := model.Protocol{}
	if ob.Protocol != nil {
		p = *ob.Protocol
	}
	path := base + "/protocol"
	if _, present := c.ppos[path+"/protocol"]; !present {
		p.SSRProtocol = "origin"
	} else if err := ssr.ValidateProtocol(p.SSRProtocol); err != nil {
		c.errorf(model.DocProfile, path+"/protocol", "outbound.protocol", "%v", err)
	}
	if p.Obfs == nil {
		p.Obfs = &model.Obfs{Type: "plain"}
	} else {
		for _, field := range c.present(path + "/obfs") {
			if field != "type" && field != "param" {
				c.errorf(model.DocProfile, path+"/obfs/"+field, "outbound.protocol", "option does not apply to SSR obfs")
			}
		}
		if err := ssr.ValidateObfs(p.Obfs.Type); err != nil {
			c.errorf(model.DocProfile, path+"/obfs/type", "outbound.protocol", "%v", err)
		}
	}
	p.SSRProtocolParam = c.resolveSecret(path+"/protocol-param", p.SSRProtocolParam)
	out.Protocol = &p
}
