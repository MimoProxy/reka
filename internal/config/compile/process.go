package compile

import "github.com/MimoProxy/reka/internal/config/model"

func (c *compiler) process(eff *Effective) {
	value, doc := c.profile.Process, model.DocProfile
	if c.local.Process != nil || hasKey(c.lpos, "/process") {
		c.override(eff, "/process")
		value, doc = c.local.Process, model.DocLocal
	}
	eff.Process.Mode = "rule"
	if value != nil && value.Mode != "" {
		eff.Process = *value
	}
	switch eff.Process.Mode {
	case "off", "rule", "always":
	default:
		c.errorf(doc, "/process/mode", "process.mode", "process mode must be off, rule or always")
	}
}
