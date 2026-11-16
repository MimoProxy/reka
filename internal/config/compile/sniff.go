package compile

import (
	"fmt"
	"slices"

	"github.com/MimoProxy/reka/internal/config/model"
)

func (c *compiler) sniff(eff *Effective) {
	value, doc := c.profile.Sniff, model.DocProfile
	if c.local.Sniff != nil || hasKey(c.lpos, "/sniff") {
		c.override(eff, "/sniff")
		value, doc = c.local.Sniff, model.DocLocal
	}
	if value == nil {
		return
	}
	v := *value
	v.Protocols = slices.Clone(v.Protocols)
	if len(v.Protocols) == 0 {
		v.Protocols = []string{"http", "tls", "quic"}
	}
	seen := map[string]bool{}
	for i, protocol := range v.Protocols {
		if !slices.Contains([]string{"http", "tls", "quic"}, protocol) || seen[protocol] {
			c.errorf(doc, fmt.Sprintf("/sniff/protocols/#%d", i), "sniff.protocol", "sniff protocols must be unique http, tls or quic values")
		}
		seen[protocol] = true
	}
	if v.TimeoutMS == 0 {
		v.TimeoutMS = 300
	}
	if v.MaxBytes == 0 {
		v.MaxBytes = 65536
	}
	if v.MaxPackets == 0 {
		v.MaxPackets = 8
	}
	for _, limit := range []struct {
		name            string
		value, min, max int
	}{
		{"timeout-ms", v.TimeoutMS, 10, 2000},
		{"max-bytes", v.MaxBytes, 512, 262144},
		{"max-packets", v.MaxPackets, 1, 32},
	} {
		if limit.value < limit.min || limit.value > limit.max {
			c.errorf(doc, "/sniff/"+limit.name, "sniff.budget", "%s must be between %d and %d", limit.name, limit.min, limit.max)
		}
	}
	eff.Sniff = v
}
