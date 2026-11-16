package importer

import (
	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

func (c *converter) convertMultiplex(r *proxyReader, out object) {
	n := get(r.n, "smux")
	if empty(n) {
		return
	}
	if n.Kind != yaml.MappingNode {
		r.fail("smux", "import.multiplex", "smux must be a mapping")
		return
	}
	br := proxyReader{c: c, n: n, path: r.path + "/smux"}
	m := object{"enabled": br.boolean("enabled", false)}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i].Value
		switch key {
		case "enabled":
		case "protocol":
			m[key] = br.str(key)
		case "max-connections", "min-streams", "max-streams":
			m[key] = br.number(key, 0)
		case "padding", "only-tcp", "statistic":
			m[key] = br.boolean(key, false)
		case "brutal-opts":
			value := get(n, key)
			if value.Kind != yaml.MappingNode {
				br.fail(key, "import.multiplex", "brutal-opts must be a mapping")
				continue
			}
			reader := proxyReader{c: c, n: value, path: br.path + "/brutal-opts"}
			for j := 0; j+1 < len(value.Content); j += 2 {
				if k := value.Content[j].Value; k != "enabled" && k != "up" && k != "down" {
					reader.fail(k, "import.multiplex", "unknown Brutal option")
				}
			}
			up, err := model.BandwidthBytes(reader.str("up"))
			if err != nil {
				reader.fail("up", "import.multiplex", err.Error())
			}
			down, err := model.BandwidthBytes(reader.str("down"))
			if err != nil {
				reader.fail("down", "import.multiplex", err.Error())
			}
			m["brutal"] = object{"enabled": reader.boolean("enabled", false), "up-bps": up, "down-bps": down}
			br.bad = br.bad || reader.bad
		default:
			br.fail(key, "import.multiplex", "unsupported multiplex option")
		}
	}
	if m["statistic"] == true {
		c.diag(get(n, "statistic"), br.path+"/statistic", "import.multiplex-statistic", "Reka always reports native per-flow traffic; reference nested accounting is retained as metadata", false)
	}
	r.bad = r.bad || br.bad
	out["multiplex"] = m
}
