package importer

import "strings"

func (c *converter) convertDialer(r *proxyReader, out object, allowed map[string]bool) {
	if out["type"] == "reject" {
		return
	}
	dialer := object{}
	for _, key := range []string{"interface-name", "routing-mark", "ip-version", "tfo", "mptcp"} {
		allowed[key] = true
		if get(r.n, key) == nil {
			continue
		}
		switch key {
		case "tfo", "mptcp":
			dialer[key] = r.boolean(key, false)
		case "routing-mark":
			dialer[key] = r.number(key, 0)
		case "ip-version":
			dialer[key] = strings.ToLower(r.str(key))
		default:
			dialer[key] = r.str(key)
		}
	}
	if len(dialer) > 0 {
		out["dialer"] = dialer
	}
}
