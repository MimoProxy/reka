package importer

import "strings"

func (c *converter) convertDialer(r *proxyReader, out object, allowed map[string]bool) {
	if out["type"] == "reject" {
		return
	}
	allowed["smux"] = true
	dialer := object{}
	for _, key := range []string{"interface-name", "routing-mark", "ip-version", "tfo", "mptcp", "dialer-proxy"} {
		allowed[key] = true
		if get(r.n, key) == nil {
			continue
		}
		switch key {
		case "dialer-proxy":
			name := r.str(key)
			if name == "" {
				continue
			}
			target, ok := c.names[name]
			switch name {
			case "DIRECT", "COMPATIBLE":
				target, ok = "direct", true
			case "REJECT":
				target, ok = "reject", true
			case "PASS":
				target, ok = "pass", true
			case "REJECT-DROP":
				target, ok = "reject-drop", true
			}
			if !ok {
				r.fail(key, "import.dialer-proxy", "unknown dialer target")
			} else {
				dialer["proxy"] = target
			}
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
