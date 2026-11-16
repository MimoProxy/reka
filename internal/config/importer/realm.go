package importer

import "go.yaml.in/yaml/v3"

func (c *converter) convertRealm(parent *proxyReader, n *yaml.Node, p object) {
	r := proxyReader{c: c, n: n, path: parent.path + "/realm-opts"}
	if n.Kind != yaml.MappingNode {
		parent.fail("realm-opts", "import.realm", "realm-opts must be a mapping")
		return
	}
	known := map[string]bool{}
	for _, key := range []string{"enable", "server-url", "token", "realm-id", "stun-servers", "sni", "skip-cert-verify", "name-cert-verify", "fingerprint", "certificate", "private-key", "alpn"} {
		known[key] = true
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if !known[n.Content[i].Value] {
			r.fail(n.Content[i].Value, "import.realm", "unknown realm option")
		}
	}
	out := object{"enabled": r.boolean("enable", false), "server-url": r.str("server-url"), "token": r.str("token"), "realm-id": r.str("realm-id")}
	if v := get(n, "stun-servers"); v != nil {
		var servers []string
		if err := v.Decode(&servers); err != nil {
			r.fail("stun-servers", "import.realm", "STUN servers must be a string list")
		} else {
			out["stun-servers"] = servers
		}
	}
	tls := object{"server-name": r.str("sni"), "insecure": r.boolean("skip-cert-verify", false)}
	if v := get(n, "alpn"); v != nil {
		var protocols []string
		if err := v.Decode(&protocols); err != nil {
			r.fail("alpn", "import.realm", "ALPN must be a string list")
		} else {
			tls["alpn"] = protocols
		}
	}
	wrapper := object{"tls": tls}
	c.convertTLSExtras(&r, "http", wrapper)
	out["tls"] = tls
	if out["enabled"] == true {
		p["realm"] = out
	} else {
		c.report.Ignored = append(c.report.Ignored, r.path)
	}
	parent.bad = parent.bad || r.bad
}
