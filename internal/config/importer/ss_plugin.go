package importer

import "go.yaml.in/yaml/v3"

func (c *converter) convertSSPlugin(parent *proxyReader, out object) {
	kind := parent.str("plugin")
	n := get(parent.n, "plugin-opts")
	if kind == "" {
		if !empty(n) {
			parent.fail("plugin-opts", "import.plugin", "plugin-opts requires a plugin")
		}
		if parent.str("client-fingerprint") != "" {
			c.diag(get(parent.n, "client-fingerprint"), parent.path+"/client-fingerprint", "import.ignored-field", "ClientHello preset has no meaning without a TLS plugin", false)
		}
		return
	}
	if n == nil {
		n = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}
	if n.Kind != yaml.MappingNode {
		parent.fail("plugin-opts", "import.plugin", "plugin-opts must be a mapping")
		return
	}
	r := proxyReader{c: c, n: n, path: parent.path + "/plugin-opts"}
	fields := map[string][]string{
		"obfs":         {"mode", "host"},
		"v2ray-plugin": {"mode", "host", "path", "tls", "ech-opts", "fingerprint", "certificate", "private-key", "headers", "skip-cert-verify", "name-cert-verify", "mux", "v2ray-http-upgrade", "v2ray-http-upgrade-fast-open"},
		"gost-plugin":  {"mode", "host", "path", "tls", "ech-opts", "fingerprint", "certificate", "private-key", "headers", "skip-cert-verify", "name-cert-verify", "mux"},
		"shadow-tls":   {"version", "password", "host", "fingerprint", "certificate", "private-key", "skip-cert-verify", "name-cert-verify", "alpn"},
	}
	known, ok := fields[kind]
	if !ok {
		parent.fail("plugin", "import.plugin", "plugin is not implemented by this build")
		return
	}
	allowed := map[string]bool{}
	for _, key := range known {
		allowed[key] = true
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if !allowed[n.Content[i].Value] {
			r.fail(n.Content[i].Value, "import.plugin", "unknown plugin option")
		}
	}
	p := object{"type": kind, "host": r.str("host")}
	switch kind {
	case "obfs":
		p["mode"] = r.str("mode")
	case "v2ray-plugin", "gost-plugin":
		p["mode"], p["path"], p["mux"] = r.str("mode"), r.str("path"), r.boolean("mux", true)
		if kind == "v2ray-plugin" {
			p["http-upgrade"], p["fast-open"] = r.boolean("v2ray-http-upgrade", false), r.boolean("v2ray-http-upgrade-fast-open", false)
		}
		if h := get(n, "headers"); h != nil {
			if h.Kind != yaml.MappingNode {
				r.fail("headers", "import.plugin", "headers must be a mapping")
			} else {
				headers := []object{}
				for i := 0; i+1 < len(h.Content); i += 2 {
					if h.Content[i+1].Kind != yaml.ScalarNode {
						r.fail("headers", "import.plugin", "header values must be scalar strings")
						continue
					}
					headers = append(headers, object{"name": h.Content[i].Value, "value": h.Content[i+1].Value})
				}
				p["headers"] = headers
			}
		}
	case "shadow-tls":
		p["version"], p["password"] = r.number("version", 2), r.str("password")
	}
	tlsEnabled := kind == "shadow-tls" || r.boolean("tls", false)
	if tlsEnabled {
		tls := object{"server-name": r.str("host"), "insecure": r.boolean("skip-cert-verify", false)}
		if kind == "shadow-tls" {
			tls["fingerprint"] = parent.str("client-fingerprint")
			if alpn := get(n, "alpn"); alpn != nil {
				var values []string
				if err := alpn.Decode(&values); err != nil {
					r.fail("alpn", "import.plugin", "ALPN must be a string list")
				} else {
					tls["alpn"] = values
				}
			}
		}
		wrapper := object{"tls": tls}
		c.convertTLSExtras(&r, "http", wrapper)
		p["tls"] = tls
	} else {
		for _, key := range []string{"ech-opts", "fingerprint", "certificate", "private-key", "skip-cert-verify", "name-cert-verify"} {
			if !empty(get(n, key)) {
				c.diag(get(n, key), r.path+"/"+key, "import.ignored-field", "TLS option is inactive because plugin TLS is disabled", false)
			}
		}
	}
	if kind != "shadow-tls" && parent.str("client-fingerprint") != "" {
		c.diag(get(parent.n, "client-fingerprint"), parent.path+"/client-fingerprint", "import.ignored-field", "the reference only uses this preset for ShadowTLS, Restls and JLS", false)
	}
	parent.bad = parent.bad || r.bad
	out["plugin"] = p
}
