package importer

import (
	"go.yaml.in/yaml/v3"
	"slices"
	"strings"
)

func (c *converter) convertTLSCarrier(r *proxyReader, key string, out object) {
	node := deref(get(r.n, key))
	if node == nil {
		return
	}
	p := proxyReader{c: c, n: node, path: r.path + "/" + key}
	if node.Kind != yaml.MappingNode {
		p.fail("", "import.tls-carrier", "security options must be a mapping")
		r.bad = true
		return
	}
	fields := map[string][]string{"shadow-tls-opts": {"password", "version"}, "restls-opts": {"password", "version-hint", "restls-script"}, "jls-opts": {"username", "password"}}
	for i := 0; i+1 < len(node.Content); i += 2 {
		field := node.Content[i].Value
		if !slices.Contains(fields[key], field) {
			p.fail(field, "import.tls-carrier", "unknown security carrier option")
		}
	}
	carrier := object{"type": strings.TrimSuffix(key, "-opts"), "password": p.str("password")}
	active := false
	switch key {
	case "shadow-tls-opts":
		version := p.number("version", 0)
		carrier["version"] = version
		active = version != 0 || p.str("password") != ""
	case "restls-opts":
		carrier["version-hint"], carrier["script"] = p.str("version-hint"), p.str("restls-script")
		active = p.str("password") != "" || p.str("version-hint") != "" || p.str("restls-script") != ""
	case "jls-opts":
		carrier["username"] = p.str("username")
		active = p.str("username") != "" || p.str("password") != ""
	}
	r.bad = r.bad || p.bad
	if !active {
		return
	}
	tls, ok := out["tls"].(object)
	if !ok {
		r.fail(key, "import.tls-carrier", "security carrier requires TLS")
		return
	}
	if tls["carrier"] != nil || tls["reality"] != nil {
		r.fail(key, "import.tls-carrier", "security modes are mutually exclusive")
		return
	}
	if tls["ech"] != nil {
		delete(tls, "ech")
		c.diag(node, p.path, "import.ignored-field", "ECH is inactive with this security carrier in the reference", false)
	}
	if key == "jls-opts" {
		for _, field := range []string{"insecure", "certificate-sha256", "verify-name", "certificate", "private-key"} {
			if tls[field] != nil {
				delete(tls, field)
				c.diag(node, p.path, "import.ignored-field", "JLS authenticates credentials rather than ordinary certificate options", false)
			}
		}
	}
	tls["carrier"] = carrier
}
