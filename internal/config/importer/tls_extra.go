package importer

import (
	"strings"

	"go.yaml.in/yaml/v3"
)

func tlsExtraKeys(typ string) []string {
	switch typ {
	case "http", "socks5", "vless", "vmess", "trojan", "hysteria2", "hy2", "tuic":
		return []string{"fingerprint", "name-cert-verify", "certificate", "private-key", "ech-opts"}
	}
	return nil
}
func permitTLSExtras(typ string, allowed map[string]bool) {
	for _, key := range tlsExtraKeys(typ) {
		allowed[key] = true
	}
}
func (c *converter) convertTLSExtras(r *proxyReader, typ string, out object) {
	for _, key := range tlsExtraKeys(typ) {
		if get(r.n, key) == nil {
			continue
		}
		if key == "ech-opts" {
			n := get(r.n, key)
			opts := proxyReader{c: c, n: n, path: r.path + "/ech-opts"}
			known := map[string]bool{"enable": true, "config": true, "query-server-name": true}
			if n.Kind != yaml.MappingNode {
				r.fail(key, "import.ech", "ECH options must be a mapping")
				continue
			}
			for i := 0; i+1 < len(n.Content); i += 2 {
				if !known[n.Content[i].Value] {
					opts.fail(n.Content[i].Value, "import.ech", "unknown ECH option")
				}
			}
			enabled := opts.boolean("enable", false)
			config, query := opts.str("config"), opts.str("query-server-name")
			if opts.bad {
				r.bad = true
				continue
			}
			if !enabled {
				continue
			}
			tls, ok := out["tls"].(object)
			if !ok {
				r.fail(key, "import.ech", "ECH requires TLS")
				continue
			}
			tls["ech"] = object{"enabled": true, "config": config, "query-server-name": query}
			continue
		}
		value := r.str(key)
		if value == "" {
			continue
		}
		if key == "certificate" || key == "private-key" {
			if !strings.Contains(value, "-----BEGIN ") && !strings.HasPrefix(value, "secret://") {
				contents, ok := c.req.CertificateFiles[value]
				if !ok || contents == "" {
					r.fail(key, "import.certificate-file", "certificate file requires an explicit caller-supplied attachment")
					continue
				}
				value = contents
			}
		}
		tls, ok := out["tls"].(object)
		if !ok {
			r.fail(key, "import.tls", "certificate options require TLS")
			continue
		}
		native := key
		switch key {
		case "fingerprint":
			native = "certificate-sha256"
		case "name-cert-verify":
			native = "verify-name"
		}
		tls[native] = value
	}
}
