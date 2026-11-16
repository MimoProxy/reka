package importer

func tlsExtraKeys(typ string) []string {
	switch typ {
	case "http", "socks5", "vless", "vmess", "trojan", "hysteria2", "hy2", "tuic":
		return []string{"fingerprint", "name-cert-verify", "certificate", "private-key"}
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
		value := r.str(key)
		if value == "" {
			continue
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
