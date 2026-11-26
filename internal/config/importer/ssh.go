package importer

import (
	"strings"

	"go.yaml.in/yaml/v3"
)

func (c *converter) convertSSH(r *proxyReader, out object) {
	allowed := map[string]bool{
		"name": true, "type": true, "server": true, "port": true, "udp": true,
		"username": true, "password": true, "private-key": true, "private-key-passphrase": true,
		"host-key": true, "host-key-algorithms": true,
	}
	c.convertDialer(r, out, allowed)
	for i := 0; i+1 < len(r.n.Content); i += 2 {
		key := r.n.Content[i].Value
		if !allowed[key] {
			r.fail(key, "import.unsupported-field", "unsupported SSH option")
		}
	}
	out["server"], out["port"] = r.str("server"), r.port()
	for _, key := range []string{"username", "password"} {
		if v := r.str(key); v != "" {
			out[key] = v
		}
	}
	if r.boolean("udp", false) {
		path := r.path + "/udp"
		c.report.Ignored = append(c.report.Ignored, path)
		c.diag(get(r.n, "udp"), path, "import.ignored-field", "SSH carries TCP only. The UDP flag was ignored.", false)
	}

	p := object{}
	out["protocol"] = p
	if key := r.str("private-key"); key != "" {
		// mihomo interprets any value without PRIVATE KEY as a file path.
		if strings.Contains(key, "PRIVATE KEY") {
			p["private-key"] = key
		} else {
			r.fail("private-key", "import.unsupported-field", "SSH private key paths are unsupported. Supply the inline private key.")
		}
	}
	if passphrase := r.str("private-key-passphrase"); passphrase != "" {
		p["private-key-passphrase"] = passphrase
	}
	hostKeys := get(r.n, "host-key")
	if empty(hostKeys) || hostKeys.Kind == yaml.SequenceNode && len(hostKeys.Content) == 0 {
		// Preserve mihomo's behavior for an unpinned node and make it visible in the preview.
		p["insecure-skip-host-key"] = true
		if hostKeys == nil {
			hostKeys = r.n
		}
		c.diag(hostKeys, r.path+"/host-key", "import.ssh.unverified-host-key", "Host key verification is disabled for this SSH node. Set host-key to a trusted server public key.", false)
	} else {
		p["host-key"] = r.stringList(hostKeys, "host-key", "import.type")
	}
	if algorithms := get(r.n, "host-key-algorithms"); !empty(algorithms) {
		p["host-key-algorithms"] = r.stringList(algorithms, "host-key-algorithms", "import.type")
	}
}
