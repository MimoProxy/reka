package importer

import (
	"encoding/json"
	"slices"

	"go.yaml.in/yaml/v3"
)

var xhttpStrings = []string{
	"mode", "x-padding-bytes", "x-padding-key", "x-padding-header", "x-padding-placement", "x-padding-method",
	"uplink-http-method", "session-placement", "session-key", "session-table", "session-length", "seq-placement", "seq-key",
	"uplink-data-placement", "uplink-data-key", "uplink-chunk-size", "sc-max-each-post-bytes", "sc-min-posts-interval-ms",
}

func (c *converter) convertXHTTPTransport(r *proxyReader, out object) {
	if r.str("type") != "vless" {
		r.fail("network", "import.transport", "XHTTP applies to VLESS only")
		return
	}
	for _, key := range []string{"ws-opts", "grpc-opts", "http-upgrade-opts", "http-opts", "h2-opts"} {
		if get(r.n, key) != nil {
			r.fail(key, "import.transport", "options do not apply to XHTTP")
		}
	}
	t := object{"type": "xhttp"}
	if opts := get(r.n, "xhttp-opts"); opts != nil {
		x := c.convertXHTTPOptions(r, opts, r.path+"/xhttp-opts", false, out)
		for _, key := range []string{"host", "path", "headers"} {
			if value, ok := x[key]; ok {
				t[key] = value
				delete(x, key)
			}
		}
		t["xhttp"] = x
	}
	out["transport"] = t
}

func (c *converter) convertXHTTPOptions(parent *proxyReader, node *yaml.Node, path string, download bool, main object) object {
	node = deref(node)
	r := proxyReader{c: c, n: node, path: path}
	out := object{}
	if node.Kind != yaml.MappingNode {
		parent.fail("xhttp-opts", "import.transport", "XHTTP options must be a mapping")
		return out
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		switch {
		case key == "host" || key == "path":
			out[key] = r.str(key)
		case key == "headers":
			out[key] = xhttpImportHeaders(&r, key)
		case key == "xmux" || key == "reuse-settings":
			if _, exists := out["xmux"]; exists {
				r.fail(key, "import.transport", "choose reuse-settings or xmux, not both")
				continue
			}
			out["xmux"] = xhttpImportReuse(&r, key)
		case key == "download-settings" && !download:
			out[key] = c.convertXHTTPOptions(&r, deref(node.Content[i+1]), path+"/"+key, true, main)
		case slices.Contains(xhttpStrings, key) && !download:
			out[key] = r.str(key)
		case (key == "no-grpc-header" || key == "x-padding-obfs-mode") && !download:
			out[key] = r.boolean(key, false)
		case download && key == "server":
			out[key] = r.str(key)
		case download && key == "port":
			out[key] = r.port()
		case download && slices.Contains(xhttpDownloadTLSKeys(), key):
			// Parsed together after checking the complete endpoint below.
		default:
			r.fail(key, "import.transport", "unsupported XHTTP option")
		}
	}
	if download {
		c.convertXHTTPDownloadTLS(&r, out, main)
	}
	parent.bad = parent.bad || r.bad
	return out
}

func xhttpImportHeaders(r *proxyReader, key string) []object {
	n := deref(get(r.n, key))
	if n.Kind != yaml.MappingNode {
		r.fail(key, "import.transport", "XHTTP headers must be a mapping")
		return nil
	}
	values := make([]object, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		v := deref(n.Content[i+1])
		if v.Kind != yaml.ScalarNode || v.Tag != "!!str" {
			r.fail(key, "import.transport", "XHTTP header values must be strings")
			continue
		}
		values = append(values, object{"name": n.Content[i].Value, "value": v.Value})
	}
	return values
}

func xhttpImportReuse(parent *proxyReader, key string) object {
	n := deref(get(parent.n, key))
	r := proxyReader{c: parent.c, n: n, path: parent.path + "/" + key}
	out := object{}
	if n.Kind != yaml.MappingNode {
		parent.fail(key, "import.transport", "XHTTP reuse options must be a mapping")
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		field := n.Content[i].Value
		if !slices.Contains([]string{"max-concurrency", "max-connections", "c-max-reuse-times", "h-max-request-times", "h-max-reusable-secs", "h-keep-alive-period"}, field) {
			r.fail(field, "import.transport", "unsupported XHTTP reuse option")
			continue
		}
		out[field] = r.str(field)
	}
	parent.bad = parent.bad || r.bad
	return out
}

func xhttpDownloadTLSKeys() []string {
	return []string{"tls", "alpn", "servername", "client-fingerprint", "skip-cert-verify", "fingerprint", "name-cert-verify", "certificate", "private-key", "ech-opts", "shadow-tls-opts", "restls-opts", "jls-opts", "reality-opts"}
}

func (c *converter) convertXHTTPDownloadTLS(r *proxyReader, out, main object) {
	hasOptions := false
	for _, key := range xhttpDownloadTLSKeys() {
		hasOptions = hasOptions || get(r.n, key) != nil
	}
	if !hasOptions {
		return
	}
	mainTLS, enabled := main["tls"].(object)
	if get(r.n, "tls") != nil {
		enabled = r.boolean("tls", enabled)
	}
	if !enabled {
		out["disable-tls"] = true
		for _, key := range xhttpDownloadTLSKeys()[1:] {
			if get(r.n, key) != nil {
				r.fail(key, "import.transport", "download TLS options require TLS")
			}
		}
		return
	}
	// Match optional Clash download fields by inheriting the main TLS identity,
	// then overriding only fields explicitly present in download-settings.
	tls := object{}
	if mainTLS != nil {
		raw, _ := json.Marshal(mainTLS)
		_ = json.Unmarshal(raw, &tls)
	}
	for from, to := range map[string]string{"servername": "server-name", "client-fingerprint": "fingerprint"} {
		if get(r.n, from) != nil {
			tls[to] = r.str(from)
		}
	}
	if get(r.n, "skip-cert-verify") != nil {
		tls["insecure"] = r.boolean("skip-cert-verify", false)
	}
	if n := get(r.n, "alpn"); n != nil {
		tls["alpn"] = transportStrings(r, r.n, "alpn")
	}
	if n := get(r.n, "reality-opts"); n != nil {
		n = deref(n)
		rr := proxyReader{c: c, n: n, path: r.path + "/reality-opts"}
		if n.Kind != yaml.MappingNode {
			r.fail("reality-opts", "import.transport", "download REALITY options must be a mapping")
		} else {
			for i := 0; i+1 < len(n.Content); i += 2 {
				key := n.Content[i].Value
				if !slices.Contains([]string{"public-key", "short-id", "support-x25519mlkem768"}, key) {
					rr.fail(key, "import.transport", "unknown REALITY option")
				}
			}
			tls["reality"] = object{"public-key": rr.str("public-key"), "short-id": rr.str("short-id"), "x25519mlkem768": rr.boolean("support-x25519mlkem768", false)}
			r.bad = r.bad || rr.bad
		}
	}
	wrapped := object{"tls": tls}
	c.convertTLSExtras(r, "vless", wrapped)
	out["tls"] = wrapped["tls"]
}
