package importer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

type proxyReader struct {
	c    *converter
	n    *yaml.Node
	path string
	bad  bool
}

func (r *proxyReader) fail(key, code, message string) {
	r.bad = true
	at := get(r.n, key)
	if at == nil {
		at = r.n
	}
	r.c.unsupported(at, model.JoinPath(r.path, key), code, message)
}
func (r *proxyReader) str(key string) string {
	n := get(r.n, key)
	if empty(n) {
		return ""
	}
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" && n.Tag != "!!int" {
		r.fail(key, "import.type", "expected a scalar string")
		return ""
	}
	return n.Value
}
func (r *proxyReader) stringList(n *yaml.Node, key, code string) []string {
	if n == nil || n.Kind != yaml.SequenceNode {
		r.fail(key, code, "expected a list of strings")
		return nil
	}
	values := make([]string, 0, len(n.Content))
	for _, item := range n.Content {
		item = deref(item)
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			r.fail(key, code, "expected a list of strings")
			continue
		}
		values = append(values, item.Value)
	}
	return values
}
func (r *proxyReader) boolean(key string, def bool) bool {
	n := get(r.n, key)
	if empty(n) {
		return def
	}
	if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
		r.fail(key, "import.type", "expected true or false")
		return def
	}
	var value bool
	if err := n.Decode(&value); err != nil {
		r.fail(key, "import.type", "expected true or false")
		return def
	}
	return value
}
func (r *proxyReader) optionalBool(key string) bool {
	if n := get(r.n, key); n != nil && empty(n) {
		r.fail(key, "import.type", "expected true or false")
		return false
	}
	return r.boolean(key, false)
}
func (r *proxyReader) port() int {
	p := r.number("port", 0)
	if p < 1 || p > 65535 {
		r.fail("port", "import.port", "port must be between 1 and 65535")
		return 0
	}
	return p
}

func (c *converter) convertProxy(n *yaml.Node, path string) {
	n = deref(n)
	r := proxyReader{c: c, n: n, path: path}
	name := r.str("name")
	id := c.names[name]
	typ := r.str("type")
	switch typ {
	case "vmess", "trojan", "anytls", "hysteria", "hysteria2", "hy2", "tuic", "snell":
		c.convertExtended(n, path)
		return
	}
	nativeType := map[string]string{"ss": "shadowsocks", "ssr": model.OutboundSSR, "vless": "vless", "http": "http", "socks5": "socks", "direct": "direct", "reject": "reject", "wireguard": model.OutboundWireGuard, "ssh": model.OutboundSSH, "mieru": model.OutboundMieru}[typ]
	binding := Binding{Kind: "outbound", Name: name, ID: id}
	defer func() { c.report.Bindings = append(c.report.Bindings, binding) }()
	if nativeType == "" {
		c.unsupported(get(n, "type"), path+"/type", "import.protocol", "protocol is not implemented by this build")
		return
	}
	out := object{"id": id, "name": name, "type": nativeType}
	switch typ {
	case model.OutboundSSR:
		c.convertSSR(&r, out)
		c.addOutbound(&r, out, &binding)
		return
	case "mieru":
		c.convertMieru(&r, out)
		c.addOutbound(&r, out, &binding)
		return
	case "ssh":
		c.convertSSH(&r, out)
		c.addOutbound(&r, out, &binding)
		return
	case "wireguard":
		c.convertWireGuard(&r, out)
		c.addOutbound(&r, out, &binding)
		return
	}
	allowed := map[string]bool{"name": true, "type": true}
	for _, key := range []string{"server", "port", "udp", "username", "password", "cipher", "uuid", "flow", "packet-encoding", "network", "tls", "servername", "sni", "client-fingerprint", "skip-cert-verify", "alpn", "reality-opts", "encryption", "xudp", "packet-addr", "ws-opts", "grpc-opts", "http-upgrade-opts", "h2-opts", "http-opts", "xhttp-opts", "smux"} {
		switch key {
		case "server", "port":
			allowed[key] = typ != "direct" && typ != "reject"
		case "udp":
			allowed[key] = typ == "ss" || typ == "vless" || typ == "socks5" || typ == "direct"
		case "username":
			allowed[key] = typ == "http" || typ == "socks5"
		case "password":
			allowed[key] = typ == "http" || typ == "socks5" || typ == "ss"
		case "cipher":
			allowed[key] = typ == "ss"
		case "tls", "skip-cert-verify":
			allowed[key] = typ == "http" || typ == "socks5" || typ == "vless"
		case "sni":
			allowed[key] = typ == "http" || typ == "socks5"
		default:
			allowed[key] = typ == "vless"
		}
	}
	if typ == "ss" {
		allowed["plugin"], allowed["plugin-opts"], allowed["client-fingerprint"] = true, true, true
		c.convertSSPlugin(&r, out)
		allowed["udp-over-tcp"], allowed["udp-over-tcp-version"] = true, true
		out["udp-over-tcp"], out["udp-over-tcp-version"] = r.boolean("udp-over-tcp", false), r.number("udp-over-tcp-version", 0)
	}
	if typ == "http" {
		allowed["headers"] = true
		if h := get(n, "headers"); h != nil {
			if h.Kind != yaml.MappingNode {
				r.fail("headers", "import.headers", "headers must be a mapping")
			} else {
				headers := []object{}
				for i := 0; i+1 < len(h.Content); i += 2 {
					if h.Content[i+1].Kind != yaml.ScalarNode {
						r.fail("headers", "import.headers", "header values must be scalar strings")
						continue
					}
					headers = append(headers, object{"name": h.Content[i].Value, "value": h.Content[i+1].Value})
				}
				out["headers"] = headers
			}
		}
	}
	c.convertDialer(&r, out, allowed)
	permitTLSExtras(typ, allowed)
	// These disabled options do not change the wire format. Enabled values
	// must never be silently dropped.
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, v := n.Content[i].Value, deref(n.Content[i+1])
		if allowed[key] {
			continue
		}
		if typ == "vless" && (key == "alterId" || key == "cipher") {
			c.diag(v, model.JoinPath(path, key), "import.ignored-field", "VMess-only field has no meaning on a VLESS node", false)
			continue
		}
		if key == "tfo" || key == "mptcp" || key == "udp-over-tcp" {
			if v.Kind == yaml.ScalarNode && v.Tag == "!!bool" && v.Value == "false" {
				continue
			}
		}
		if key == "smux" && v.Kind == yaml.MappingNode && len(v.Content) == 2 && text(get(v, "enabled")) == "false" {
			continue
		}
		r.fail(key, "import.unsupported-field", "field is not supported for this protocol")
	}
	if typ != "direct" && typ != "reject" {
		out["server"], out["port"] = r.str("server"), r.port()
	}
	if allowed["udp"] {
		out["udp"] = r.boolean("udp", typ == "direct")
	}
	for _, key := range []string{"username", "password", "uuid", "flow"} {
		if allowed[key] && get(n, key) != nil {
			out[key] = r.str(key)
		}
	}
	if typ == "http" || typ == "socks5" {
		if (r.str("username") == "") != (r.str("password") == "") {
			r.fail("password", "import.outbound.auth", "set both username and password or neither")
		}
	}
	if typ == "ss" {
		out["method"] = r.str("cipher")
	}
	if typ == "vless" {

		if encryption := r.str("encryption"); encryption != "" {
			out["encryption"] = encryption
		}
		encoding := r.str("packet-encoding")
		addr := r.boolean("packet-addr", false)
		xudp := r.boolean("xudp", false)
		switch encoding {
		case "packet", "packetaddr":
			addr = true
			xudp = false
		case "", "xudp", "none":
			if encoding == "none" {
				c.diag(get(n, "packet-encoding"), path+"/packet-encoding", "import.ignored-field", "the pinned reference treats none as its default packet selection; native raw UDP is selected separately", false)
			}
			if !addr {
				xudp = true
			}
		default:
			r.fail("packet-encoding", "import.packet-encoding", "unknown VLESS packet encoding")
		}
		if xudp {
			addr = false
		}
		out["packet-encoding"] = "xudp"
		if addr {
			out["packet-encoding"] = "packetaddr"
		}
	}
	tlsEnabled := false
	if allowed["tls"] {
		tlsEnabled = r.boolean("tls", false)
	}
	if typ == "vless" && r.str("network") == "h2" {
		tlsEnabled = true
	}
	if tlsEnabled && (typ == "http" || typ == "vless" || typ == "socks5") {
		tls := object{}
		sniKey := "servername"
		if typ == "http" || typ == "socks5" {
			sniKey = "sni"
		}
		if get(n, sniKey) != nil {
			tls["server-name"] = r.str(sniKey)
		}
		if get(n, "skip-cert-verify") != nil {
			tls["insecure"] = r.boolean("skip-cert-verify", false)
		}
		if typ == "vless" {
			if get(n, "client-fingerprint") != nil {
				tls["fingerprint"] = r.str("client-fingerprint")
			}
			if alpn := get(n, "alpn"); !empty(alpn) {
				if alpn.Kind != yaml.SequenceNode {
					r.fail("alpn", "import.type", "alpn must be a list")
				} else {
					values := []string{}
					for _, v := range alpn.Content {
						v = deref(v)
						if v.Kind != yaml.ScalarNode || v.Tag != "!!str" {
							r.fail("alpn", "import.type", "alpn values must be strings")
						} else {
							values = append(values, v.Value)
						}
					}
					tls["alpn"] = values
				}
			}
			if reality := get(n, "reality-opts"); !empty(reality) {
				if reality.Kind != yaml.MappingNode {
					r.fail("reality-opts", "import.type", "reality-opts must be a mapping")
				} else {
					rr := proxyReader{c: c, n: reality, path: path + "/reality-opts"}
					for i := 0; i+1 < len(reality.Content); i += 2 {
						key := reality.Content[i].Value
						if key != "public-key" && key != "short-id" && key != "support-x25519mlkem768" {
							rr.fail(key, "import.unsupported-field", "unknown REALITY option")
						}
					}
					if tls["insecure"] == true {
						tls["insecure"] = false
						c.diag(get(n, "skip-cert-verify"), path+"/skip-cert-verify", "import.ignored-field", "REALITY authenticates its configured public key; this certificate flag has no effect", false)
					}
					tls["reality"] = object{"public-key": rr.str("public-key"), "short-id": rr.str("short-id"), "x25519mlkem768": rr.boolean("support-x25519mlkem768", false)}
					r.bad = r.bad || rr.bad
				}
			}
		}
		out["tls"] = tls
	} else if typ == "vless" || typ == "http" || typ == "socks5" {
		for _, key := range []string{"servername", "sni", "client-fingerprint", "skip-cert-verify", "alpn", "reality-opts"} {
			if v := get(n, key); !empty(v) && ((v.Kind == yaml.MappingNode || v.Kind == yaml.SequenceNode) && len(v.Content) > 0 || v.Kind == yaml.ScalarNode && v.Value != "false" && v.Value != "") {
				r.fail(key, "import.tls", "TLS-specific options require TLS")
			}
		}
	}
	c.convertTLSExtras(&r, typ, out)
	if typ == "vless" {
		c.convertTransport(&r, out)
	}
	c.convertMultiplex(&r, out)
	c.addOutbound(&r, out, &binding)
}

func (c *converter) addOutbound(r *proxyReader, out object, binding *Binding) {
	if r.bad || !c.validateOutbound(out, r.n, r.path) {
		return
	}
	c.nodes = append(c.nodes, out)
	c.available[binding.Name] = true
	binding.Available = true
}

func (c *converter) validateOutbound(out object, n *yaml.Node, path string) bool {
	b, _ := json.Marshal(object{"schema-version": 1, "outbounds": []object{out}})
	_, diags := compile.Compile(b, nil, compile.Options{ProcessLookup: true})
	valid := true
	for _, d := range diags {
		if d.Severity != model.SeverityError || strings.HasPrefix(d.Code, "secret.") || d.Code == "outbound.detour" {
			continue
		}
		if d.Code == "outbound.auth" {
			hasReference := false
			for _, key := range []string{"username", "password"} {
				v, _ := out[key].(string)
				hasReference = hasReference || strings.HasPrefix(v, model.SecretPrefix)
			}
			if hasReference {
				continue
			}
		}
		valid = false
		// Compiler errors are safe summaries, never reproduce credential values.
		key := strings.TrimPrefix(d.Path, model.JoinPath("/outbounds", out["id"].(string)))
		switch {
		case key == "/method":
			key = "/cipher"
		case out["type"] == model.OutboundMieru && strings.HasPrefix(key, "/protocol/server-ports"):
			key = "/port-range"
		case (out["type"] == model.OutboundSSH || out["type"] == model.OutboundMieru) && strings.HasPrefix(key, "/protocol/"):
			key = strings.TrimPrefix(key, "/protocol")
		case strings.HasPrefix(key, "/tls"):
			key = "/tls"
		}
		at := n
		if c.report.Format == "wireguard" {
			at = wireGuardConfDiagnosticNode(n, key)
		} else if len(key) > 1 {
			if child := get(n, strings.TrimPrefix(key, "/")); child != nil {
				at = child
			}
		}
		c.unsupported(at, path+key, "import."+d.Code, fmt.Sprintf("native validation failed (%s)", d.Code))
	}
	return valid
}
