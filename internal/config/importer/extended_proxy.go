package importer

import (
	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
	"strconv"
	"strings"
)

func (r *proxyReader) number(key string, def int) int {
	if get(r.n, key) == nil {
		return def
	}
	base := 10
	if get(r.n, key).Tag == "!!int" {
		base = 0
	}
	value, err := strconv.ParseInt(r.str(key), base, 64)
	v := int(value)
	if err != nil {
		r.fail(key, "import.type", "expected an integer")
	}
	return v
}
func (c *converter) convertExtended(n *yaml.Node, path string) {
	r := proxyReader{c: c, n: n, path: path}
	name, typ := r.str("name"), r.str("type")
	id := c.names[name]
	nativeType := typ
	if nativeType == "hy2" {
		nativeType = "hysteria2"
	}
	binding := Binding{Kind: "outbound", Name: name, ID: id}
	defer func() { c.report.Bindings = append(c.report.Bindings, binding) }()
	port := 0
	if nativeType != "hysteria2" || empty(get(n, "ports")) || (!empty(get(n, "port")) && text(get(n, "port")) != "0") {
		port = r.port()
	}
	out := object{"id": id, "name": name, "type": nativeType, "server": r.str("server"), "port": port, "udp": r.boolean("udp", false)}
	allowed := map[string]bool{}
	for _, k := range []string{"name", "type", "server", "port", "udp", "tls", "servername", "sni", "skip-cert-verify", "client-fingerprint", "alpn"} {
		allowed[k] = true
	}
	permit := func(keys ...string) {
		for _, k := range keys {
			allowed[k] = true
		}
	}
	p := object{}
	switch nativeType {
	case "vmess":
		permit("uuid", "alterId", "cipher", "network", "ws-opts", "grpc-opts", "http-upgrade-opts", "h2-opts", "http-opts", "smux", "packet-encoding")
		out["uuid"] = r.str("uuid")
		security := r.str("cipher")
		if security == "" {
			security = "auto"
		}
		p["security"], p["alter-id"] = security, r.number("alterId", 0)
		if v := r.str("packet-encoding"); v != "" {
			out["packet-encoding"] = v
		}
	case "trojan":
		permit("password", "network", "ws-opts", "grpc-opts", "http-upgrade-opts", "smux")
		out["password"] = r.str("password")
	case "hysteria2":
		permit("password", "up", "down", "obfs", "obfs-password", "ports", "hop-interval")
		if ports := r.str("ports"); ports != "" {
			ranges, err := model.PortHops(ports)
			if err != nil {
				r.fail("ports", "import.ports", err.Error())
			} else {
				p["server-ports"] = ranges
			}
			lo, hi, err := model.HopSeconds(r.str("hop-interval"))
			if err != nil {
				r.fail("hop-interval", "import.ports", err.Error())
			} else {
				p["hop-interval-seconds"], p["hop-interval-max-seconds"] = lo, hi
			}
		} else if get(n, "hop-interval") != nil {
			c.report.Ignored = append(c.report.Ignored, path+"/hop-interval")
		}
		out["password"] = r.str("password")
		p["up-mbps"], p["down-mbps"] = r.number("up", 0), r.number("down", 0)
		if obfs := r.str("obfs"); obfs != "" {
			p["obfs"] = object{"type": obfs, "password": r.str("obfs-password")}
		}
	case "tuic":
		permit("uuid", "password", "congestion-controller", "udp-relay-mode", "reduce-rtt", "heartbeat-interval")
		out["uuid"], out["password"] = r.str("uuid"), r.str("password")
		p["congestion-control"], p["udp-relay-mode"], p["zero-rtt"] = r.str("congestion-controller"), r.str("udp-relay-mode"), r.boolean("reduce-rtt", false)
		p["heartbeat"] = r.number("heartbeat-interval", 0)
	case "snell":
		permit("psk", "version", "userkey", "mode", "reuse", "obfs-opts")
		out["password"] = r.str("psk")
		p["version"], p["user-key"], p["mode"], p["reuse"] = r.number("version", 0), r.str("userkey"), r.str("mode"), r.boolean("reuse", false)
		if obfs := get(n, "obfs-opts"); !empty(obfs) {
			br := proxyReader{c: c, n: obfs, path: path + "/obfs-opts"}
			p["obfs"] = object{"type": br.str("mode"), "host": br.str("host")}
			for i := 0; i+1 < len(obfs.Content); i += 2 {
				if obfs.Content[i].Value != "mode" && obfs.Content[i].Value != "host" {
					br.fail(obfs.Content[i].Value, "import.obfs", "unsupported Snell obfs option")
				}
			}
			r.bad = r.bad || br.bad
		}
	}
	if len(p) > 0 {
		out["protocol"] = p
	}
	c.convertDialer(&r, out, allowed)
	permitTLSExtras(nativeType, allowed)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, v := n.Content[i].Value, n.Content[i+1]
		if !allowed[key] {
			if (key == "tfo" || key == "mptcp") && text(v) == "false" {
				continue
			}
			r.fail(key, "import.unsupported-field", "unsupported protocol option")
		}
	}
	tlsEnabled := nativeType == "trojan" || nativeType == "hysteria2" || nativeType == "tuic"
	tlsEnabled = r.boolean("tls", tlsEnabled)
	if nativeType == "vmess" && r.str("network") == "h2" {
		tlsEnabled = true
	}
	if nativeType == "snell" && tlsEnabled {
		r.fail("tls", "import.tls", "Snell TLS is an obfs option, not outer TLS")
	}
	if tlsEnabled && nativeType != "snell" {
		tls := object{}
		sni := r.str("servername")
		if sni == "" {
			sni = r.str("sni")
		}
		if sni != "" {
			tls["server-name"] = sni
		}
		tls["insecure"] = r.boolean("skip-cert-verify", false)
		if fp := r.str("client-fingerprint"); fp != "" {
			tls["fingerprint"] = fp
		}
		if v := get(n, "alpn"); v != nil {
			var values []string
			if err := v.Decode(&values); err != nil {
				r.fail("alpn", "import.type", "alpn must be a string list")
			} else {
				tls["alpn"] = values
			}
		}
		out["tls"] = tls
	} else if nativeType != "snell" {
		for _, key := range []string{"servername", "sni", "client-fingerprint", "alpn"} {
			if !empty(get(n, key)) {
				r.fail(key, "import.tls", "TLS options require TLS")
			}
		}
	}
	c.convertTLSExtras(&r, nativeType, out)
	c.convertTransport(&r, out)
	if !r.bad && !c.validateOutbound(out, n, path) {
		r.bad = true
	}
	if r.bad {
		return
	}
	c.nodes = append(c.nodes, out)
	c.available[name] = true
	binding.Available = true
}
func (c *converter) convertTransport(r *proxyReader, out object) {
	network := r.str("network")
	if network != "" && network != "tcp" {
		t := object{"type": network}
		key := ""
		switch network {
		case "ws":
			key = "ws-opts"
		case "grpc":
			key = "grpc-opts"
		case "httpupgrade":
			key = "http-upgrade-opts"
		case "http", "h2":
			key = network + "-opts"
		default:
			r.fail("network", "import.transport", "unsupported transport")
			return
		}
		if opts := get(r.n, key); !empty(opts) {
			br := proxyReader{c: c, n: opts, path: r.path + "/" + key}
			for i := 0; i+1 < len(opts.Content); i += 2 {
				field := opts.Content[i].Value
				switch field {
				case "method":
					t["method"] = br.str(field)
				case "path":
					if network == "http" {
						t["paths"] = transportStrings(&br, opts, field)
					} else {
						t["path"] = br.str(field)
					}
				case "host":
					if network == "h2" {
						t["hosts"] = transportStrings(&br, opts, field)
					} else {
						t["host"] = br.str(field)
					}
				case "grpc-service-name":
					t["service-name"] = br.str(field)
				case "max-early-data":
					t["max-early-data"] = br.number(field, 0)
				case "early-data-header-name":
					t["early-data-header"] = br.str(field)
				case "headers":
					headers := []object{}
					v := get(opts, field)
					if v.Kind != yaml.MappingNode {
						br.fail(field, "import.type", "headers must be a mapping")
						continue
					}
					for j := 0; j+1 < len(v.Content); j += 2 {
						if network == "http" {
							for _, value := range transportStrings(&br, v, v.Content[j].Value) {
								headers = append(headers, object{"name": v.Content[j].Value, "value": value})
							}
							continue
						}
						if v.Content[j+1].Kind != yaml.ScalarNode {
							br.fail(field, "import.type", "headers must be scalar")
							continue
						}
						headers = append(headers, object{"name": v.Content[j].Value, "value": v.Content[j+1].Value})
					}
					t["headers"] = headers
				default:
					br.fail(field, "import.transport", "unsupported transport option")
				}
			}
			r.bad = r.bad || br.bad
		}
		out["transport"] = t
	}
	if mux := get(r.n, "smux"); !empty(mux) {
		br := proxyReader{c: c, n: mux, path: r.path + "/smux"}
		m := object{"enabled": br.boolean("enabled", false)}
		for i := 0; i+1 < len(mux.Content); i += 2 {
			key := mux.Content[i].Value
			switch key {
			case "enabled":
			case "protocol":
				m[key] = br.str(key)
			case "max-connections", "min-streams", "max-streams":
				m[key] = br.number(key, 0)
			case "padding":
				m[key] = br.boolean(key, false)
			default:
				br.fail(key, "import.multiplex", "unsupported multiplex option")
			}
		}
		r.bad = r.bad || br.bad
		out["multiplex"] = m
	}
	for _, key := range []string{"ws-opts", "grpc-opts", "http-upgrade-opts"} {
		if !empty(get(r.n, key)) && strings.TrimSpace(network) == "" {
			r.fail(key, "import.transport", "transport options require network")
		}
	}
}

// Clash HTTP obfuscation selects one value from each configured list.
func transportStrings(r *proxyReader, n *yaml.Node, key string) []string {
	v := get(n, key)
	if v == nil || v.Kind != yaml.SequenceNode {
		r.fail(key, "import.transport", "expected a list of strings")
		return nil
	}
	values := []string{}
	for _, item := range v.Content {
		item = deref(item)
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
			r.fail(key, "import.transport", "expected a list of strings")
			continue
		}
		values = append(values, item.Value)
	}
	return values
}
