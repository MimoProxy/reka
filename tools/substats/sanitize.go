package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"go.yaml.in/yaml/v3"
)

// sanitize rewrites doc in place so it can be kept as a test corpus.
//
// Default is redact: inside proxies only proxyKeep fields keep their value;
// every other string becomes a placeholder. Proxy, group and provider names
// are mapped to placeholders consistently everywhere they are referenced.
// Top-level sections outside the four imported parts and the providers
// keep their key but lose their content. Comments are dropped.
func sanitize(doc *yaml.Node) {
	root := docRoot(doc)
	if root == nil {
		return
	}
	stripComments(doc)
	s := &sanitizer{names: map[string]string{}, hosts: map[string]string{}, counters: map[string]int{}}
	s.collectNames(root)
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, val := root.Content[i].Value, root.Content[i+1]
		switch key {
		case "proxies":
			for _, p := range val.Content {
				s.proxy(p)
			}
		case "proxy-groups":
			for _, g := range val.Content {
				s.group(g)
			}
		case "rules":
			for _, r := range val.Content {
				r.Value = s.rule(r.Value)
			}
		case "dns":
			s.dns(val)
		case "proxy-providers", "rule-providers":
			s.providers(key, val)
		default:
			root.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
		}
	}
}

func stripComments(n *yaml.Node) {
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	for _, c := range n.Content {
		stripComments(c)
	}
}

type sanitizer struct {
	names    map[string]string // proxy, group and provider names
	hosts    map[string]string
	counters map[string]int
}

func (s *sanitizer) next(kind string) int {
	s.counters[kind]++
	return s.counters[kind]
}

var builtinTargets = map[string]bool{
	"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true,
}

func (s *sanitizer) collectNames(root *yaml.Node) {
	add := func(kind, name string) {
		if name == "" || builtinTargets[name] {
			return
		}
		if _, ok := s.names[kind+"\x00"+name]; !ok {
			s.names[kind+"\x00"+name] = fmt.Sprintf("%s-%03d", kind, s.next(kind))
		}
	}
	if p := mapGet(root, "proxies"); p != nil {
		for _, px := range p.Content {
			if n := mapGet(px, "name"); n != nil {
				add("proxy", n.Value)
			}
		}
	}
	if g := mapGet(root, "proxy-groups"); g != nil {
		for _, grp := range g.Content {
			if n := mapGet(grp, "name"); n != nil {
				add("group", n.Value)
			}
		}
	}
	for _, kind := range []string{"proxy-providers", "rule-providers"} {
		if pp := mapGet(root, kind); pp != nil && pp.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(pp.Content); i += 2 {
				add(strings.TrimSuffix(kind, "s"), pp.Content[i].Value)
			}
		}
	}
}

// ref maps a proxy or group reference; unknown names (typos, references to
// things defined elsewhere) are redacted too.
func (s *sanitizer) ref(name string) string {
	if builtinTargets[name] {
		return name
	}
	for _, kind := range []string{"group", "proxy"} {
		if v, ok := s.names[kind+"\x00"+name]; ok {
			return v
		}
	}
	return "unknown-" + shortHash(name)
}

func (s *sanitizer) providerRef(kind, name string) string {
	if v, ok := s.names[kind+"\x00"+name]; ok {
		return v
	}
	return "unknown-" + shortHash(name)
}

func shortHash(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:3])
}

// host replaces an address, keeping whether it was an IPv4, IPv6 or domain
// name. Replacements come from the documentation ranges.
func (s *sanitizer) host(h string) string {
	if h == "" {
		return h
	}
	if v, ok := s.hosts[h]; ok {
		return v
	}
	var v string
	if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		n := s.next("ip")
		if a.Is4() {
			v = fmt.Sprintf("192.0.2.%d", n%250+1)
		} else {
			v = fmt.Sprintf("2001:db8::%x", n)
		}
	} else {
		v = fmt.Sprintf("host-%03d.example.com", s.next("host"))
	}
	s.hosts[h] = v
	return v
}

// Proxy fields whose values are protocol options, safe to keep verbatim.
var proxyKeep = map[string]bool{
	"type": true, "port": true, "cipher": true, "network": true, "flow": true, "tls": true, "udp": true,
	"client-fingerprint": true, "skip-cert-verify": true, "packet-encoding": true, "plugin": true,
	"obfs": true, "protocol": true, "xudp": true, "udp-over-tcp": true, "udp-over-tcp-version": true,
	"ip-version": true, "encryption": true, "tfo": true, "mptcp": true, "alpn[]": true, "alterId": true,
	"version": true, "congestion-controller": true, "udp-relay-mode": true, "reduce-rtt": true,
	"fast-open": true, "disable-sni": true, "authenticated-length": true, "global-padding": true,
	"up": true, "down": true, "heartbeat-interval": true, "request-timeout": true, "mtu": true,
	"reality-opts.support-x25519mlkem768": true, "smux.enabled": true, "smux.protocol": true,
	"smux.max-connections": true, "smux.min-streams": true, "smux.max-streams": true, "smux.padding": true,
	"plugin-opts.mode": true, "plugin-opts.tls": true, "plugin-opts.mux": true, "plugin-opts.skip-cert-verify": true,
	"ws-opts.max-early-data": true, "ws-opts.early-data-header-name": true, "ws-opts.v2ray-http-upgrade": true,
	"ws-opts.v2ray-http-upgrade-fast-open": true, "http-opts.method": true, "hop-interval": true,
}

func (s *sanitizer) proxy(px *yaml.Node) {
	rewriteLeaves("", px, func(path string, v *yaml.Node) {
		switch {
		case path == "name":
			v.Value = s.ref(v.Value)
		case path == "dialer-proxy":
			v.Value = s.ref(v.Value)
		case path == "server" || path == "ip" || path == "ipv6" || path == "peers[].server":
			v.Value = s.host(v.Value)
		case proxyKeep[path] || proxyKeep[strings.TrimSuffix(path, "[]")+"[]"]:
		case v.Tag == "!!bool" || v.Tag == "!!int" || v.Tag == "!!float" || v.Tag == "!!null":
		default:
			v.Value = "redacted-" + shortHash(v.Value)
			v.Tag, v.Style = "!!str", 0
		}
	})
}

// rewriteLeaves calls fn on every scalar under n with its dotted path.
// Mapping keys under header maps are replaced too, since they can carry
// identifying values (custom headers).
func rewriteLeaves(prefix string, n *yaml.Node, fn func(path string, v *yaml.Node)) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			p := k.Value
			if prefix != "" {
				p = prefix + "." + p
			}
			if strings.HasSuffix(prefix, "headers") && !strings.EqualFold(k.Value, "Host") && !strings.EqualFold(k.Value, "User-Agent") {
				k.Value = "X-Header-" + shortHash(k.Value)
			}
			rewriteLeaves(p, n.Content[i+1], fn)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			rewriteLeaves(prefix+"[]", c, fn)
		}
	case yaml.ScalarNode:
		fn(prefix, n)
	}
}

func (s *sanitizer) group(g *yaml.Node) {
	rewriteLeaves("", g, func(path string, v *yaml.Node) {
		switch path {
		case "name", "proxies[]", "dialer-proxy":
			v.Value = s.ref(v.Value)
		case "use[]":
			v.Value = s.providerRef("proxy-provider", v.Value)
		case "icon", "interface-name":
			v.Value = "redacted-" + shortHash(v.Value)
		case "url":
			// Health-check endpoints are public probes; keep host only.
			v.Value = "https://" + urlHost(v.Value) + "/"
		}
	})
}

func (s *sanitizer) rule(r string) string {
	parts := splitRule(r)
	typ := strings.ToUpper(parts[0])
	switch typ {
	case "MATCH", "FINAL":
		if len(parts) > 1 {
			parts[1] = s.ref(parts[1])
		}
		return strings.Join(parts, ",")
	case "RULE-SET":
		if len(parts) > 1 {
			parts[1] = s.providerRef("rule-provider", parts[1])
		}
	case "AND", "OR", "NOT":
		if len(parts) >= 3 {
			return typ + "," + s.logical(logicalArg(parts)) + "," + s.ref(parts[len(parts)-1])
		}
		return r
	case "SUB-RULE":
		if len(parts) > 2 {
			parts[2] = "redacted-" + shortHash(parts[2])
			return strings.Join(parts, ",")
		}
	}
	if len(parts) >= 2 {
		parts[1] = s.payload(typ, parts[1])
	}
	if len(parts) >= 3 {
		parts[2] = s.ref(parts[2])
	}
	return strings.Join(parts, ",")
}

// logical rewrites the payloads inside a logical rule's argument, keeping
// whichever spelling it used (see logicalItems).
func (s *sanitizer) logical(arg string) string {
	arg = strings.TrimSpace(arg)
	wrapped := len(splitRule(arg)) == 1 && strings.HasPrefix(arg, "((") && strings.HasSuffix(arg, "))")
	items := logicalItems(arg)
	for i, item := range items {
		typ, rest := subRule(item)
		if isLogical(typ) {
			rest = s.logical(rest)
		} else {
			p := splitRule(rest)
			if len(p) > 0 {
				p[0] = s.payload(typ, strings.TrimSpace(p[0]))
			}
			rest = strings.Join(p, ",")
		}
		items[i] = "(" + typ + "," + rest + ")"
	}
	out := strings.Join(items, ",")
	if wrapped {
		out = "(" + out + ")"
	}
	return out
}

// payload replaces rule values that can identify a provider (its own
// domains, server addresses, brand keywords). Geo codes, ports, process
// names and network types are generic and kept.
func (s *sanitizer) payload(typ, v string) string {
	switch typ {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD":
		return s.domain(v)
	case "DOMAIN-KEYWORD":
		return s.mapped("keyword", v, "keyword-%03d")
	case "DOMAIN-REGEX":
		return s.mapped("regex", v, `^regex-%03d\.example\.com$`)
	case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "IP-SUFFIX", "SRC-IP-SUFFIX":
		return s.cidr(v)
	case "IP-ASN", "SRC-IP-ASN":
		return s.mapped("asn", v, "%d")
	}
	return v
}

func (s *sanitizer) mapped(kind, v, format string) string {
	key := kind + "\x00" + v
	if r, ok := s.hosts[key]; ok {
		return r
	}
	r := fmt.Sprintf(format, s.next(kind)+64500*boolInt(kind == "asn"))
	s.hosts[key] = r
	return r
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// domain maps a domain to a placeholder, keeping a leading "+.", "*." or ".".
func (s *sanitizer) domain(d string) string {
	prefix := ""
	for _, p := range []string{"+.", "*.", "."} {
		if strings.HasPrefix(d, p) {
			prefix, d = p, strings.TrimPrefix(d, p)
			break
		}
	}
	if d == "" || strings.HasPrefix(d, "geosite:") || strings.HasPrefix(d, "rule-set:") {
		return prefix + d
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return prefix + s.host(d)
	}
	if !strings.Contains(d, ".") {
		return prefix + d // single labels (lan, local, localhost) identify nobody
	}
	return prefix + s.mapped("domain", strings.ToLower(d), "domain-%03d.example.com")
}

// cidr maps a prefix into the documentation ranges, keeping its length.
func (s *sanitizer) cidr(v string) string {
	p, err := netip.ParsePrefix(v)
	if err != nil {
		if a, err := netip.ParseAddr(v); err == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		} else {
			return "redacted-" + shortHash(v)
		}
	}
	n := s.next("cidr")
	var base netip.Addr
	if p.Addr().Is4() {
		base = netip.AddrFrom4([4]byte{10, byte(n >> 8), byte(n), 0})
	} else {
		base = netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::", n))
	}
	return netip.PrefixFrom(base, p.Bits()).Masked().String()
}

// server rewrites a DNS server address, keeping scheme and port shape.
func (s *sanitizer) server(v string) string {
	v = strings.TrimSpace(v)
	if v == "system" || strings.HasPrefix(v, "dhcp") {
		return v
	}
	scheme, rest := "", v
	if i := strings.Index(v, "://"); i >= 0 {
		scheme, rest = v[:i+3], v[i+3:]
	}
	param := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		rest, param = rest[:i], "#"+s.ref(rest[i+1:])
	}
	path := ""
	if i := strings.Index(rest, "/"); i >= 0 {
		rest, path = rest[:i], rest[i:]
		if path != "/dns-query" && path != "/resolve" {
			path = "/redacted-" + shortHash(path)
		}
	}
	host, port := rest, ""
	if strings.HasPrefix(rest, "[") {
		if i := strings.Index(rest, "]"); i >= 0 {
			host, port = rest[:i+1], rest[i+1:]
		}
	} else if strings.Count(rest, ":") == 1 {
		i := strings.Index(rest, ":")
		host, port = rest[:i], rest[i:]
	}
	h := s.host(strings.Trim(host, "[]"))
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return scheme + h + port + path + param
}

func (s *sanitizer) dns(d *yaml.Node) {
	for _, key := range []string{"nameserver-policy", "hosts"} {
		if m := mapGet(d, key); m != nil && m.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(m.Content); i += 2 {
				k := m.Content[i]
				parts := strings.Split(k.Value, ",")
				for j, part := range parts {
					parts[j] = s.domain(strings.TrimSpace(part))
				}
				k.Value = strings.Join(parts, ",")
			}
		}
	}
	rewriteLeaves("", d, func(path string, v *yaml.Node) {
		key := strings.TrimSuffix(path, "[]")
		switch {
		case key == "nameserver" || key == "fallback" || key == "default-nameserver" ||
			key == "proxy-server-nameserver" || key == "direct-nameserver":
			v.Value = s.server(v.Value)
		case strings.HasPrefix(key, "nameserver-policy."):
			v.Value = s.server(v.Value)
		case strings.HasPrefix(key, "hosts."):
			v.Value = s.host(v.Value)
		case key == "listen":
			v.Value = "127.0.0.1:53"
		case key == "fake-ip-filter" || key == "fallback-filter.domain":
			v.Value = s.domain(v.Value)
		case key == "fallback-filter.ipcidr":
			v.Value = s.cidr(v.Value)
		}
	})
}

func (s *sanitizer) providers(kind string, pp *yaml.Node) {
	single := strings.TrimSuffix(kind, "s")
	for i := 0; i+1 < len(pp.Content); i += 2 {
		pp.Content[i].Value = s.providerRef(single, pp.Content[i].Value)
		id := pp.Content[i].Value
		rewriteLeaves("", pp.Content[i+1], func(path string, v *yaml.Node) {
			switch path {
			case "url":
				v.Value = "https://provider.example/" + id
			case "path":
				v.Value = "./providers/" + id + ".yaml"
			case "proxy", "override.dialer-proxy":
				v.Value = s.ref(v.Value)
			case "payload[]":
				p := splitRule(v.Value)
				if len(p) >= 2 {
					p[1] = s.payload(strings.ToUpper(p[0]), p[1])
					v.Value = strings.Join(p, ",")
				} else {
					v.Value = s.domain(v.Value)
				}
			case "header.<any>":
			default:
				if strings.HasPrefix(path, "header.") || strings.HasPrefix(path, "override.") && v.Tag == "!!str" {
					v.Value = "redacted-" + shortHash(v.Value)
				}
			}
		})
	}
}
