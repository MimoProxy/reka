package importer

import (
	"encoding/base64"
	"fmt"
	"iter"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

func decodeBase64(s string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := encoding.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}
func isLink(s string) bool {
	scheme, _, ok := strings.Cut(strings.TrimSpace(s), "://")
	return ok && scheme != "" && !strings.ContainsAny(scheme, " \t\r\n:{}[]")
}
func firstContentLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}
func detectFormat(s string) string {
	trimmed := strings.TrimSpace(s)
	for raw := range strings.SplitSeq(strings.TrimPrefix(trimmed, "\ufeff"), "\n") {
		if line := wireGuardConfContent(raw); line != "" {
			if strings.EqualFold(line, "[Interface]") {
				return "wireguard"
			}
			break
		}
	}
	if isLink(firstContentLine(trimmed)) {
		return "links"
	}
	if b, err := decodeBase64(strings.Join(strings.Fields(trimmed), "")); err == nil && isLink(firstContentLine(string(b))) {
		return "links"
	}
	return "clash"
}
func (c *converter) links(data string) {
	if !isLink(firstContentLine(data)) {
		if b, err := decodeBase64(strings.Join(strings.Fields(data), "")); err == nil {
			data = string(b)
		}
	}
	type entry struct {
		node *yaml.Node
		path string
	}
	entries := []entry{}
	mieruNames := make(map[string]int)
	expandedBytes := 0
	for i, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		path := fmt.Sprintf("/links/#%d", i)
		at := &yaml.Node{Line: i + 1, Column: 1}
		nodes, err := parseLink(line)
		if err != nil {
			c.report.Nodes.Total++
			c.unsupported(at, path, "import.link", "invalid or unsupported share-link parameters")
			continue
		}
		for values := range nodes {
			c.report.Nodes.Total++
			name, _ := values["name"].(string)
			count, previousMieru := mieruNames[name]
			if values["type"] == model.OutboundMieru || previousMieru {
				// mihomo suffixes repeated share-link names with -01, -02, ...
				for candidate := name; c.names[candidate] != ""; {
					count++
					candidate = fmt.Sprintf("%s-%02d", name, count)
					values["name"] = candidate
				}
				mieruNames[name] = count
			}
			n := &yaml.Node{}
			if err := n.Encode(values); err != nil {
				c.unsupported(at, path, "import.link", "invalid share-link fields")
				continue
			}
			expandedBytes += markLinkPosition(n, i+1)
			// One Mieru URL can repeat a long profile or credential for every port.
			if expandedBytes > model.MaxDocumentSize {
				c.diag(at, path, "import.size", "expanded links exceed the document size limit", true)
				return
			}
			if c.register(n, "p", path) {
				entries = append(entries, entry{n, path})
			}
		}
	}
	if c.fatal {
		return
	}
	for _, e := range entries {
		c.convertProxy(e.node, e.path)
	}
}

func markLinkPosition(n *yaml.Node, line int) int {
	n.Line, n.Column = line, 1
	size := len(n.Value)
	for _, child := range n.Content {
		size += markLinkPosition(child, line)
	}
	return size
}

func parseLink(raw string) (iter.Seq[object], error) {
	scheme, _, _ := strings.Cut(raw, "://")
	if strings.EqualFold(scheme, "mierus") {
		return parseMieruLink(raw)
	}
	node, err := parseSingleLink(raw)
	if err != nil {
		return nil, err
	}
	return slices.Values([]object{node}), nil
}

func parseSingleLink(raw string) (object, error) {
	if strings.HasPrefix(raw, "vmess://") {
		return parseVMessLink(raw)
	}
	// SIP002 also permits a complete base64 authority, with the label outside.
	if strings.HasPrefix(raw, "ss://") {
		authority, label, _ := strings.Cut(strings.TrimPrefix(raw, "ss://"), "#")
		if !strings.Contains(authority, "@") {
			b, err := decodeBase64(authority)
			if err != nil {
				return nil, err
			}
			raw = "ss://" + string(b)
			if label != "" {
				raw += "#" + label
			}
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.User == nil && u.Scheme != "hysteria") {
		return nil, fmt.Errorf("invalid link")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("unexpected path")
	}
	portText := u.Port()
	if portText == "" && (u.Scheme == "hysteria2" || u.Scheme == "hy2") {
		portText = "443"
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port")
	}
	name := u.Fragment
	if u.Scheme == "anytls" && name == "" {
		name = u.Hostname() + ":" + portText
	} else if strings.TrimSpace(name) == "" {
		name = u.Scheme + "@" + u.Host
	}
	out := object{"name": name, "type": u.Scheme, "server": u.Hostname(), "port": port, "udp": true}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("invalid query")
	}
	for _, v := range query {
		if len(v) != 1 {
			return nil, fmt.Errorf("duplicate query")
		}
	}
	switch u.Scheme {
	case "ss":
		method := u.User.Username()
		password, plain := u.User.Password()
		if !plain {
			b, err := decodeBase64(method)
			if err != nil {
				return nil, err
			}
			var ok bool
			method, password, ok = strings.Cut(string(b), ":")
			if !ok {
				return nil, fmt.Errorf("missing password")
			}
		}
		out["cipher"], out["password"] = method, password
		for key := range query {
			switch key {
			case "plugin":
				if query.Get(key) != "" {
					name, options, err := ssLinkPlugin(query.Get(key))
					if err != nil {
						return nil, err
					}
					out["plugin"], out["plugin-opts"] = name, options
				}
			case "client-fingerprint":
				out[key] = query.Get(key)
			case "udp-over-tcp":
				flag, err := strconv.ParseBool(query.Get(key))
				if err != nil {
					return nil, fmt.Errorf("invalid UDP-over-TCP flag")
				}
				out["udp-over-tcp"] = flag
			case "uot":
				if query.Get(key) != "0" && query.Get(key) != "1" {
					return nil, fmt.Errorf("invalid UoT flag")
				}
				if query.Get(key) == "1" {
					out["udp-over-tcp"] = true
				}
			case "udp-over-tcp-version":
				version, err := strconv.Atoi(query.Get(key))
				if err != nil {
					return nil, fmt.Errorf("invalid UoT version")
				}
				out[key] = version
			default:
				return nil, fmt.Errorf("unknown SS option")
			}
		}
		if query.Get("uot") == "1" {
			out["udp-over-tcp"] = true
		}
	case "vless":
		if _, hasPassword := u.User.Password(); hasPassword {
			return nil, fmt.Errorf("invalid VLESS user")
		}
		out["uuid"] = u.User.Username()
		known := map[string]bool{"security": true, "type": true, "flow": true, "encryption": true, "packetEncoding": true, "fp": true, "sni": true, "pbk": true, "sid": true, "support-x25519mlkem768": true, "allowInsecure": true, "alpn": true, "path": true, "host": true, "serviceName": true}
		for key := range query {
			if !known[key] {
				return nil, fmt.Errorf("unknown VLESS option")
			}
		}
		for from, to := range map[string]string{"type": "network", "flow": "flow", "encryption": "encryption", "packetEncoding": "packet-encoding", "fp": "client-fingerprint", "sni": "servername"} {
			if v := query.Get(from); v != "" {
				out[to] = v
			}
		}
		linkTransport(out, query)
		security := query.Get("security")
		switch security {
		case "", "none":
		case "tls", "reality":
			out["tls"] = true
		default:
			return nil, fmt.Errorf("unsupported security")
		}
		if v := query.Get("alpn"); v != "" {
			out["alpn"] = strings.Split(v, ",")
		}
		if v := query.Get("allowInsecure"); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, err
			}
			out["skip-cert-verify"] = b
		}
		if security == "reality" {
			reality := object{"public-key": query.Get("pbk"), "short-id": query.Get("sid")}
			if v := query.Get("support-x25519mlkem768"); v != "" {
				b, err := strconv.ParseBool(v)
				if err != nil {
					return nil, err
				}
				reality["support-x25519mlkem768"] = b
			}
			out["reality-opts"] = reality
		} else if query.Get("pbk") != "" || query.Get("sid") != "" || query.Get("support-x25519mlkem768") != "" {
			return nil, fmt.Errorf("REALITY parameters need security=reality")
		}
	case "hysteria":
		if err := parseHysteriaLink(out, query); err != nil {
			return nil, err
		}
	case "trojan", "hysteria2", "hy2", "tuic":
		if err := parseSecureLink(u, out, query); err != nil {
			return nil, err
		}
	case "anytls":
		for key := range query {
			switch key {
			case "sni", "insecure", "hpkp":
			default:
				return nil, fmt.Errorf("unknown AnyTLS option")
			}
		}
		// mihomo uses the password component when present, and otherwise the username.
		password, ok := u.User.Password()
		if !ok {
			password = u.User.Username()
		}
		out["password"] = password
		out["sni"] = query.Get("sni")
		out["skip-cert-verify"] = query.Get("insecure") == "1"
		out["fingerprint"] = query.Get("hpkp")
	default:
		return nil, fmt.Errorf("unsupported scheme")
	}
	return out, nil
}
