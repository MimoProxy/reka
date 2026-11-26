package importer

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

func wireGuardConfContent(raw string) string {
	line, _, _ := strings.Cut(raw, "#")
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, ";") {
		return ""
	}
	return line
}

func (c *converter) wireGuardConf(data string) {
	const path = "/wireguard/#0"
	c.report.Nodes.Total = 1
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	name := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "WireGuard"}
	var peer, section *yaml.Node
	lineNumber := 0
	for raw := range strings.SplitSeq(strings.TrimPrefix(data, "\ufeff"), "\n") {
		lineNumber++
		if comment, ok := strings.CutPrefix(strings.TrimSpace(raw), "#"); ok && n.Line == 0 {
			key, value, ok := strings.Cut(comment, "=")
			if value = strings.TrimSpace(value); ok && strings.EqualFold(strings.TrimSpace(key), "Name") && value != "" {
				name.Value, name.Line, name.Column = value, lineNumber, 1
			}
		}
		line := wireGuardConfContent(raw)
		if line == "" {
			continue
		}
		at := &yaml.Node{Line: lineNumber, Column: 1}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[interface]":
				if n.Line != 0 {
					c.diag(at, path, "import.wireguard.section", "expected only one [Interface] section", true)
					return
				}
				n.Line, n.Column = at.Line, at.Column
				section = n
			case "[peer]":
				if n.Line == 0 {
					c.diag(at, path, "import.wireguard.section", "expected [Interface] before [Peer]", true)
					return
				}
				if peer != nil {
					c.diag(at, path, "import.wireguard.peers", "expected exactly one [Peer] section", true)
					return
				}
				peer = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Line: at.Line, Column: at.Column}
				section = peer
			default:
				c.diag(at, path, "import.wireguard.section", "unknown WireGuard section", true)
				return
			}
			continue
		}
		if section == nil {
			c.diag(at, path, "import.wireguard.section", "expected an [Interface] section", true)
			return
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			c.diag(at, path, "import.wireguard.field", "expected a key = value assignment", true)
			return
		}
		c.wireGuardConfField(n, section, at, path, strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value))
		if c.fatal {
			return
		}
	}
	if n.Line == 0 {
		c.diag(&yaml.Node{Line: 1, Column: 1}, path, "import.wireguard.section", "expected an [Interface] section", true)
		return
	}
	if peer == nil {
		c.diag(n, path, "import.wireguard.peers", "expected exactly one [Peer] section", true)
		return
	}
	if get(peer, "server") == nil {
		c.diag(peer, path+"/endpoint", "import.wireguard.endpoint", "Endpoint is required in [Peer]", true)
		return
	}
	if name.Line == 0 {
		name.Line, name.Column = n.Line, n.Column
	}
	putField(n, "name", name)
	putField(n, "type", wireGuardConfScalar(n, "wireguard"))
	putField(n, "udp", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true", Line: n.Line, Column: n.Column})
	putField(n, "peers", &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{peer}, Line: peer.Line, Column: peer.Column})
	if c.register(n, "p", path) {
		c.convertProxy(n, path)
	}
}

func (c *converter) wireGuardConfField(n, section, at *yaml.Node, path, key, value string) {
	if section == n {
		switch key {
		case "privatekey":
			putField(n, "private-key", wireGuardConfScalar(at, value))
			return
		case "address":
			appendWireGuardConfList(n, at, "address", value)
			return
		case "mtu":
			putField(n, "mtu", wireGuardConfScalar(at, value))
			return
		case "dns", "listenport", "table", "fwmark", "saveconfig", "preup", "postup", "predown", "postdown":
			path = model.JoinPath(path, key)
			message := "WireGuard option was ignored"
			switch key {
			case "preup", "postup", "predown", "postdown":
				message = "WireGuard script was ignored and will not be executed"
			}
			c.report.Ignored = append(c.report.Ignored, path)
			c.diag(at, path, "import.ignored-field", message, false)
			return
		}
	} else {
		switch key {
		case "publickey":
			putField(section, "public-key", wireGuardConfScalar(at, value))
			return
		case "presharedkey":
			putField(section, "pre-shared-key", wireGuardConfScalar(at, value))
			return
		case "allowedips":
			appendWireGuardConfList(section, at, "allowed-ips", value)
			return
		case "endpoint":
			host, port, err := net.SplitHostPort(value)
			if err != nil || host == "" || port == "" {
				c.diag(at, path+"/endpoint", "import.wireguard.endpoint", "expected an Endpoint with a host and port", true)
				return
			}
			putField(section, "server", wireGuardConfScalar(at, host))
			putField(section, "port", wireGuardConfScalar(at, port))
			return
		case "persistentkeepalive":
			if strings.EqualFold(value, "off") {
				value = "0"
			}
			putField(n, "persistent-keepalive", wireGuardConfScalar(at, value))
			return
		}
	}
	c.diag(at, model.JoinPath(path, key), "import.unsupported-field", "unknown WireGuard option", true)
}

func wireGuardConfScalar(at *yaml.Node, value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Line: at.Line, Column: at.Column}
}

func appendWireGuardConfList(n, at *yaml.Node, key, value string) {
	list := get(n, key)
	if list == nil {
		list = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Line: at.Line, Column: at.Column}
		putField(n, key, list)
	}
	for item := range strings.SplitSeq(value, ",") {
		item = strings.TrimSpace(item)
		if key == "address" {
			if addr, err := netip.ParseAddr(item); err == nil && addr.Zone() == "" {
				item = netip.PrefixFrom(addr, addr.BitLen()).String()
			}
		}
		list.Content = append(list.Content, wireGuardConfScalar(at, item))
	}
}

// Compiler paths refer to the native outbound, including nested protocol fields.
// The conversion nodes still carry the source line of each original value.
func wireGuardConfDiagnosticNode(n *yaml.Node, path string) *yaml.Node {
	path = strings.TrimPrefix(strings.TrimPrefix(path, "/protocol"), "/")
	field, item, _ := strings.Cut(path, "/")
	switch field {
	case "server", "port", "public-key", "pre-shared-key", "allowed-ips":
		n = get(n, "peers").Content[0]
	}
	at := get(n, field)
	if at == nil {
		return n
	}
	if index, err := strconv.Atoi(strings.TrimPrefix(item, "#")); err == nil && at.Kind == yaml.SequenceNode && index >= 0 && index < len(at.Content) {
		return at.Content[index]
	}
	return at
}
