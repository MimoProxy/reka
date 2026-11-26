package importer

import (
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

func (c *converter) convertWireGuard(r *proxyReader, out object) {
	if get(r.n, "amnezia-wg-option") != nil {
		r.fail("amnezia-wg-option", "import.wireguard.amnezia", "AmneziaWG is not supported")
		return
	}
	peer := r
	if peers := get(r.n, "peers"); peers != nil {
		if peers.Kind != yaml.SequenceNode || len(peers.Content) > 1 {
			r.fail("peers", "import.wireguard.peers", "expected a list with at most one WireGuard peer")
			return
		}
		if len(peers.Content) == 1 {
			n := deref(peers.Content[0])
			if n.Kind != yaml.MappingNode {
				r.fail("peers", "import.wireguard.peers", "expected a WireGuard peer mapping")
				return
			}
			peer = &proxyReader{c: c, n: n, path: r.path + "/peers/#0"}
		}
	}
	allowed := map[string]bool{"name": true, "type": true, "peers": true, "ip": true, "ipv6": true, "private-key": true, "udp": true, "mtu": true, "persistent-keepalive": true}
	peerFields := map[string]bool{"server": true, "port": true, "public-key": true, "pre-shared-key": true, "allowed-ips": true, "reserved": true}
	for key := range peerFields {
		allowed[key] = true
	}
	if peer != r {
		for i := 0; i+1 < len(peer.n.Content); i += 2 {
			key := peer.n.Content[i].Value
			if !peerFields[key] {
				peer.fail(key, "import.unsupported-field", "unknown WireGuard peer option")
			}
		}
	}
	c.convertDialer(r, out, allowed)
	for i := 0; i+1 < len(r.n.Content); i += 2 {
		key := r.n.Content[i].Value
		switch key {
		case "remote-dns-resolve", "dns", "refresh-server-ip-interval", "workers", "ip-stack":
			path := model.JoinPath(r.path, key)
			c.report.Ignored = append(c.report.Ignored, path)
			c.diag(r.n.Content[i+1], path, "import.ignored-field", "WireGuard option was ignored", false)
		default:
			if !allowed[key] {
				r.fail(key, "import.unsupported-field", "unsupported WireGuard option")
			}
		}
	}
	out["server"], out["port"], out["udp"] = peer.str("server"), peer.port(), r.boolean("udp", false)
	protocol := object{"private-key": r.str("private-key"), "public-key": peer.str("public-key")}
	out["protocol"] = protocol
	if get(peer.n, "pre-shared-key") != nil {
		protocol["pre-shared-key"] = peer.str("pre-shared-key")
	}
	for _, key := range []string{"mtu", "persistent-keepalive"} {
		if get(r.n, key) != nil {
			protocol[key] = r.number(key, 0)
		}
	}
	addresses := []string{}
	for _, key := range []string{"ip", "ipv6"} {
		address := r.str(key)
		if address == "" {
			continue
		}
		if !strings.Contains(address, "/") {
			if key == "ip" {
				address += "/32"
			} else {
				address += "/128"
			}
		}
		prefix, err := netip.ParsePrefix(address)
		if err != nil || prefix.Addr().Is4() != (key == "ip") {
			r.fail(key, "import.wireguard.address", "expected an address or prefix of the specified IP family")
			continue
		}
		addresses = append(addresses, prefix.String())
	}
	protocol["address"] = addresses
	if ips := get(peer.n, "allowed-ips"); ips != nil {
		var prefixes []string
		if ips.Kind != yaml.SequenceNode || ips.Decode(&prefixes) != nil {
			peer.fail("allowed-ips", "import.wireguard.allowed-ips", "expected a list of IP prefixes")
		} else {
			protocol["allowed-ips"] = prefixes
		}
	}
	// The reference bind uses top-level reserved bytes until a peer overrides them.
	if n := get(r.n, "reserved"); n != nil {
		protocol["reserved"] = wireGuardReserved(r, n)
	}
	if n := get(peer.n, "reserved"); peer != r && n != nil {
		if values := wireGuardReserved(peer, n); len(values) > 0 {
			protocol["reserved"] = values
		}
	}
	r.bad = r.bad || peer.bad
}

func wireGuardReserved(r *proxyReader, n *yaml.Node) []int {
	values := []int{}
	var items []string
	base := 0
	switch {
	case n.Kind == yaml.SequenceNode:
		for _, item := range n.Content {
			item = deref(item)
			if item.Kind != yaml.ScalarNode || (item.Tag != "!!int" && item.Tag != "!!str") {
				r.fail("reserved", "import.wireguard.reserved", "reserved values must be bytes")
				return nil
			}
			items = append(items, item.Value)
		}
	case n.Kind == yaml.ScalarNode && n.Tag == "!!str":
		if strings.Contains(n.Value, ",") {
			base, items = 10, strings.Split(n.Value, ",")
		} else {
			decoded, err := base64.StdEncoding.DecodeString(n.Value)
			if err != nil {
				r.fail("reserved", "import.wireguard.reserved", "invalid base64 reserved bytes")
				return nil
			}
			for _, value := range decoded {
				values = append(values, int(value))
			}
		}
	default:
		r.fail("reserved", "import.wireguard.reserved", "expected a byte list, base64 string or comma-separated bytes")
		return nil
	}
	for _, item := range items {
		value, err := strconv.ParseUint(strings.TrimSpace(item), base, 8)
		if err != nil {
			r.fail("reserved", "import.wireguard.reserved", "reserved values must be bytes")
			return nil
		}
		values = append(values, int(value))
	}
	if len(values) != 0 && len(values) != 3 {
		r.fail("reserved", "import.wireguard.reserved", "reserved must contain zero or three bytes")
		return nil
	}
	return values
}
