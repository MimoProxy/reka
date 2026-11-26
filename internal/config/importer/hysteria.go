package importer

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

// mihomo's proxy decoder treats underscores in option names as hyphens.
func (c *converter) normalizeHysteriaKeys(n *yaml.Node, path string) bool {
	if n.Kind != yaml.MappingNode {
		return true
	}
	seen := make(map[string]bool)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i]
		name := strings.ReplaceAll(key.Value, "_", "-")
		fieldPath := model.JoinPath(path, key.Value)
		if seen[name] {
			c.diag(key, fieldPath, "import.duplicate-key", "duplicate Hysteria option after replacing underscores with hyphens", true)
			return false
		}
		key.Value = name
		seen[name] = true
		if name == "ech-opts" && !c.normalizeHysteriaKeys(n.Content[i+1], fieldPath) {
			return false
		}
	}
	return true
}

func (r *proxyReader) hysteriaPorts(ports string, p object) {
	ranges, err := model.PortHops(ports)
	if err != nil {
		r.fail("ports", "import.ports", err.Error())
		return
	}
	p["server-ports"] = ranges
}

func (r *proxyReader) hysteria(out, p object) {
	ignore := func(key string) {
		if get(r.n, key) != nil {
			r.c.report.Ignored = append(r.c.report.Ignored, model.JoinPath(r.path, key))
		}
	}
	if auth := r.str("auth"); auth != "" {
		if _, err := base64.StdEncoding.DecodeString(auth); err != nil {
			r.fail("auth", "import.hysteria.auth", "auth must be standard base64")
		}
		p["auth-base64"] = auth
		ignore("auth-str")
	} else if password := r.str("auth-str"); password != "" {
		out["password"] = password
	}
	for _, key := range []string{"up", "down"} {
		// mihomo validates both base speeds before applying the Stash overrides.
		rate, err := model.BandwidthBytes(r.str(key))
		if err != nil {
			r.fail(key, "import.bandwidth", err.Error())
			continue
		}
		if rate == 0 {
			r.fail(key, "import.bandwidth", "Hysteria requires a positive bandwidth in each direction")
			continue
		}
		override := key + "-speed"
		if speed := r.number(override, 0); speed != 0 {
			if speed < 0 || speed > math.MaxInt/model.HysteriaBytesPerMbps {
				r.fail(override, "import.bandwidth", "speed must be positive and fit in bytes per second")
				continue
			}
			rate = uint64(speed * model.HysteriaBytesPerMbps)
		}
		if rate < model.HysteriaMinSpeedBPS {
			r.fail(key, "import.bandwidth", fmt.Sprintf("Hysteria requires at least %d bytes per second", model.HysteriaMinSpeedBPS))
			continue
		}
		p[key+"-bps"] = rate
	}
	protocolKey := "protocol"
	if r.str("obfs-protocol") != "" {
		protocolKey = "obfs-protocol"
		ignore("protocol")
	}
	if protocol := r.str(protocolKey); protocol != "" && protocol != "udp" {
		r.fail(protocolKey, "import.unsupported-field", "Hysteria only supports udp")
	}
	if password := r.str("obfs"); password != "" {
		p["obfs"] = object{"type": "xplus", "password": password}
	}
	if ports := r.str("ports"); ports != "" {
		r.hysteriaPorts(ports, p)
		interval := r.number("hop-interval", 0)
		if interval == 0 {
			interval = 10 // mihomo's DefaultHopInterval for Hysteria, in seconds.
		}
		p["hop-interval-seconds"] = interval
	} else {
		ignore("hop-interval")
	}
	if window := r.number("recv-window", 0); window != 0 {
		p["connection-receive-window"] = window
		if stream := r.number("recv-window-conn", 0); stream != 0 {
			p["stream-receive-window"] = stream
		}
	} else {
		// mihomo resets both windows when the connection window is zero.
		ignore("recv-window-conn")
	}
	if get(r.n, "disable-mtu-discovery") != nil {
		p["disable-mtu-discovery"] = r.optionalBool("disable-mtu-discovery")
	}
	r.optionalBool("fast-open") // sing-quic always sends the request with the first write.
	ignore("ca")
	ignore("ca-str")
	ignore("tls") // Hysteria always enables TLS.
}
