package importer

import (
	"errors"
	"iter"
	"maps"
	"net/url"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
)

func (c *converter) convertMieru(r *proxyReader, out object) {
	allowed := map[string]bool{
		"name": true, "type": true, "server": true, "port": true, "port-range": true, "udp": true,
		"username": true, "password": true, "transport": true, "multiplexing": true,
		"handshake-mode": true, "traffic-pattern": true,
	}
	c.convertDialer(r, out, allowed)
	for i := 0; i+1 < len(r.n.Content); i += 2 {
		key := r.n.Content[i].Value
		if !allowed[key] {
			r.fail(key, "import.unsupported-field", "unsupported Mieru option")
		}
	}
	if dialer, ok := out["dialer"].(object); ok {
		for _, key := range []string{"tfo", "mptcp"} {
			if dialer[key] == true {
				r.fail(key, "import.unsupported-field", "Mieru does not support "+key)
			}
		}
	}
	out["server"], out["udp"] = r.str("server"), r.boolean("udp", false)
	out["username"], out["password"] = r.str("username"), r.str("password")
	p := object{"transport": r.str("transport")}
	out["protocol"] = p
	if ports := r.str("port-range"); ports != "" {
		if !strings.Contains(ports, "-") {
			r.fail("port-range", "import.port", "Mieru port-range must be a single begin-end range")
		}
		p["server-ports"] = []string{ports}
	}
	if get(r.n, "port") != nil || p["server-ports"] == nil {
		out["port"] = r.port()
	}
	for _, key := range []string{"multiplexing", "handshake-mode", "traffic-pattern"} {
		if value := r.str(key); value != "" {
			p[key] = value
		}
	}
}

func parseMieruLink(raw string) (iter.Seq[object], error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("invalid Mieru link")
	}
	query := u.Query()
	baseName := u.Fragment
	if baseName == "" {
		baseName = query.Get("profile")
	}
	if baseName == "" {
		baseName = u.Hostname()
	}
	password, _ := u.User.Password()
	common := object{"type": model.OutboundMieru, "server": u.Hostname(), "username": u.User.Username(), "password": password, "udp": true}
	for _, key := range []string{"multiplexing", "handshake-mode", "traffic-pattern"} {
		if value := query.Get(key); value != "" {
			common[key] = value
		}
	}
	ports, protocols := query["port"], query["protocol"]
	return func(yield func(object) bool) {
		if len(ports) != len(protocols) {
			return
		}
		for i, port := range ports {
			node := maps.Clone(common)
			if strings.Contains(port, "-") {
				node["port-range"] = port
			} else {
				value, err := strconv.Atoi(port)
				if err != nil {
					continue
				}
				node["port"] = value
			}
			node["name"] = baseName + ":" + port + "/" + protocols[i]
			node["transport"] = protocols[i]
			if !yield(node) {
				return
			}
		}
	}, nil
}
