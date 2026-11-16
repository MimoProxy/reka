package compile

import (
	"fmt"
	"github.com/MimoProxy/reka/internal/config/model"
	"golang.org/x/net/http/httpguts"
	"slices"
	"strings"
)

func (c *compiler) protocol(base string, ob model.Outbound, out *Outbound) {
	fail := func(field, message string) {
		c.errorf(model.DocProfile, base+"/"+field, "outbound.protocol", "%s", message)
	}
	if ob.Type == "vmess" && !slices.Contains([]string{"", "xudp", "packetaddr"}, ob.PacketEncoding) {
		fail("packet-encoding", "unsupported VMess packet encoding")
	}
	if ob.Type == "vmess" || ob.Type == "tuic" {
		if !uuidRE.MatchString(out.UUID) && !c.hasErrorAt(base+"/uuid") {
			fail("uuid", "a valid UUID is required")
		}
	}
	if slices.Contains([]string{"trojan", "hysteria2", "tuic", "snell"}, ob.Type) && out.Password == "" && !c.hasErrorAt(base+"/password") {
		fail("password", "password is required")
	}
	if (ob.Type == "hysteria2" || ob.Type == "tuic") && ob.TLS != nil && ob.TLS.Fingerprint != "" {
		fail("tls/fingerprint", "QUIC does not use a TCP ClientHello fingerprint")
	}
	if slices.Contains([]string{"trojan", "hysteria2", "tuic"}, ob.Type) && ob.TLS == nil {
		fail("tls", "this protocol requires TLS")
	}
	if ob.Protocol != nil {
		p := *ob.Protocol
		p.ServerPorts = slices.Clone(p.ServerPorts)
		allowed := map[string][]string{"vmess": {"security", "alter-id"}, "hysteria2": {"up-mbps", "down-mbps", "obfs", "server-ports", "hop-interval-seconds", "hop-interval-max-seconds"}, "tuic": {"congestion-control", "udp-relay-mode", "zero-rtt", "heartbeat"}, "snell": {"version", "user-key", "mode", "reuse", "obfs"}}
		for _, field := range c.present(base + "/protocol") {
			if !slices.Contains(allowed[ob.Type], field) {
				fail("protocol/"+field, "option does not apply to protocol")
			}
		}
		if p.AlterID < 0 || p.AlterID > 65535 || p.UpMbps < 0 || p.DownMbps < 0 || p.Heartbeat < 0 {
			fail("protocol", "invalid protocol numeric option")
		}
		if ob.Type == "vmess" && !slices.Contains([]string{"", "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"}, p.Security) {
			fail("protocol/security", "unsupported VMess cipher")
		}
		if ob.Type == "hysteria2" {
			if len(p.ServerPorts) > 1024 {
				fail("protocol/server-ports", "too many port ranges")
			}
			for _, v := range p.ServerPorts {
				parts := strings.Split(v, ":")
				if len(parts) != 2 {
					fail("protocol/server-ports", "expected explicit start:end port range")
					continue
				}
				ranges, err := model.PortHops(strings.Join(parts, "-"))
				if err != nil || len(ranges) != 1 || ranges[0] != v {
					fail("protocol/server-ports", "invalid port range")
				}
			}
			if p.HopInterval < 0 || p.HopInterval > 86400 || p.HopIntervalMax < 0 || p.HopIntervalMax > 86400 || p.HopIntervalMax != 0 && p.HopIntervalMax < p.HopInterval {
				fail("protocol/hop-interval-seconds", "invalid hop interval")
			}
		}
		if ob.Type == "tuic" {
			if !slices.Contains([]string{"", "cubic", "new_reno", "bbr"}, p.Congestion) {
				fail("protocol/congestion-control", "unsupported congestion control")
			}
			if !slices.Contains([]string{"", "native", "quic"}, p.UDPMode) {
				fail("protocol/udp-relay-mode", "unsupported UDP mode")
			}
		}
		if ob.Type == "snell" {
			if p.Version == 5 && p.Mode != "" {
				fail("protocol/mode", "mode only applies to Snell 6")
			}
			if p.Version != 5 && p.Version != 6 {
				fail("protocol/version", "Snell requires version 5 or 6")
			}
			if !slices.Contains([]string{"", "default", "unshaped", "unsafe-raw"}, p.Mode) {
				fail("protocol/mode", "invalid Snell mode")
			}
			p.UserKey = c.resolveSecret(base+"/protocol/user-key", p.UserKey)
		}
		if p.Obfs != nil {
			copy := *p.Obfs
			p.Obfs = &copy
			p.Obfs.Password = c.resolveSecret(base+"/protocol/obfs/password", p.Obfs.Password)
			if ob.Type == "hysteria2" {
				if p.Obfs.Host != "" {
					fail("protocol/obfs/host", "obfs host only applies to Snell")
				}
				if p.Obfs.Type != "salamander" || p.Obfs.Password == "" && !c.hasErrorAt(base+"/protocol/obfs/password") {
					fail("protocol/obfs", "HY2 obfs requires salamander and password")
				}
			} else if ob.Type == "snell" {
				if p.Obfs.Password != "" {
					fail("protocol/obfs/password", "Snell obfs does not accept a password")
				}
				if p.Version == 6 {
					fail("protocol/obfs", "Snell 6 uses mode, not obfs")
				}
				if !slices.Contains([]string{"", "none", "http", "tls"}, p.Obfs.Type) {
					fail("protocol/obfs", "invalid Snell obfs")
				}
			}
		}
		out.Protocol = &p
	} else if ob.Type == "snell" {
		fail("protocol/version", "Snell version is required")
	}
	if ob.Transport != nil {
		copy := *ob.Transport
		t := &copy
		t.Headers = slices.Clone(t.Headers)
		t.Paths = slices.Clone(t.Paths)
		t.Hosts = slices.Clone(t.Hosts)
		for i := range t.Headers {
			t.Headers[i].Value = c.resolveSecret(fmt.Sprintf("%s/transport/headers/#%d/value", base, i), t.Headers[i].Value)
		}
		out.Transport = t
		allowed := map[string][]string{"ws": {"type", "path", "host", "headers", "max-early-data", "early-data-header"}, "grpc": {"type", "service-name"}, "httpupgrade": {"type", "path", "host", "headers"}, "http": {"type", "paths", "method", "headers", "host"}, "h2": {"type", "hosts", "path"}}
		for _, field := range c.present(base + "/transport") {
			if !slices.Contains(allowed[t.Type], field) {
				fail("transport/"+field, "option does not apply to this transport")
			}
		}
		if ob.TLS != nil && len(ob.TLS.ALPN) > 0 {
			if (t.Type == "grpc" || t.Type == "h2") && !slices.Contains(ob.TLS.ALPN, "h2") {
				fail("tls/alpn", "this transport requires h2")
			}
			if (t.Type == "ws" || t.Type == "httpupgrade" || t.Type == "http") && (len(ob.TLS.ALPN) != 1 || ob.TLS.ALPN[0] != "http/1.1") {
				fail("tls/alpn", "WebSocket/HTTPUpgrade requires http/1.1")
			}
		}

		if !slices.Contains([]string{"ws", "grpc", "httpupgrade", "http", "h2"}, t.Type) {
			fail("transport/type", "unsupported transport")
		}
		if !slices.Contains([]string{"vless", "vmess", "trojan"}, ob.Type) {
			fail("transport", "transport does not apply to protocol")
		}
		if (t.Type == "http" || t.Type == "h2") && ob.Type != "vless" && ob.Type != "vmess" {
			fail("transport", "HTTP and H2 apply to VLESS and VMess")
		}
		if t.Type == "h2" && ob.TLS == nil {
			fail("tls", "H2 requires TLS")
		}
		if t.Method != "" && !httpguts.ValidHeaderFieldName(t.Method) {
			fail("transport/method", "invalid HTTP method")
		}
		for _, path := range t.Paths {
			if strings.ContainsAny(path, "\r\n\x00") {
				fail("transport/paths", "invalid HTTP path")
			}
		}
		if ob.Flow != "" && (out.Encryption == "" || out.Encryption == "none") {
			fail("flow", "Vision without VLESS encryption requires raw TCP")
		}
		if t.EarlyData < 0 || t.EarlyData > 65536 {
			fail("transport/max-early-data", "invalid early data limit")
		}
		for _, h := range t.Headers {
			if !httpguts.ValidHeaderFieldName(h.Name) || !httpguts.ValidHeaderFieldValue(h.Value) {
				fail("transport/headers", "invalid header")
			}
		}
	}
	if ob.Multiplex != nil && ob.Multiplex.Enabled {
		m := ob.Multiplex
		if slices.Contains([]string{"reject", "reject-drop", "pass"}, ob.Type) {
			fail("multiplex", "this action has no transport to multiplex")
		}
		if !slices.Contains([]string{"", "h2mux", "smux", "yamux"}, m.Protocol) || m.MaxConnections < 0 || m.MinStreams < 0 || m.MaxStreams < 0 {
			fail("multiplex", "invalid multiplex options")
		}
		if m.Brutal != nil && m.Brutal.Enabled && (m.Brutal.UpBPS < 65536 || m.Brutal.DownBPS < 65536) {
			fail("multiplex/brutal", "Brutal requires upload and download of at least 65536 bytes/s")
		}
		if m.Statistic {
			c.warnf(model.DocProfile, base+"/multiplex/statistic", "multiplex.statistic", "reference nested accounting is metadata; Reka always reports native per-flow traffic")
		}
	}
}
