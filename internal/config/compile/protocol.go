package compile

import (
	"encoding/base64"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"golang.org/x/net/http/httpguts"
)

var protocolFields = map[string][]string{
	model.OutboundSSR:       {"obfs", "protocol", "protocol-param"},
	"vmess":                 {"security", "alter-id"},
	"anytls":                {"idle-session-check-interval-seconds", "idle-session-timeout-seconds", "min-idle-session", "client-metadata"},
	"hysteria":              {"auth-base64", "up-mbps", "down-mbps", "up-bps", "down-bps", "obfs", "server-ports", "hop-interval-seconds", "stream-receive-window", "connection-receive-window", "disable-mtu-discovery"},
	"hysteria2":             {"up-mbps", "down-mbps", "obfs", "server-ports", "hop-interval-seconds", "hop-interval-max-seconds", "up-bps", "down-bps", "realm"},
	"tuic":                  {"congestion-control", "udp-relay-mode", "zero-rtt", "heartbeat"},
	"snell":                 {"version", "user-key", "mode", "reuse", "obfs"},
	model.OutboundSSH:       {"private-key", "private-key-passphrase", "host-key", "host-key-algorithms", "client-version", "insecure-skip-host-key"},
	model.OutboundMieru:     {"transport", "multiplexing", "handshake-mode", "traffic-pattern", "server-ports"},
	model.OutboundWireGuard: {"private-key", "public-key", "pre-shared-key", "address", "allowed-ips", "persistent-keepalive", "reserved", "mtu"},
}

func (c *compiler) protocol(base string, ob model.Outbound, out *Outbound) {
	fail := func(field, message string) {
		c.errorf(model.DocProfile, base+"/"+field, "outbound.protocol", "%s", message)
	}
	if ob.Protocol != nil {
		for _, field := range c.present(base + "/protocol") {
			if !slices.Contains(protocolFields[ob.Type], field) {
				fail("protocol/"+field, "option does not apply to protocol")
			}
		}
		if _, present := c.ppos[base+"/protocol/obfs/param"]; present && ob.Type != model.OutboundSSR {
			fail("protocol/obfs/param", "obfs param does not apply to this protocol")
		}
	}
	if ob.Type == model.OutboundSSR {
		c.ssr(base, ob, out)
		return
	}
	if ob.Type == model.OutboundSSH {
		c.ssh(base, ob.Protocol, out)
		return
	}
	if ob.Type == model.OutboundMieru {
		c.mieru(base, ob.Protocol, out)
		return
	}
	if ob.Type == model.OutboundWireGuard {
		if _, present := c.ppos[base+"/multiplex"]; present {
			fail("multiplex", "multiplex does not apply to WireGuard")
		}
		p := model.Protocol{}
		if ob.Protocol != nil {
			p = *ob.Protocol
		}
		c.wireGuard(base+"/protocol", &p)
		out.Protocol = &p
		return
	}
	if ob.Type == "vmess" && !slices.Contains([]string{"", "xudp", "packetaddr"}, ob.PacketEncoding) {
		fail("packet-encoding", "unsupported VMess packet encoding")
	}
	if ob.Type == "vmess" || ob.Type == "tuic" {
		if !uuidRE.MatchString(out.UUID) && !c.hasErrorAt(base+"/uuid") {
			fail("uuid", "a valid UUID is required")
		}
	}
	if slices.Contains([]string{"trojan", "anytls", "hysteria2", "tuic", "snell"}, ob.Type) && out.Password == "" && !c.hasErrorAt(base+"/password") {
		fail("password", "password is required")
	}
	if slices.Contains([]string{"hysteria", "hysteria2", "tuic"}, ob.Type) && ob.TLS != nil && ob.TLS.Fingerprint != "" {
		fail("tls/fingerprint", "QUIC does not use a TCP ClientHello fingerprint")
	}
	if slices.Contains([]string{"trojan", "anytls", "hysteria", "hysteria2", "tuic"}, ob.Type) && ob.TLS == nil {
		fail("tls", "this protocol requires TLS")
	}
	if ob.Type == "hysteria" && ob.Protocol == nil {
		fail("protocol", "Hysteria requires upload and download bandwidth")
	}
	if ob.Protocol != nil {
		p := *ob.Protocol
		p.ServerPorts = slices.Clone(p.ServerPorts)
		if p.AlterID < 0 || p.AlterID > 65535 || p.UpMbps < 0 || p.DownMbps < 0 || p.Heartbeat < 0 {
			fail("protocol", "invalid protocol numeric option")
		}
		if ob.Type == "vmess" && !slices.Contains([]string{"", "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"}, p.Security) {
			fail("protocol/security", "unsupported VMess cipher")
		}
		if ob.Type == "anytls" {
			if p.IdleSessionCheckIntervalSeconds < 0 || p.IdleSessionCheckIntervalSeconds > 86400 {
				fail("protocol/idle-session-check-interval-seconds", "idle session check interval must be between 0 and 86400 seconds")
			}
			if p.IdleSessionTimeoutSeconds < 0 || p.IdleSessionTimeoutSeconds > 86400 {
				fail("protocol/idle-session-timeout-seconds", "idle session timeout must be between 0 and 86400 seconds")
			}
			if p.MinIdleSession < 0 || p.MinIdleSession > 64 {
				fail("protocol/min-idle-session", "minimum idle sessions must be between 0 and 64")
			}
		}
		if ob.Type == "hysteria" || ob.Type == "hysteria2" {
			if p.UpMbps > math.MaxInt/model.HysteriaBytesPerMbps || p.DownMbps > math.MaxInt/model.HysteriaBytesPerMbps {
				fail("protocol", "legacy Mbps rate overflows; use exact bytes/s")
			}
			if p.UpBPS != nil && p.UpMbps != 0 || p.DownBPS != nil && p.DownMbps != 0 {
				fail("protocol", "choose bytes/s or legacy Mbps for each direction")
			}
			if ob.Type == "hysteria" {
				c.hysteriaOptions(base, &p)
			} else {
				c.realm(base+"/protocol/realm", &p)
			}
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
			if ob.Type == "hysteria" {
				for _, field := range c.present(base + "/protocol/obfs") {
					if field != "type" && field != "password" {
						fail("protocol/obfs/"+field, "option does not apply to XPlus obfs")
					}
				}
				if p.Obfs.Type != "xplus" {
					fail("protocol/obfs/type", "Hysteria requires xplus obfs")
				}
				if p.Obfs.Password == "" && !c.hasErrorAt(base+"/protocol/obfs/password") {
					fail("protocol/obfs/password", "XPlus obfs requires a password")
				}
			} else if ob.Type == "hysteria2" {
				if p.Obfs.Host != "" {
					fail("protocol/obfs/host", "obfs host only applies to Snell")
				}
				if !slices.Contains([]string{"salamander", "gecko"}, p.Obfs.Type) || p.Obfs.Password == "" && !c.hasErrorAt(base+"/protocol/obfs/password") {
					fail("protocol/obfs", "HY2 obfs requires salamander or gecko and password")
				}
				if p.Obfs.Type == "gecko" {
					lo, hi := p.Obfs.MinPacketSize, p.Obfs.MaxPacketSize
					if lo == 0 {
						lo = 512
					}
					if hi == 0 {
						hi = 1200
					}
					if lo < 1 || lo > hi || hi > 2048 {
						fail("protocol/obfs", "gecko packet sizes must satisfy 1 <= min <= max <= 2048")
					}
				} else if p.Obfs.MinPacketSize != 0 || p.Obfs.MaxPacketSize != 0 {
					fail("protocol/obfs", "packet size options require gecko")
				}
			} else if ob.Type == "snell" {
				if p.Obfs.MinPacketSize != 0 || p.Obfs.MaxPacketSize != 0 {
					fail("protocol/obfs", "packet size options only apply to HY2 gecko")
				}
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
		allowed := map[string][]string{"ws": {"type", "path", "host", "headers", "max-early-data", "early-data-header"}, "grpc": {"type", "service-name"}, "httpupgrade": {"type", "path", "host", "headers"}, "http": {"type", "paths", "method", "headers", "host"}, "h2": {"type", "hosts", "path"}, "xhttp": {"type", "host", "path", "headers", "xhttp"}}
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

		if !slices.Contains([]string{"ws", "grpc", "httpupgrade", "http", "h2", "xhttp"}, t.Type) {
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
		if t.Type == "xhttp" {
			c.xhttp(base, ob, out)
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

func (c *compiler) hysteriaOptions(base string, p *model.Protocol) {
	path := base + "/protocol"
	fail := func(field, message string) {
		c.errorf(model.DocProfile, path+"/"+field, "outbound.protocol", "%s", message)
	}
	checkBandwidth := func(direction string, exact *uint64, mbps int) {
		if exact == nil && mbps == 0 {
			fail(direction+"-bps", fmt.Sprintf("Hysteria requires %s-bps or %s-mbps", direction, direction))
		} else if exact != nil && *exact < model.HysteriaMinSpeedBPS {
			fail(direction+"-bps", fmt.Sprintf("bandwidth must be at least %d bytes/s", model.HysteriaMinSpeedBPS))
		}
	}
	checkBandwidth("up", p.UpBPS, p.UpMbps)
	checkBandwidth("down", p.DownBPS, p.DownMbps)
	if _, present := c.ppos[path+"/auth-base64"]; present {
		if _, passwordPresent := c.ppos[base+"/password"]; passwordPresent {
			fail("auth-base64", "password and auth-base64 are mutually exclusive")
		}
		p.AuthBase64 = c.resolveSecret(path+"/auth-base64", p.AuthBase64)
		if _, err := base64.StdEncoding.DecodeString(p.AuthBase64); err != nil {
			fail("auth-base64", "expected standard base64-encoded authentication bytes")
		}
	}
	// sing-quic NewHopConn requires an interval of at least five seconds.
	if _, present := c.ppos[path+"/hop-interval-seconds"]; present && p.HopInterval < 5 {
		fail("hop-interval-seconds", "hop interval must be at least 5 seconds")
	}
	if _, present := c.ppos[path+"/stream-receive-window"]; present && p.StreamReceiveWindow == 0 {
		fail("stream-receive-window", "stream receive window must be positive")
	}
	if _, present := c.ppos[path+"/connection-receive-window"]; present && p.ConnectionReceiveWindow == 0 {
		fail("connection-receive-window", "connection receive window must be positive")
	}
}
