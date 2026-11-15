package importer

import "strings"

// Support describes conversion support, rather than future protocol goals.
// Unlisted fields inside an imported resource make that resource unavailable.
type Support struct {
	Scope  string `json:"scope"`
	Field  string `json:"field"`
	Status string `json:"status"`
	Notes  string `json:"notes"`
}

func SupportMatrix() []Support {
	entries := []Support{}
	add := func(scope, status, fields, notes string) {
		for _, field := range strings.Fields(fields) {
			entries = append(entries, Support{scope, field, status, notes})
		}
	}
	add("proxies", "supported", "name", "Exact original name → stable hashed ID; duplicates/reserved names are errors")
	add("proxies", "partial", "type", "ss/vless/vmess/trojan/hysteria2/tuic/snell/http/socks5/direct/reject; only documented options are accepted")
	add("proxies", "supported", "server port", "Scalar host/IP and integer or quoted numeric port; native validation applies")
	add("ss/socks5/vless", "supported", "udp", "Absent means false, matching the locked Clash options")
	add("direct", "supported", "udp", "Defaults to true")
	add("http/socks5", "supported", "username password", "Both or neither; credentials are masked in previews")
	add("ss", "supported", "cipher password", "Native Shadowsocks cipher allowlist, including 2022; no plugins")
	add("vless", "supported", "uuid", "Native UUID validation; secret:// references can be resolved at commit")
	add("vless", "partial", "flow", "Empty or xtls-rprx-vision; Vision requires TLS")
	add("http/vless", "supported", "tls", "Boolean; REALITY options require true")
	add("socks5", "partial", "tls skip-cert-verify", "Only false/no TLS; TLS over SOCKS5 is unavailable")
	add("http", "supported", "sni skip-cert-verify", "Maps to native TLS server-name/insecure")
	add("vless", "supported", "servername client-fingerprint alpn", "Maps to native TLS fields; fingerprint must be in the native allowlist")
	add("vless", "partial", "skip-cert-verify", "Ordinary TLS supported; true with REALITY is unavailable")
	add("vless", "supported", "reality-opts.public-key reality-opts.short-id reality-opts.support-x25519mlkem768", "Native REALITY validation; unknown nested options make the node unavailable")
	add("vless", "partial", "network", "Empty/tcp, ws, grpc and httpupgrade; Vision requires raw TCP; REALITY supports the documented non-Vision combinations")
	add("vless", "partial", "packet-encoding", "Empty/xudp only; locked mihomo defaults to XUDP; packet/packetaddr unavailable")
	add("vless", "partial", "packet-addr", "False only")
	add("vless", "partial", "xudp", "Boolean accepted; locked mihomo still selects XUDP when packet-addr is false")
	add("vless", "partial", "encryption", "Empty/none only; encrypted VLESS is unavailable")
	add("vless", "partial", "alterId cipher", "VMess-only fields tolerated and listed as ignored; never used as VLESS options")
	add("proxies", "partial", "tfo mptcp udp-over-tcp", "Only disabled false is accepted; enabled values are unavailable")
	add("proxies", "partial", "smux", "Enabled/padding/protocol and connection/stream limits; h2mux/smux/yamux for non-Vision VLESS, VMess and Trojan")
	add("proxies", "unsupported", "plugin plugin-opts dialer-proxy interface-name routing-mark ip-version fingerprint name-cert-verify certificate private-key headers h2-opts http-opts ech-opts shadow-tls-opts restls-opts jls-opts", "Not silently removed; node is unavailable")
	add("proxy-groups", "supported", "name proxies icon", "Names/explicit member list; icon retained as GUI metadata; member availability is reported")
	add("proxy-groups", "partial", "type", "select/url-test/fallback/load-balance; relay unavailable")
	add("proxy-groups", "supported", "include-all include-all-proxies include-all-providers filter exclude-filter url interval timeout tolerance lazy disable-udp strategy", "Expansion preserves source/provider identity; regex filters; bounded cancellable probes; observed choices do not write configuration; round-robin or stable rendezvous hashing")
	add("rules", "supported", "DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD DOMAIN-REGEX IP-CIDR IP-CIDR6 SRC-IP-CIDR DST-PORT SRC-PORT NETWORK PROCESS-NAME MATCH FINAL", "Ordered native rule mapping; NETWORK normalized to lowercase")
	add("rules", "partial", "no-resolve", "IP-CIDR/IP-CIDR6/SRC-IP-CIDR, GEOIP and RULE-SET; propagated through nested rule sets")
	add("rules", "supported", "AND OR NOT SUB-RULE", "Recursive ordered short circuit; named sub-rules preserve fallthrough; invalid references/cycles rejected")
	add("rules", "partial", "RULE-SET", "HTTP resources require background refresh; inline providers work locally; yaml/text domain/ipcidr/classical and MRS v1 domain/ipcidr")
	add("rules", "partial", "GEOIP GEOSITE", "GEOIP LAN is built in; other selectors require explicit SHA-locked protobuf .dat resources; GeoSite attributes match by key presence; MMDB unavailable")
	add("rules", "unsupported", "PROCESS-NAME-REGEX", "No process regex approximation")
	add("targets", "supported", "DIRECT REJECT", "Built-in actions; no guessing unknown targets")
	add("targets", "unsupported", "REJECT-DROP PASS COMPATIBLE GLOBAL", "No semantic approximation")
	add("dns", "partial", "enable", "Absent/false is ignored; true converts an isolated DNS snapshot; profile dns.from explicitly activates it")
	add("dns", "supported", "nameserver default-nameserver proxy-server-nameserver direct-nameserver direct-nameserver-follow-policy nameserver-policy fallback fallback-filter enhanced-mode fake-ip-range fake-ip-range6 fake-ip-ttl fake-ip-filter fake-ip-filter-mode respect-rules use-hosts use-system-hosts ipv6", "UDP/TCP/DoT/DoH; explicit bootstrap; policy/scoped TTL and negative caches; fake-IP blacklist/whitelist; geodata selectors (including default fallback GeoIP CN) require explicit locked assets; imported hosts flags default true, fake TTL 1; zero TTL unavailable")
	add("dns", "partial", "hosts", "Top-level hosts are imported into source DNS as IP address entries; alias hosts unavailable")
	add("dns", "ignored", "listen", "Remote DNS cannot choose local ports; set profile dns.listen explicitly")
	add("dns", "partial", "prefer-h3", "False ignored; DNS over HTTP/3 unavailable")
	add("proxy-groups", "partial", "use", "Remote refresh expands HTTP/inline proxy providers; pure local import resolves inline providers")
	add("proxy-providers/rule-providers", "partial", "type", "Remote refresh supports http/inline; file providers are unavailable")
	add("proxy-providers/rule-providers", "supported", "url interval header", "HTTP(S), 30–604800 seconds (default 3600), scalar/list header values; no root credential inheritance")
	add("proxy-providers/rule-providers", "ignored", "path", "Compatibility hint only; remote input cannot choose local filesystem paths")
	add("proxy-providers/rule-providers", "partial", "payload", "Inline payload only; HTTP fallback payload is unavailable")
	add("proxy-providers", "partial", "health-check", "Active URL/interval/timeout/lazy checks become explicit generated health groups; disabled checks ignored")
	add("rule-providers", "partial", "behavior format", "domain/ipcidr/classical in yaml/text; MRS v1 domain/ipcidr; decoded and executed from locked resources; invalid entries reject the bundle")
	add("proxy-providers/rule-providers", "unsupported", "override filter exclude-filter proxy", "No silent approximation of provider transformation or routing")
	add("top-level", "ignored", "mixed-port port socks-port allow-lan bind-address mode log-level external-controller secret tun sniffer profile ipv6 geo-auto-update geo-update-interval geox-url tcp-concurrent unified-delay find-process-mode x-mimo", "All other top-level settings are also ignored and reported; local settings are untouched")
	add("links", "partial", "ss:// vless://", "Plain/base64 lists; SIP002 and legacy SS; VLESS TCP/WS/gRPC/HTTPUpgrade; unknown query parameters rejected")
	add("links", "partial", "trojan:// vmess:// hysteria2:// hy2:// tuic://", "Trojan/HY2/TUIC URLs and conventional base64 JSON VMess; explicit options only; no downgrade")
	add("vmess", "supported", "uuid alterId", "Native UUID and alter-id validation; raw TCP and optional TLS/transport")
	add("vmess", "partial", "cipher packet-encoding", "auto/none/zero/aes-128-gcm/chacha20-poly1305; empty/xudp/packetaddr packet encoding")
	add("trojan", "supported", "password sni servername", "TLS required; TCP and UDP")
	add("vmess/trojan/vless", "supported", "ws-opts grpc-opts http-upgrade-opts", "Explicit path/Host/header/service-name and WS early-data fields; unknown options rejected")
	add("hysteria2", "partial", "password up down obfs obfs-password", "Integer Mbps values and optional salamander; QUIC TLS, TCP/UDP; port hopping and realm options unavailable")
	add("tuic", "supported", "uuid password congestion-controller udp-relay-mode reduce-rtt heartbeat-interval", "TUIC v5; cubic/new_reno/bbr; native/quic UDP; heartbeat milliseconds")
	add("snell", "supported", "psk version userkey mode reuse obfs-opts", "v5/v6 servers; v5 uses upstream v4-compatible client framing verified against v5 server; v6 modes; native protocol lifetime owns reuse")
	return entries
}
