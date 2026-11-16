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
	add("vless", "supported", "flow", "Empty or xtls-rprx-vision; Vision requires TLS or VLESS encryption; encrypted Vision also supports the documented stream transports")
	add("http/vless", "supported", "tls", "Boolean; REALITY options require true")
	add("socks5", "supported", "tls sni skip-cert-verify", "TLS wraps the SOCKS control stream; UDP ASSOCIATE stays UDP; certificate verification is enabled unless explicitly disabled")
	add("http", "supported", "sni skip-cert-verify", "Maps to native TLS server-name/insecure")
	add("vless", "supported", "servername client-fingerprint alpn", "Maps to native TLS fields; fingerprint must be in the native allowlist")
	add("vless", "partial", "skip-cert-verify", "Ordinary TLS supported; true with REALITY is unavailable")
	add("vless", "supported", "reality-opts.public-key reality-opts.short-id reality-opts.support-x25519mlkem768", "Native REALITY validation; unknown nested options make the node unavailable")
	add("vless", "supported", "network", "Empty/tcp, ws, grpc, httpupgrade, HTTP obfuscation and H2; Vision without encryption requires raw TCP; encrypted Vision over WS/gRPC/HTTPUpgrade/H2 tested")
	add("vless", "supported", "packet-encoding", "Empty/xudp, packet/packetaddr, or none for raw UDP; packetaddr resolves through normal DNS")
	add("vless", "supported", "packet-addr", "Selects packetaddr unless xudp=true takes precedence")
	add("vless", "supported", "xudp", "Boolean accepted; locked mihomo still selects XUDP when packet-addr is false")
	add("vless", "supported", "encryption", "none or mlkem768x25519plus native/xorpub/random, 1rtt/0rtt, X25519/ML-KEM-768 relay keys; masked and fingerprinted; real TLS/REALITY/transport/Vision TCP+UDP, wrong-key rejection and pinned-reference bidirectional tests")
	add("vless", "partial", "alterId cipher", "VMess-only fields tolerated and listed as ignored; never used as VLESS options")
	add("proxies", "supported", "tfo mptcp interface-name routing-mark ip-version", "Per-node physical dialer options; socket protection remains active with explicit interface binding; OS capability errors are reported")
	add("ss", "supported", "udp-over-tcp udp-over-tcp-version", "TCP-only node transport for UDP; default legacy v1 or explicit v1/v2; TCP and UDP echo tested")
	add("http", "supported", "headers", "Custom CONNECT headers; configured credentials take precedence over Proxy-Authorization; values are masked")
	add("vmess/vless", "supported", "h2-opts http-opts", "HTTP method/path/header lists and H2 host/path; H2 enables TLS, including when omitted in Clash")
	add("proxies", "supported with accounting diagnostic", "smux", "h2mux/smux/yamux on all dialing protocols; enabled/padding/connection/stream limits, only-tcp and brutal-opts integer K/M/G/T bps/Bps rates (unitless Mbps). statistic is retained as metadata while native per-flow accounting is always active. Brutal needs a compatible Linux server/kernel module; unavailable server negotiation fails.")
	add("http/socks5/vmess/vless/trojan/hysteria2/tuic", "supported", "fingerprint name-cert-verify", "Full DER certificate SHA256 pin (not SPKI); independent verification name keeps SNI; real TLS/uTLS/QUIC tests")
	add("http/socks5/vmess/vless/trojan/hysteria2/tuic", "supported", "certificate private-key", "Matching inline PEM, secret references or explicit caller-supplied certificate_files path attachments; masked previews and subscription refresh; remote paths never opened implicitly")
	add("http/socks5/vmess/vless/trojan/hysteria2/tuic", "supported", "ech-opts", "enable/config/query-server-name; explicit base64 ECHConfigList or HTTPS DNS lookup through active proxy-server DNS; real TLS/uTLS and HY2/TUIC TCP/UDP tests, wrong-key rejection; excludes REALITY")
	add("proxies", "supported", "dialer-proxy", "Named node/group dependency; combined cycles rejected; source namespaces and nodes-only dependencies preserved; parent transport changes replace dependent children, existing streams drain")
	add("proxies", "unsupported", "plugin plugin-opts shadow-tls-opts restls-opts jls-opts", "Not silently removed; node is unavailable")
	add("proxy-groups", "supported", "name proxies icon", "Names/explicit member list; icon retained as GUI metadata; member availability is reported")
	add("proxy-groups", "partial", "type", "select/url-test/fallback/load-balance; relay unavailable")
	add("proxy-groups", "supported", "include-all include-all-proxies include-all-providers filter exclude-filter url interval timeout tolerance lazy disable-udp strategy", "Expansion preserves source/provider identity; regex filters; bounded cancellable probes; observed choices do not write configuration; round-robin or stable rendezvous hashing")
	add("rules", "supported", "DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD DOMAIN-REGEX IP-CIDR IP-CIDR6 SRC-IP-CIDR DST-PORT SRC-PORT NETWORK PROCESS-NAME MATCH FINAL", "Ordered native rule mapping; NETWORK normalized to lowercase")
	add("rules", "partial", "no-resolve", "IP-CIDR/IP-CIDR6/SRC-IP-CIDR, GEOIP and RULE-SET; propagated through nested rule sets")
	add("rules", "supported", "AND OR NOT SUB-RULE", "Recursive ordered short circuit; named sub-rules preserve fallthrough; invalid references/cycles rejected")
	add("rules", "partial", "RULE-SET", "HTTP resources require background refresh; inline providers work locally; yaml/text domain/ipcidr/classical and MRS v1 domain/ipcidr")
	add("rules", "partial", "GEOIP GEOSITE", "GEOIP LAN is built in; other selectors use explicit SHA-locked DAT or country MMDB assets; GeoSite DAT attributes match by key presence")
	add("rules", "supported", "PROCESS-NAME-REGEX", "Case-insensitive .NET-compatible process basename expressions; 50 ms match budget; unknown processes do not match")
	add("targets", "supported", "DIRECT REJECT COMPATIBLE PASS REJECT-DROP GLOBAL", "COMPATIBLE routes directly; PASS continues after resolving current group choice; REJECT-DROP accepts locally and discards without a remote socket; GLOBAL uses an explicit selector or is synthesized when referenced")
	add("dns", "partial", "enable", "Absent/false is ignored; true converts an isolated DNS snapshot; profile dns.from explicitly activates it")
	add("dns", "supported", "nameserver default-nameserver proxy-server-nameserver direct-nameserver direct-nameserver-follow-policy nameserver-policy fallback fallback-filter enhanced-mode fake-ip-range fake-ip-range6 fake-ip-ttl fake-ip-filter fake-ip-filter-mode respect-rules use-hosts use-system-hosts ipv6", "UDP/TCP/DoT/DoH; explicit bootstrap; policy/scoped TTL and negative caches; fake-IP blacklist/whitelist; geodata selectors (including default fallback GeoIP CN) require explicit locked assets; imported hosts flags default true, fake TTL 1; explicit zero response TTL supported with a separate 60-second connection mapping lease")
	add("dns", "supported", "hosts", "IP entries and domain aliases; local alias chains resolve to IPs, external aliases rewrite the question and prepend CNAME; cyclic chains fail closed")
	add("dns", "ignored", "listen", "Remote DNS cannot choose local ports; set profile dns.listen explicitly")
	add("dns", "supported", "prefer-h3", "TLS/QUIC handshake selection with one DNS query; explicit native h3:// and quic:// endpoints also supported")
	add("proxy-groups", "partial", "use", "Remote refresh expands HTTP/inline proxy providers; pure local import resolves inline providers")
	add("proxy-providers/rule-providers", "supported", "type", "HTTP/inline/file bundles; file reads require an explicit local subscription provider-directory; root escapes and external symlinks rejected")
	add("proxy-providers/rule-providers", "supported", "url interval header", "HTTP(S), 30–604800 seconds (default 3600), scalar/list header values; no root credential inheritance")
	add("proxy-providers/rule-providers", "supported", "path", "HTTP cache-path hint ignored; file paths are relative to an explicit local provider-directory")
	add("proxy-providers/rule-providers", "supported", "payload", "Inline payload or declared startup fallback on initial HTTP transport/status failure; committed and invalid resources never silently replaced; status identifies fallback resources")
	add("proxy-providers", "partial", "health-check", "Active URL/interval/timeout/lazy checks become explicit generated health groups; disabled checks ignored")
	add("rule-providers", "partial", "behavior format", "domain/ipcidr/classical in yaml/text; MRS v1 domain/ipcidr; decoded and executed from locked resources; invalid entries reject the bundle")
	add("proxy-providers", "supported", "override filter exclude-filter", "Case-sensitive .NET regex lists preserve filter priority; structured overrides, name replacement/prefix/suffix and pinned yq-subset expressions; output revalidated")
	add("proxy-providers/rule-providers", "supported", "proxy", "Named active outbound/group carries HTTP downloads; unknown/rejected routes fail closed; does not create an uncommitted proxy for its own first download")
	add("top-level", "ignored", "mixed-port port socks-port allow-lan bind-address mode log-level external-controller secret tun sniffer profile ipv6 geo-auto-update geo-update-interval geox-url tcp-concurrent unified-delay find-process-mode x-mimo", "All other top-level settings are also ignored and reported; local settings are untouched")
	add("links", "partial", "ss:// vless://", "Plain/base64 lists; SIP002 and legacy SS; VLESS TCP/WS/gRPC/HTTPUpgrade; unknown query parameters rejected")
	add("links", "partial", "trojan:// vmess:// hysteria2:// hy2:// tuic://", "Trojan/HY2/TUIC URLs and conventional base64 JSON VMess; explicit options only; no downgrade")
	add("vmess", "supported", "uuid alterId", "Native UUID and alter-id validation; raw TCP and optional TLS/transport")
	add("vmess", "partial", "cipher packet-encoding", "auto/none/zero/aes-128-gcm/chacha20-poly1305; empty/xudp/packetaddr packet encoding")
	add("trojan", "supported", "password sni servername", "TLS required; TCP and UDP")
	add("vmess/trojan/vless", "supported", "ws-opts grpc-opts http-upgrade-opts", "Explicit path/Host/header/service-name and WS early-data fields; unknown options rejected")
	add("hysteria2", "supported", "password up down obfs obfs-password obfs-min-packet-size obfs-max-packet-size", "Integer K/M/G/T bps/Bps (unitless Mbps), checked conversion without rounding; salamander or gecko (bounded packet sizes); QUIC TLS and TCP/UDP. Actual hopping across multiple destination ports is tested with the five-second minimum.")
	add("hysteria2", "supported", "ports hop-interval", "Port lists/ranges and interval ranges; at least five seconds; mutually exclusive with Realm")
	add("hysteria2", "supported", "realm-opts", "enable/server-url/token/realm-id/stun-servers; separate control TLS sni/skip-cert-verify/name-cert-verify/fingerprint/certificate/private-key/alpn, explicit PEM file attachments; protected control and STUN/punch sockets, token masking and transport rotation; real punch TCP/UDP plus certificate/token negatives")
	add("tuic", "supported", "uuid password congestion-controller udp-relay-mode reduce-rtt heartbeat-interval", "TUIC v5; cubic/new_reno/bbr; native/quic UDP; heartbeat milliseconds")
	add("snell", "supported", "psk version userkey mode reuse obfs-opts", "v5/v6 servers; v5 uses upstream v4-compatible client framing verified against v5 server; v6 modes; native protocol lifetime owns reuse")
	return entries
}
