# Reka configuration (schema version 1, draft)

Reka keeps four documents in each configuration revision:

- the **profile**: outbounds, groups and rules, the part you share between machines;
- the **local settings**: listeners, log level and the control endpoint of this machine;
- **sources**: normalized snapshots of nodes, groups, rules and DNS;
- the **overlay**: explicit user edits applied to the composed resources.

The effective configuration is composed in a fixed order: built-in defaults → explicitly imported source resources → profile → overlay → local settings. See [Sources and overlays](source-overlays.md) for the format and examples. Every effective field records where it came from (`rekactl origin /listeners/mixed/listen`). A key set in local settings replaces the same key from the profile; the profile file itself is never rewritten for that.

All four documents are YAML. Parsing is strict: unknown fields, duplicate keys, wrong types, more than one document, nesting deeper than 32 levels and runaway alias expansion are errors. Every diagnostic carries the document, line, column and a field path built from stable IDs, for example `/outbounds/my-vps/port` (list entries without an ID are addressed by position, `/rules/#3`).

## Profile

```yaml
schema-version: 1

outbounds:
  - id: my-vps
    name: My VPS            # display only
    type: vless
    server: vps.example
    port: 443
    uuid: secret://outbounds/my-vps/uuid
    flow: xtls-rprx-vision
    tls:
      server-name: www.example.com
      fingerprint: chrome
      reality:
        public-key: "<base64url X25519 public key>"
        short-id: "ab12"
        x25519mlkem768: true

groups:
  - id: proxy
    type: select
    members: [my-vps, direct]
    selected: my-vps

rules:
  - id: lan
    match: {ip-cidr: [192.168.0.0/16, 10.0.0.0/8], no-resolve: true}
    outbound: direct
  - match: {domain-suffix: example.org}
    outbound: proxy
  - id: final
    match: {all: true}
    outbound: proxy
```

### IDs

Outbounds, groups and listeners need an `id`; rules may have one. IDs start with a letter or digit and use letters, digits, `.`, `_` and `-` (at most 64). Imported resources use `source/id`; escape the slash as `~1` in API paths, for example `/groups/airport~1proxy/selected`. They are the stable names used by patches, diagnostics, connection listings and history, so renaming the display `name` never replaces anything.

### Outbounds

`direct` and `reject` exist without being declared. Fields that do not apply to a type are errors.

| type | fields |
| --- | --- |
| `direct` | `udp` |
| `reject` | none |
| `http` | `server`, `port`, `username`, `password`, `tls` (no `reality`) |
| `socks` | `server`, `port`, `username`, `password`, `udp` (SOCKS5) |
| `shadowsocks` | `server`, `port`, `method`, `password`, `udp` |
| `vless` | `server`, `port`, `uuid`, `flow` (`xtls-rprx-vision`), `packet-encoding` (`xudp`, `packetaddr`, `none`), `tls`, `udp`, `transport`, `multiplex` |
| `vmess` | `server`, `port`, `uuid`, `tls`, `udp`, `protocol` (`security`, `alter-id`), `packet-encoding`, `transport`, `multiplex` |
| `trojan` | `server`, `port`, `password`, `tls` (required), `udp`, `transport`, `multiplex` |
| `hysteria2` | `server`, `port`, `password`, `tls` (required), `udp`, `protocol` (`up-mbps`, `down-mbps`, `obfs`) |
| `tuic` | `server`, `port`, `uuid`, `password`, `tls` (required), `udp`, `protocol` (`congestion-control`, `udp-relay-mode`, `zero-rtt`, `heartbeat` in ms) |
| `snell` | `server`, `port`, `password` (PSK), `udp`, `protocol` (`version` 5/6, `user-key`, `mode`, `reuse`, `obfs`) |

- `udp` defaults to `true` where the protocol carries UDP. UDP connections routed to an outbound with `udp: false` are rejected.
- Shadowsocks methods: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`.
- `tls`: `server-name` (defaults to `server` when it is a name), `insecure`, `fingerprint` (uTLS preset: `chrome`, `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android`, `random`, `randomized`), `alpn`, `reality`.
- `reality` (vless only): `public-key`, `short-id` (even number of hex digits, at most 16), `x25519mlkem768` (keep the hybrid post-quantum key share; newer Xray servers may require it). REALITY needs `server-name` and uses `fingerprint: chrome` when none is set.
- Without VLESS encryption, Vision requires raw TCP. VLESS, including REALITY, supports `transport: {type: ws, path: /reka, host: front.example}` (also `grpc` with `service-name`, `httpupgrade` with `path`/`host`). WS accepts `headers: [{name: X-Key, value: ...}]`, `max-early-data` and `early-data-header`.
- `multiplex: {enabled: true, protocol: smux}` also accepts `h2mux`/`yamux`, `padding`, `max-connections`, `min-streams`, `max-streams`; `only-tcp`, `statistic` and `brutal: {enabled: true, up-bps: 1250000, down-bps: 2000000}` (bytes/s). All dialing protocols support this wrapper. Full multiplexing carries UDP over the TCP carrier even when native UDP is disabled; `only-tcp` preserves native UDP behavior. The instance owns and drains its pool. `statistic` is retained as metadata: Reka always reports native per-flow traffic. Brutal requires a compatible Linux server and the TCP Brutal kernel module; a server that does not enable Brutal fails negotiation. Local kernel rate control is attempted where available. Limits alone do not demonstrate a measured throughput guarantee.
- HY2 obfs is `{type: salamander|gecko, password: ...}`. Gecko additionally accepts `min-packet-size`/`max-packet-size` (defaults 512/1200; 1 <= min <= max <= 2048). Snell v5 obfs is `{type: http|tls, host: ...}`; Snell v6 uses `mode: default|unshaped|unsafe-raw`. Snell v5 uses the pinned component’s v4-compatible wire client, verified against a v5 server.

### Groups

`select`, `url-test`, `fallback` and `load-balance` accept `members` (outbounds or groups). A select group’s `selected` value is configuration and survives restarts. Health observations and automatic choices are separate runtime state. Cycles through any member are errors. See [automatic groups](automatic-groups.md) for filters, timings, hashing and API.

### DNS

`dns` is optional. Configure a native resolver or explicitly choose source settings with `dns: {from: airport, listen: "127.0.0.1:5353"}`. See [DNS/Fake IP](dns.md) for policy, transports, lifetimes and defaults.

### Rules

Rules are matched in order and the first match wins. Each rule has exactly one condition in `match`; a list of values matches when any value does.

| condition | matches |
| --- | --- |
| `domain` | the destination name exactly (case-insensitive) |
| `domain-suffix` | the name or any subdomain of it |
| `domain-keyword` | names containing the keyword |
| `domain-regex` | names matching an RE2 expression |
| `ip-cidr` | the destination address (IPv4 or IPv6 prefix) |
| `src-ip-cidr` | the client address |
| `dst-port`, `src-port` | a port or a range, `"1000-2000"` |
| `network` | `tcp` or `udp` |
| `process-name` | the client process file name, on platforms that can tell (macOS, Windows, Linux); elsewhere the rule never matches and validation warns |
| `rule-set` | an immutable named set of conditions |
| `geoip: LAN` | built-in local/private address classification |
| `domain-pattern` | Clash provider label wildcard syntax |
| `and`, `or`, `not` | recursively composed conditions (a list of operands) |
| `all: true` | everything |

`ip-cidr` rules resolve a name destination with the configured generation DNS (system resolver when DNS is absent) unless `no-resolve: true` is set; they then see the first IPv4 answer (else the first IPv6 one). A failed lookup makes ip rules not match; it never sends the connection anywhere by itself. Rules after a match-all rule are reported as unreachable. Without a match-all rule, unmatched connections go to `direct` and validation warns.

Domain and domain-suffix rules are indexed, so thousands of them cost about as much as a few; the index only finds candidates, and the first matching position still wins.

Named `rule-sets`, `sub-rules`, resource hashes and explicit GeoIP/GeoSite assets are documented in [Rule resources](rule-resources.md). Rule-set and sub-rule definitions use stable IDs; references and cycles are validated before activation.

### Secrets

Any `password`, `uuid`, `username`, TLS client `certificate`/`private-key`, protocol `user-key`/obfs password or HTTP/transport header value may be `secret://<name>`. Secrets live in the platform store (macOS Keychain, Windows DPAPI, the host's cipher on Android, a 0600 file on Linux) and are set with `rekactl secret set NAME` (value on stdin), which also re-applies the configuration. A first import (`reka -profile`) whose only problem is a secret that is not stored yet is kept as revision 1 and starts once the secret is set. Credentials written inline are masked as `********` when the configuration is read through the API; sending `********` back keeps the stored value.

## Local settings

```yaml
listeners:
  - {id: mixed, type: mixed, listen: "127.0.0.1:7890"}
  - {id: socks, type: socks, listen: "[::1]:1080", udp: false}
log:
  level: info
control:
  listen: unix:///Users/me/Library/Application Support/Reka/control.sock
```

- Listener types: `mixed` (SOCKS4/4a/5 and HTTP on one port), `socks`, `http`. `listen` is an IP address and port. `udp` (default true) enables SOCKS5 UDP ASSOCIATE.
- `log.level`: `debug`, `info`, `warn`, `error`.
- `control.listen` is read when the kernel starts; changing it is reported as needing a restart.

`schema-version: 1` is required in the profile and optional in the other documents.

## Changes and history

All writes, whether from `rekactl`, the API, a GUI or a hand-edited file, go through one transaction:

1. validate (no side effects), 2. plan, 3. prepare (build new instances, bind new ports), 4. store the revision, 5. switch, 6. record it as active.

A commit names the revision it was based on; if another commit landed first it is refused with the field differences. Each commit has an operation ID, so a client that lost the response can look the result up or retry without applying the change twice. Old revisions can be restored, which commits their content as a new revision.

What a commit does to running connections:

| change | new connections | existing connections |
| --- | --- | --- |
| rules, group selection | follow the change | keep their outbound |
| outbound address or credentials | use a new instance | stay on the old instance, which closes once they end (forced after 30 s) |
| new or removed outbound | follow the change | removed outbound's connections run to completion |
| listener address | new address | already accepted connections continue; the new port is bound before the old one stops |
| listener protocol on the same address | brief refusal while it rebinds (shown in the plan) | continue |
| a port already in use | the commit is refused in preparation; nothing changes | unaffected |

UDP is split by destination: in one SOCKS5 association each destination is routed separately, keeps the configuration it started with, and is closed after 60 s idle.

### Hand editing

The kernel exports the active documents to `<state-root>/edit/`: `profile.yaml`, `local.yaml`, `sources.yaml`, and `overlay.yaml`. Each saved file is a separate transaction; submit a single API request when several documents must change atomically. Saving a change commits it. If the file is invalid or conflicts with a newer revision, the active configuration keeps running and the reasons are written to `<file>.errors`. When the kernel writes a document itself (a GUI change, `rekactl set`), it keeps your comments and uses a canonical layout: two-space indentation and a blank line between top-level sections.

## Local network takeover

`local.network` is the durable OS takeover intent. It is not permitted in imported sources or the shared profile. See [network takeover](network-takeover.md) for schema, modes, platform limits and interruption/recovery behavior.

`process-name-regex` matches the owning process basename using case-insensitive .NET-compatible expressions (including lookaround), with a 50 ms match budget. Unknown owners do not match. Clash regex payloads retain commas, escaped parentheses and character classes.

DNS hosts values accept IP lists or one domain alias. Alias chains ending in a
hosts IP entry return addresses under the original question; an external alias
rewrites the upstream question and prepends a CNAME with TTL 10. Cycles fail
closed. An explicit `fake-ip-ttl: 0` emits zero TTL while retaining a separate
60-second connection mapping lease; omission keeps the native 60-second default.

DNS endpoints also accept `quic://host:853` (DoQ) and `h3://host/dns-query`
(DoH3). Both use the configured bootstrap, certificate validation and selected
outbound, including UDP socket protection on Android. `prefer-h3: true` enables
TLS/QUIC handshake selection for HTTPS resolvers, sending the DNS message only
on the selected transport. Explicit `h3://` endpoints require HTTP/3.

Hysteria2 imports accept comma-separated `ports` and closed ranges, plus
`hop-interval` in seconds or a closed interval range. The pinned Clash defaults
are 30 seconds and a 5-second minimum. An omitted/zero `port` is allowed when
`ports` supplies the remote ports. Native profiles use `protocol.server-ports`
with explicit `start:end` ranges and `hop-interval-seconds` /
`hop-interval-max-seconds`.

Per-node `dialer` accepts `interface-name`, uint32 `routing-mark`, `ip-version`
(`dual`, `ipv4`, `ipv6`, `ipv4-prefer`, `ipv6-prefer`), `tfo`, and `mptcp`.
These describe the physical socket, including its mandatory VPN protection.
Unsupported host socket options return an error.

Native HTTP CONNECT outbounds accept `headers: [{name: X-Key, value: ...}]`;
configured username/password take precedence over `Proxy-Authorization`.
Shadowsocks supports `udp-over-tcp: true` and `udp-over-tcp-version: 1|2`
(default 1, matching Clash). VLESS `packetaddr` destinations use normal DNS,
while proxy server addresses continue to use the proxy DNS scope.

VLESS/VMess additionally accept `transport: {type: http, method: POST,
paths: [/one, /two], headers: [{name: Host, value: front.example}]}` and
`transport: {type: h2, hosts: [front.example], path: /tunnel}`. HTTP selects one
path and one value per header per connection; H2 requires TLS. The Clash
importer enables TLS for `network: h2` even when `tls` is omitted. REALITY
supports these non-Vision transports too.

TLS `certificate-sha256` is a SHA256 hex digest of the full DER certificate,
with optional colon separators; it is separate from the uTLS ClientHello
`fingerprint`. A pinned leaf is trusted directly; a pinned intermediate/root
must validate the leaf's chain and name. `verify-name` verifies a different
certificate name while retaining the configured SNI. `certificate` and
`private-key` are a matching inline PEM client identity or secret references;
these values are masked and participate in transport replacement.

`dialer: {proxy: parent-id}` routes a node's connection through another node
or group. Clash's `dialer-proxy` imports by exact original name. The combined
node/group graph must be acyclic, including unselected members. All possible
parent transports are retained for the child's lifetime; replacing a parent
also replaces its dependent children while existing streams drain. A rule-only
change reuses transports and reads the active group's observed choice. Rejected
or unavailable parents never fall back to a direct socket. UDP requires an
enabled parent and group. Put physical socket options on the parent: as in the
reference, a dialer proxy takes precedence over the child's interface, routing
mark, IP version, TFO and MPTCP settings; the compiler reports that precedence.

TLS `ech: {enabled: true, config: BASE64_ECHCONFIGLIST}` enables Encrypted
ClientHello. Omitting `config` queries HTTPS records using the active native
DNS configuration's proxy-server scope; `query-server-name` can override the
query name. Configure native DNS (or activate imported DNS with `dns.from`)
for this automatic mode. Missing ECH data or authentication failure is an
error; it does not silently send clear SNI. TLS/uTLS and Hysteria2/TUIC QUIC
are exercised by real TCP/UDP tests. REALITY uses its own handshake and cannot
be combined with ECH. The matching Clash field is `ech-opts` with `enable`,
`config` and `query-server-name`.

VLESS `encryption` accepts `none` or the pinned reference's
`mlkem768x25519plus.MODE.RTT.KEY...` form. Modes are `native`, `xorpub`,
`random`; RTT is `1rtt` or `0rtt`; relay keys are X25519 or ML-KEM-768 public
keys. It accepts inline configuration or a secret reference, is masked in
source reads, and participates in transport replacement. At most 32 relay
keys and 32 padding phases are allowed; total padding remains at most 65553
bytes. Handshake cancellation interrupts padding waits. A wrong key fails the
connection. Vision can use this encryption layer with or without outer TLS,
including WS, gRPC, HTTPUpgrade and H2 (H2 still requires TLS). Its transition
uses typed decrypted-buffer references while retaining the underlying carrier.

Hysteria2 `protocol` accepts `up-bps`/`down-bps` for exact bytes/s; the legacy
`up-mbps`/`down-mbps` remain available, but choose one representation per
direction. Clash `up`/`down` accept integer K/M/G/T `bps` or `Bps`; unitless
values mean Mbps. Invalid/overflowing rates are rejected rather than silently
becoming automatic bandwidth. Runtime authentication transmits the exact rate.

`protocol.realm` accepts `enabled`, `server-url`, `token`, `realm-id`,
`stun-servers` and a separate `tls` configuration for its HTTP(S) control peer.
The proxy's outer `tls` still verifies the QUIC peer. Realm control TLS supports
SNI, certificate pin/verification name, ALPN and client PEM identity, without a
TCP ClientHello preset, ECH or REALITY. Tokens and identities support secrets,
are masked, and replace their owning transport on edits. The node owns the
control connection pool; network reset clears idle control connections. All
physical control/STUN/punch sockets retain VPN protection and dialer settings.
Realm replaces the static server address and cannot combine with port hopping.
Controlled tests exercise actual STUN discovery, punching and TCP/UDP, including
wrong token, wrong independent TLS pins and missing control client identity.

Hysteria2 `server-ports` uses explicit `start:end` ranges, with
`hop-interval-seconds`/`hop-interval-max-seconds` (minimum five seconds). Tests
observe several destination ports during continuous TCP and UDP traffic; this
does not assert reachability through every NAT or third-party Realm service.

Shadowsocks accepts a `plugin` mapping. Implemented carriers currently include
`{type: obfs, mode: http|tls, host: front.example}`,
`{type: v2ray-plugin|gost-plugin, mode: websocket, host: front.example,
path: /tunnel, mux: true, tls: {...}, headers: [{name: X-Key, value: ...}]}`,
and `{type: shadow-tls, version: 1|2|3, host: front.example, password: ...,
tls: {...}}`. ShadowTLS defaults to version 2; websocket plugin mux defaults
to true. V2ray-plugin additionally supports `http-upgrade` and `fast-open`.
Fast-open sends the encrypted payload before the upgrade response; the response
is still checked before any reply is accepted. These are built-in Go carriers.

Plugin TLS is independent of the node's Shadowsocks cipher. Websocket carriers
support certificate pins, verification names, client PEM identities and scoped
ECH; ShadowTLS supports ordinary certificate options and ClientHello presets.
An explicit websocket Host header also sets SNI. Plugin passwords, TLS identities
and header values are masked and participate in transport replacement. Physical
sockets retain the node dialer/VPN protection. Native SS UDP bypasses the TCP
carrier; enabling UoT sends UDP through it instead. SIP002 `plugin` query values
support escaped SIP003 obfs-local/simple-obfs and v2ray-plugin options; unknown
options are rejected, and `uot=1` takes precedence over a false UoT alias.

Restls plugins use `type: restls`, `host`, `password`, `version-hint: tls12|tls13`,
optional `restls-script`, `force-tls12` and `client-fingerprint`. TLS verification
options remain under `tls`. JLS uses `type: jls`, `host`, `username`, `password`,
optional `alpn` and `client-fingerprint`; authentication uses the JLS credentials.
The SS Clash importer accepts the reference's plugin option names.

kcptun uses `plugin: {type: kcptun, kcp: {...}}`; `kcp` uses the reference's JSON
names (`key`, `crypt`, `mode`, `conn`, `autoexpire`, `scavengettl`, `mtu`,
`ratelimit`, `sndwnd`, `rcvwnd`, `datashard`, `parityshard`, `dscp`, `nocomp`,
`acknodelay`, `nodelay`, `interval`, `resend`, `nc`, `sockbuf`, `smuxver`,
`smuxbuf`, `framesize`, `streambuf`, `keepalive`). Its defaults and key expansion
match the pinned reference, including its historical default key. Explicit keys
or secret references are recommended. kcptun enables UDP over TCP automatically;
its UDP carrier uses the node's protected physical dialer or configured detour.
The pool reuses carriers, drains retired streams and releases sockets on network
reset and close. Allocation budgets cap active slots at 64, retired carriers at
256 and each configured buffer at 64 MiB.

Automatic groups accept `expected-status`, such as `204/300-399` or `200,204`.
`*` accepts any HTTP response; omitted native values retain the 200–399 default.
Clash imports explicitly select `*` when omitted, matching the reference. Provider
health checks propagate their own ranges to generated health groups. Group
filters use bounded .NET regular expressions and backtick-separated priority.
