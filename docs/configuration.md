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
| `vless` | `server`, `port`, `uuid`, `flow` (`xtls-rprx-vision`), `packet-encoding` (`xudp`), `tls`, `udp`, `transport`, `multiplex` |
| `vmess` | `server`, `port`, `uuid`, `tls`, `udp`, `protocol` (`security`, `alter-id`), `packet-encoding`, `transport`, `multiplex` |
| `trojan` | `server`, `port`, `password`, `tls` (required), `udp`, `transport`, `multiplex` |
| `hysteria2` | `server`, `port`, `password`, `tls` (required), `udp`, `protocol` (`up-mbps`, `down-mbps`, `obfs`) |
| `tuic` | `server`, `port`, `uuid`, `password`, `tls` (required), `udp`, `protocol` (`congestion-control`, `udp-relay-mode`, `zero-rtt`, `heartbeat` in ms) |
| `snell` | `server`, `port`, `password` (PSK), `udp`, `protocol` (`version` 5/6, `user-key`, `mode`, `reuse`, `obfs`) |

- `udp` defaults to `true` where the protocol carries UDP. UDP connections routed to an outbound with `udp: false` are rejected.
- Shadowsocks methods: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`.
- `tls`: `server-name` (defaults to `server` when it is a name), `insecure`, `fingerprint` (uTLS preset: `chrome`, `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android`, `random`, `randomized`), `alpn`, `reality`.
- `reality` (vless only): `public-key`, `short-id` (even number of hex digits, at most 16), `x25519mlkem768` (keep the hybrid post-quantum key share; newer Xray servers may require it). REALITY needs `server-name` and uses `fingerprint: chrome` when none is set.
- Vision requires raw TCP and cannot multiplex. Non-Vision VLESS, including REALITY, supports `transport: {type: ws, path: /reka, host: front.example}` (also `grpc` with `service-name`, `httpupgrade` with `path`/`host`). WS accepts `headers: [{name: X-Key, value: ...}]`, `max-early-data` and `early-data-header`.
- `multiplex: {enabled: true, protocol: smux}` also accepts `h2mux`/`yamux`, `padding`, `max-connections`, `min-streams`, `max-streams`; the instance owns and drains its pool.
- HY2 obfs is `{type: salamander, password: ...}`. Snell v5 obfs is `{type: http|tls, host: ...}`; Snell v6 uses `mode: default|unshaped|unsafe-raw`. Snell v5 uses the pinned component’s v4-compatible wire client, verified against a v5 server.

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

Any `password`, `uuid`, `username`, protocol `user-key`/obfs password or transport header value may be `secret://<name>`. Secrets live in the platform store (macOS Keychain, Windows DPAPI, the host's cipher on Android, a 0600 file on Linux) and are set with `rekactl secret set NAME` (value on stdin), which also re-applies the configuration. A first import (`reka -profile`) whose only problem is a secret that is not stored yet is kept as revision 1 and starts once the secret is set. Credentials written inline are masked as `********` when the configuration is read through the API; sending `********` back keeps the stored value.

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
