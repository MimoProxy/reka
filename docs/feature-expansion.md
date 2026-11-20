# Sniffing, XHTTP, rules, native clients and DNS

This expansion keeps the native configuration transaction as the control
boundary. Imported subscriptions never choose local takeover settings. Mimo
continues to own its existing profile refresh schedule; the Reka instance owns
the four active configuration documents, stable resource IDs and selections.

## Bounded protocol sniffing

```yaml
sniff:
  enabled: true
  protocols: [http, tls, quic]
  timeout-ms: 300
  max-bytes: 65536
  max-packets: 8
  override-destination: false
```

Sniffing is enabled by default, including when `sniff` or `enabled` is omitted.
Set `sniff: {enabled: false}` to turn it off. A local `sniff` object replaces the
profile object. By default, the kernel inspects IP targets without a known
domain when the active rules match on domains. HTTP Host, TLS ClientHello SNI,
and QUIC ClientHello SNI can supply the missing routing hint. A Fake IP or an
inbound hostname already supplies a domain. Explicit `enabled: true`,
conditional sniff rules, or destination rewriting can request inspection
outside the default scope.
`override-destination` explicitly permits dialing the sniffed domain instead
of the original IP. Sniffing cannot reveal ECH's encrypted inner name.

Every TCP byte and UDP packet is replayed once, including malformed input and
timeouts. QUIC CRYPTO fragments are bounded and reassembled before routing.
Known server-first ports skip sniffing. There are at most 64 concurrent sniff
operations; overflow routes immediately. Validation limits are 10–2000 ms,
512–262144 bytes and 1–32 packets. The accepted flow captures its configuration
and dependencies before inspection, so concurrent configuration replacement
cannot redirect a half-inspected flow or destroy its later DNS/ECH path.

SOCKS/HTTP CONNECT must acknowledge the tunnel before an application sends its
ClientHello. When a flow needs inspection, a subsequent rejection can therefore
appear as a successful handshake followed by a closed tunnel. No payload is
decrypted or modified. Connection listings expose `sniffed_domain` and `protocol`.

### Inspect only selected traffic

```yaml
sniff:
  enabled: true
  skip-domains: ["+.private.example"]
  rules:
    - match: {src-ip-cidr: 10.3.0.0/16}
      action: skip
    - match: {and: [{in-name: mixed}, {dst-port: [443, 8443-8450]}]}
      action: sniff
      protocols: [tls, quic]
      override-destination: false
```

Rules use the first matching action. With a nonempty list, unmatched flows skip inspection. Without a list, the global sniff configuration applies as before. Conditions can use IPs, ports, network, inbound names/types/users, domains already supplied by the inbound, and logical operators. Matching never triggers DNS or process discovery. Matched `sniff` actions can inherit or override the global protocols and destination rewriting.

`skip-domains` accepts Clash domain patterns and applies to known names and names discovered by inspection. An excluded inspection result is discarded, with all bytes and packets forwarded through the normal path.

## XHTTP

Native VLESS `transport.type: xhttp` supports `transport.host/path/headers`
and an `xhttp` object with `mode`, padding/post limits, `xmux` and one independent
`download-settings` endpoint. The importer accepts mihomo `network: xhttp` and
`xhttp-opts`, including `reuse-settings` or `xmux` (not both). Unknown fields and
recursive download endpoints fail validation.

The client supports `auto`, `packet-up`, `stream-up`, `stream-one`, HTTP/1.1,
HTTP/2 and HTTP/3, ordinary TLS, uTLS, REALITY and optional VLESS encryption.
Vision over a stream transport requires VLESS encryption; unencrypted Vision
still requires raw TCP. HTTP/3 rejects TCP security carriers, REALITY and uTLS
presets. Upload and download endpoints retain their own certificate checks,
pins, ECH lookups and pool settings. Protected/scoped dialing applies to every
physical connection. Existing streams retain their resource when replaced;
new streams use the new pool.

The narrow compatibility client is adapted from pinned mihomo v1.19.34, with
origin hashes and changes in `internal/compat/xhttp/ORIGIN.md`. It adds no module
dependencies. `tools/xhttpref` links the unmodified pinned server separately
for local interoperability tests. This is evidence for protocol compatibility;
it does not establish compatibility with every public CDN or server deployment.

## Advanced rules used by current profiles

The expansion adds `PROCESS-PATH`, `PROCESS-PATH-REGEX`,
`PROCESS-PATH-WILDCARD`, `PROCESS-NAME-WILDCARD`, `UID`, `IN-NAME`, `IN-TYPE`,
`IN-PORT` and `IN-USER`, including logical rules, rule sets and sub-rules.
See [owner and inbound routing](advanced-rules.md) for exact matching semantics.
Mixed listeners report their actual HTTP/SOCKS version; authenticated listener
users can match `IN-USER`. Credentials are secret-resolved, fingerprinted and
masked in configuration/plan/conflict responses. Credential rotation restarts
the listener while accepted streams drain normally.

Owner information is lazy and cached once per evaluation. Android's optional
rich JNI callback returns a UID and an unambiguous package path together; shared
UIDs never invent a package name. An unavailable owner is unknown. `UID:0`
follows the pinned mihomo unknown-owner behavior. Connection listings expose
`process_path`/`process_uid` only if routing actually obtained owner information.
ASN/DSCP and arbitrary mihomo extension rules are outside this batch; strict
import reports them instead of discarding them.

## Native client contract

Mimo adapters use the existing native framed API over Unix sockets, Windows
named pipes or Android JNI. They use stable native IDs and the
validate → plan → commit transaction, with a base revision, plan hash and
operation ID. `GetCapabilities` lists the methods supported by the running core.
The following additions support the actual client data paths:

| Method | Contract |
| --- | --- |
| `ProbeOutbound` | Explicit node/group and HTTP(S) URL; bounded measurement; no selection change. |
| `GetTraffic` | Cumulative user-flow upload/download, timestamp and process epoch; includes closed flows. |
| `GetRules` | Active router's paginated rules and routing mode; limit at most 1000. |
| `QueryDNS` | Name, question type and normal/proxy/direct/bootstrap scope; Fake IP requires explicit `fake: true`. |
| `FlushDNSCache` | Clear ordinary scoped observations; retain Fake IP mappings and active flows. |
| `ResetNetwork` | Clear ordinary DNS cache and close idle DNS/outbound connections after a network change. |
| `GetLogs` | Bounded recent real enabled log events; the existing subscription cursor supports replay/drop detection. |
| `StageResource` | Sequential base64 chunks at most 1 MiB into a SHA-256 addressed, bounded immutable resource. |

Imports reference staged provider bytes with `provider_resources` (scoped
`proxy-providers/name` / `rule-providers/name`) and locked geoip/geosite with
`geodata_resources`. The privileged service never reads an arbitrary client
path. Files are at most 16 MiB, import resources total at most 32 MiB; four
incomplete uploads are allowed, expiring after two minutes of inactivity.

`routing: {mode: rule|global|direct, global: <native target ID>}` in the local
document changes routing while preserving stored rules. Global mode requires
an explicit valid target. This differs from `network.mode`, which controls
off/system proxy/TUN. Windows `network.proxy-bypass` preserves the user's proxy
override string; empty uses `<local>`. Nonempty bypass is currently Windows-only.

Desktop `-defer-network` and Android `Native.startOff` persist an ordinary
transaction setting takeover off before starting restored state. Adapters
import the candidate, restore selections, verify readiness and then explicitly
enable takeover. Standby conversion failure stops startup. As of `a986b1d`, a loaded revision whose local takeover is confirmed off may remain control-only with `start_error` when its profile cannot start, allowing repair. The macOS client starts every session in standby and waits for the user to enable takeover explicitly. Unsupported client
extensions must be rejected before stopping the running core.

## DNS concurrency and lifetime

Identical full-wire questions within the same scope share one upstream query.
A caller can cancel without cancelling other waiters; a cancelled leader leaves
a surviving waiter free to retry. Each service permits at most 128 distinct
in-flight questions. `max-concurrent-upstreams` defaults to four, accepts 1–16
(zero means default), and bounds racing upstream workers. Losers are cancelled
and joined before the operation releases its captured transport dependencies.
Fallback, policy matching, negative TTLs, EDNS/ECS and scope separation remain
part of the existing resolver policy.

DoH uses persistent HTTP/1.1 or HTTP/2 connections. DoT and TCP reuse the pinned
sing-box query multiplexer with Reka's verified TLS wrapper. The generated,
source-hashed overlay retains strict wire-ID checks before reuse is established
and binds asynchronous reuse probes to the pool lifetime. Pools are keyed by
the complete endpoint/security/path, scope and actual selected outbound within
one configuration. At most 64 entries are kept; idle entries are reaped after
30 seconds. Retirement releases idle connections, lets active queries finish,
and allows old pinned flows to make bounded one-shot queries afterward.
QUIC/HTTP3/prefer-H3 retain the existing per-exchange connection lifetime.

```yaml
dns:
  nameserver: [https://resolver.example/dns-query]
  max-concurrent-upstreams: 4
  cache-stale-ttl: 0
```

`cache-stale-ttl` optionally serves expired ordinary answers with TTL zero for
up to 86400 seconds while one bounded background refresh runs. The default zero
disables this behavior. At most 16 refreshes run; each owns resource pins and
stops on retirement. A cache flush invalidates pending refresh writes. Fake IP
mapping lifetime is independent and is never used as an ordinary stale answer.

## Reproducible core checks

```sh
make test
make vet
make race
# Reference interop is explicit; ordinary tests skip external peer tests.
# Build the helper as documented in tools/xhttpref/README.md, then:
REKA_XHTTP_REFERENCE=/tmp/reka-xhttp-reference make test
```

Acceptance includes real TCP/UDP and authenticated mixed listeners; concurrent
configuration replacement while sniffing or querying DNS; no-byte-loss stream
replay; H1/H2/H3 reference XHTTP transport and VLESS TCP/XUDP; TLS/uTLS/REALITY;
independent upload/download settings and certificate identities; encrypted
Vision with an inner TLS stream; bounded cancellation; and cumulative traffic
after connections close. Platform client builds and device/UI checks are
recorded separately in their client validation reports.
