# DNS and Fake IP

DNS belongs to the active immutable configuration generation. Omitting `dns` keeps system resolution. A DNS snapshot imported from a subscription stays inactive until the profile explicitly selects it:

```yaml
schema-version: 1
imports: [{source: airport, outbounds: true, groups: true}]
dns:
  from: airport
  listen: "127.0.0.1:5353"
rules: [{source: airport}]
```

Source references in nameserver fragments and rule-set selectors are namespaced automatically. Profile DNS fields replace source fields; overlay operations can edit the composed DNS fields with recorded provenance. A remote `listen` is ignored during import; the profile chooses the local address. This is an application resolver/listener, without system DNS changes or DNS interception; those belong to [system takeover](network-takeover.md).

## Native configuration

```yaml
dns:
  listen: "127.0.0.1:5353"   # optional UDP and TCP listener
  nameserver: ["https://1.1.1.1/dns-query"]
  default-nameserver: ["1.1.1.1"]
  proxy-server-nameserver: ["1.1.1.1"]
  direct-nameserver: ["1.1.1.1"]
  direct-nameserver-follow-policy: false
  nameserver-policy:
    - {id: internal, pattern: "+.corp.example", servers: ["192.0.2.53"]}
  fallback: ["tls://1.0.0.1:853"]
  fallback-filter:
    geoip: false
    ipcidr: ["240.0.0.0/4"]
    domain: ["+.fallback.example"]
  use-hosts: true
  use-system-hosts: false
  hosts:
    - {id: "local.example", addresses: ["192.0.2.8"]}
  enhanced-mode: fake-ip
  fake-ip-range: "198.18.0.0/16"
  fake-ip-range6: "fc00::/18"
  fake-ip-filter: ["+.lan", "+.local"]
  fake-ip-filter-mode: blacklist
  fake-ip-ttl: 60
  cache-size: 4096
  ipv6: false
  respect-rules: false
```

Native defaults: bootstrap is `system`; enhanced-mode is redir-host; IPv6/hosts flags are false; Fake IP TTL is 60 s, cache size 4096, ranges as above, filter mode blacklist. Zero TTL/cache-size select these native defaults. A nameserver list is required. `ipv6: false` returns empty AAAA answers. Explicit hosts contain IP addresses; alias-to-domain entries are unavailable. System hosts are read once per prepared generation, separately from explicit hosts.

Endpoints support bare IP[:port], `udp://`, `tcp://`, `tls://` and `https://`. DoT defaults to 853; DoH defaults to 443 and `/dns-query`. HTTPS query strings are retained. A `#group-or-outbound` fragment selects a native route and follows automatic-group observations. TLS verifies the endpoint host against trusted roots; redirects and environment HTTP proxies are disabled. UDP truncation retries TCP. UDP/TCP use the pinned component transports; DoT/DoH use bounded TLS/HTTP adapters inside the backend. DoQ, HTTP/3, DHCP resolvers and DNS endpoint URI extensions are unavailable.

## Credentials in upstream URLs

Some providers put an account token in the upstream URL. When the configuration is read through the API, an upstream in `nameserver`, `default-nameserver`, `proxy-server-nameserver`, `direct-nameserver`, `fallback` or a `nameserver-policy` server list is masked if it has user info, a query, or (for DoH) a path other than `/dns-query` or `/resolve`, such as `https://dns.example/abc123`. Group health-check URLs are masked when they have user info or a query. Sending the mask back keeps the stored value. A token in the host name (`tls://abc123.dns.example`) cannot be recognized and is shown as written; DNS upstreams do not accept `secret://` references yet. Other DNS fields, such as `fake-ip-filter` and `hosts`, are never masked.

## Policy and scope

Hosts are checked before upstream resolution. Nameserver-policy uses the first matching entry and bypasses fallback. Selectors support domain patterns, `rule-set:<id>`, and explicit locked geodata; see [rule resources](rule-resources.md). Fallback applies on primary failure, non-success response, a configured domain/IP filter, or an address outside the chosen GeoIP set. GeoIP requires a locked rule set (`geoip-set` or an unambiguous imported GeoIP selector).

Normal client queries, bootstrap, proxy-server lookup and direct destination lookup have separate TTL/negative caches. Cache keys preserve question flags and EDNS contents; replies are copied and TTLs age. Negative entries use SOA TTL/minimum. CNAME lookup follows at most eight names and rejects loops. Servers are attempted in configured order within a five-second query budget; when fallback is eligible, half the remaining budget is reserved for it. This differs from mihomo's parallel upstream scheduling. A system endpoint handles address lookups only; configure explicit transports for other record types.

`respect-rules` routes normal upstream requests using the generation router; transport determines TCP/UDP metadata. Endpoint hostnames use bootstrap first. Bootstrap endpoints must be literal IPs or `system`, routed directly. Proxy-server DNS cannot route through another proxy. These boundaries keep node address resolution independent from destination policy and reject explicit bootstrap/proxy resolution cycles. They do not establish desktop interface/TUN bypass, which belongs to [system takeover](network-takeover.md).

## Fake address lifetime

Only client-facing A/AAAA queries allocate fake addresses. Routing/proxy/bootstrap lookups obtain real addresses. Blacklist filters bypass allocation for matched names; whitelist filters allocate only for matched names.

The shared mapping pool records domain, range, DNS generation, expiry and active connection leases. New DNS settings affect new queries. Changing ranges leaves prior live mappings usable; an old address cannot be reassigned until its TTL and all leases have ended. TCP and UDP destinations are translated back to domains before routing, and UDP replies retain the requested fake source address. Unknown addresses in a known fake range are rejected.

Mappings are atomically saved to owner-only `<state-root>/cache/fake-ip.json` before a fake reply is published; failed persistence rolls back allocation. Restart restores unexpired mappings, while connection lease counts reset. Corrupt state rejects startup rather than guessing an address identity. Limits: 65,536 live mappings, 1,024 historical ranges, 32 MiB state input. Expired unused entries are recyclable.

Clash import retains default `use-hosts: true`, `use-system-hosts: true`, Fake IP TTL 1 and the three Windows connectivity-check filters. Absent/false `enable` leaves source DNS disabled. Fallback defaults to GeoIP CN as in the reference and therefore needs explicit locked geodata, or explicit `geoip: false`. Zero imported Fake IP TTL is rejected. Reka requires explicit nameservers and uses system bootstrap when none is supplied, instead of silently adopting mihomo's built-in public resolvers. Unsupported options produce diagnostics and block default application.
