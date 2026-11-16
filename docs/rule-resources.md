# Rule resources and logical rules

Rules keep first-match order. `AND`, `OR` and `NOT` evaluate operands in their written order and short-circuit. A `SUB-RULE` evaluates a guard, then its named block; if that block does not select an action, evaluation continues with the next parent rule. Recursive references and missing blocks are errors.

## Native configuration

```yaml
schema-version: 1
rule-sets:
  - id: websites
    entries:
      - {domain-suffix: example.org}
      - {domain: example.net}
sub-rules:
  - id: secure
    rules:
      - id: website
        match: {and: [{rule-set: websites}, {dst-port: 443}]}
        outbound: reject
rules:
  - id: call
    match: {network: tcp}
    call: secure
  - id: final
    match: {all: true}
    outbound: direct
```

`and` and `or` take a nonempty list of conditions; `not` takes a list containing exactly one condition. A routing rule has one `outbound` or one `call`. A rule-set's inline `entries` are actionless conditions, combined with OR in order; they may refer to other native rule sets. Cycles are rejected, including in unused definitions. An empty inline set never matches. An empty sub-rule block still evaluates its guard before falling through.

A source rule marker automatically brings in that source's rule sets and sub-rules. Importing just nodes/groups does not activate those definitions. For explicit profile references, use `imports: [{source: airport, rule-sets: true, sub-rules: true}]`. All references stay inside the source namespace; a profile then refers to `airport/websites`. Profile definitions can replace imported definitions by the same scoped ID; overlays can edit `/rule-sets/airport~1websites` and `/sub-rules/airport~1secure` using existing stable-ID operations.

Sub-rules compile into ordered guarded rules. Explain shows a composite rule ID such as `call/secure/website`; provenance retains the caller's guard and the original child's fields. A forbidden DNS lookup remains **undetermined** through nested sets and NOT, rather than being inverted into a match. `no-resolve` can use destination addresses already resolved by an earlier rule, but never starts another lookup. On a rule-set it propagates to its destination-IP predicates; domain predicates remain usable.

## Clash import and providers

The importer accepts both `AND,((NETWORK,TCP),(DST-PORT,443)),REJECT` and `AND,(NETWORK,TCP),(DST-PORT,443),REJECT`, nested AND/OR/NOT, `SUB-RULE,(NETWORK,TCP),secure`, and the `sub-rules` mapping. MATCH is a routing action and cannot be a logical operand.

Referenced rule providers execute after their bytes have been locked:

| Behavior | YAML / text | MRS v1 |
| --- | --- | --- |
| `domain` | domain patterns | supported |
| `ipcidr` | IPv4/IPv6 prefixes | supported |
| `classical` | actionless supported Clash conditions, including logic and geodata | unavailable in the format |

YAML consists of a `payload` string list. Text consists of one entry per line; blank lines and lines starting with `#` or `//` are ignored. Classical entries omit the outbound; MATCH, RULE-SET and SUB-RULE entries are rejected. Unknown conditions and invalid entries reject the bundle; they are not silently skipped. Native inline sets support explicit nested set references separately.

Domain provider patterns follow Clash label semantics: `example.org` is exact, `+.example.org` includes the name and subdomains, `.example.org` includes only subdomains, and `*.example.org` matches one label. Wildcards must occupy a whole label. Exact domains and ordinary suffixes are indexed, including subdomain-only suffixes; CIDRs use an immutable IP set.

Pure local import resolves inline providers. HTTP resources require [background refresh](subscriptions.md); the local preview never downloads them. Native external definitions contain `id`, `behavior`, `format` and the full SHA-256 `hash`; geodata also has `code`. The blob must already exist under the state's content-addressed resource store. `references: [{name: 'geosite:test', to: test-sites}]` maps names inside classical bytes to native sets; generated sources scope the destination IDs. There are no live file paths or URLs in a compiled rule set.

## GeoIP and GeoSite

`GEOIP,LAN` is built in: private, unspecified, loopback, multicast and link-local-unicast addresses. Other GEOIP and GEOSITE selectors use explicitly configured assets. GEOIP accepts country MMDB and protobuf DAT; GEOSITE uses DAT. Downloads remain explicit and SHA-locked:

```sh
./bin/rekactl subscription set airport secret://subscriptions/airport/url \
  -geoip https://assets.example/geoip.dat \
  -geosite https://assets.example/geosite.dat
./bin/rekactl subscription refresh airport
```

The versioned native subscription definition is:

```yaml
subscription:
  url: secret://subscriptions/airport/url
  geodata:
    - {id: geoip, url: https://assets.example/geoip.dat}
    - {id: geosite, url: https://assets.example/geosite.dat}
```

Each URL also accepts a `secret://` reference. Inline URLs are masked and restored by asset ID. Root headers are not inherited by geodata downloads. Configured assets use the subscription interval and the existing conditional cache, bundle limits and atomic commit. Their hashes are included in the source lock; history and restart use those bytes without redownloading.

GeoIP selects a country code, supports both address families and protobuf `reverse_match`. MMDB assets are detected when importing a supplied GEOIP bundle; native rule sets can explicitly use `format: mmdb`. GeoIP2 country records and sing-geoip scalar country records are supported, and the database is verified before compiling its immutable IP index. GeoSite supports keyword, regex, suffix and full-name domain types, and `list@attribute@attribute` selectors. Attribute matching uses key presence, as in the pinned reference. Missing codes or empty attribute results reject the candidate. Large public databases may exceed the existing 16 MiB per-resource / 32 MiB per-refresh limits; provide a smaller selected database rather than expecting an implicit limit increase.

## Bounds and validation

Resources are read and hash-checked during compilation; routing performs no rule-resource file reads or downloads. Normal destination resolution still follows IP-rule semantics. Each blob is at most 16 MiB. MRS decompression/output is capped at 64 MiB with validated lengths, versions and bounded tree traversal. Decoding caps entries at one million; a compilation reads at most 64 MiB of distinct rule resources and limits aggregate entries. Logical/reference nesting is capped at 32, sub-rule expansion below 100,000 rules, and native YAML retains its existing stricter document/depth limits.

Failures leave the running revision and cache validators intact, mark the subscription stale, and retain the prior routing table. These guarantees are covered by local controlled HTTP tests, including provider-only updates, damaged entries, missing geodata codes, masked edits, restart and offline restore. Binary compatibility fixtures are generated with mihomo v1.19.34; see [fixture provenance](../testdata/rules/README.md).
