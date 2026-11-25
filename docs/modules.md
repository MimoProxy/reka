# Surge modules

Reka loads Surge `.sgmodule` files from a URL or an absolute file path. The profile owns the module's settings. The source snapshot pins the original text, remote Map Local files and script sources by SHA-256. Validation and planning use those pinned bytes. Loon `.plugin` and Stash `.stoverride` are currently unsupported.

## Profile configuration

```yaml
schema-version: 1
modules:
  - id: filters
    enabled: true
    url: https://example.com/filters.sgmodule
    interval: 86400
    arguments: {PROXY: Example route, host: api.example.com}
outbounds:
  - {id: example, name: Example route, type: direct}
rules:
  - {id: lan, match: {geoip: LAN}, outbound: direct}
  - {module: filters}
  - {id: final, match: {all: true}, outbound: example}
```

`id` uses native stable ID syntax and must be unique among modules and native sources. Use exactly one `url` or `file`. URLs accept HTTP(S) or a `secret://` reference. Ordinary configuration reads mask inline URLs. A `file` must be an absolute path on the kernel host and refer to an ordinary file. Omit `enabled` for `true`. Omit `interval` or set it to `0` to check remote modules every 86,400 seconds. Explicit intervals are 300–604,800 seconds.

The corresponding entry in `sources.yaml` contains `id`, `module`, and `lock`. `module` records format `surge`, the SHA-256 identity of the declared URL or `file:` plus the path, and the module's display name and description when present. `lock.root` identifies the original text. `lock.resources` holds the URL identity and content hash for each `map-local` or `script` resource. Use profile `modules` to activate snapshots and `{module: ID}` to place their rules. Module snapshot entries cannot also define native source fields.

## Parameters and policy references

Place metadata lines at the beginning of the module. See the [Surge parameter syntax](https://manual.nssurge.com/profile/module.html#parameter-tables).

```ini
#!name=Example filters
#!arguments=PROXY:Example route,host:api.example.com,label:"News, daily",empty:
#!arguments-desc=PROXY:Route for matching requests,host:Hostname to match

[Rule]
DOMAIN,{{{host}}},{{{PROXY}}}

[MITM]
hostname = %APPEND% {{{host}}}
```

Argument keys are case-sensitive and can use Unicode. Values can be empty. Use double quotes around a default value containing commas. Quote booleans and other non-string YAML scalars in the profile's `arguments`. Profile values override defaults. Substitution uses `{{{name}}}` and occurs before section parsing, including inside jq filters and Map Local URLs. Supplying an undeclared argument produces a warning. A line that still references an undefined argument is skipped.

Built-in Surge policies are matched case-insensitively. Other policies resolve first by exact effective outbound or group ID, including imported IDs such as `source/group`, then by exact display name. Unknown policies and ambiguous display names reject the transaction. A matching ID takes precedence over display names. Country GeoIP, GeoSite, ASN and named rule-set conditions use resources already available in the effective native configuration.

## Composition

- **Routing rules.** An enabled module without a marker contributes its rules before the profile rules, in module order. `{module: ID}` expands the rules at that point. A marker can have an `id` and can appear at most once per module. A marker for a disabled module contributes no rules.
- **HTTP rewrites and scripts.** Each list starts with the enabled modules in profile order, followed by imported source entries and then profile entries. Module rules, rewrites and scripts get IDs of the form `module/item`. Moving unrelated lines preserves those IDs. An overlay can address the generated ID using JSON Pointer escaping, such as `/scripts/filters~1s-…`.
- **MITM hostnames.** Module `%INSERT%` hostnames come first, followed by the profile hostnames, imported source hostnames, and module `%APPEND%` hostnames. Hostname groups of the same kind follow module order. A directive without a prefix appends and is noted in the report. Prefer an exclusion ahead of a broader wildcard because the first match wins.
- **MITM booleans.** Defaults, imported sources, enabled modules, the profile, and the overlay apply in that order. The last explicit value wins. CA and decryption settings remain local settings.

Overlays apply to the composed configuration. MITM hostname patches use `/mitm/hostnames/#N`. Module provenance records the module ID and the original text line. Disabled modules need no snapshot and contribute no effective entries.

## Conversion support

Section names are case-insensitive. Lines beginning with `#`, `;`, or `//` are comments, with `#!` reserved for leading metadata. Inline `#` characters are preserved. A regex incompatible with Go's RE2 engine is unsupported, including lookahead and lookbehind.

| Section or metadata | Form | Result |
| --- | --- | --- |
| Metadata | `name`, `desc`, `arguments`, `arguments-desc`, `system`, `category`, `icon` | Supported. `system` is informational. |
| Metadata | `requirement`, `author`, `homepage`, `date`, `version`, other keys | Ignored. Requirements are not evaluated. |
| `[Rule]` | `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-WILDCARD`, `DOMAIN-REGEX` | Supported. Domain wildcards span labels and support `*`, `?`, and bracket classes. |
| `[Rule]` | `IP-CIDR`, `IP-CIDR6`, `SRC-IP`, `SRC-IP-CIDR`, `DST-PORT` / `DEST-PORT`, `SRC-PORT`, `NETWORK` | Supported. `SRC-IP` uses the native source IP condition. |
| `[Rule]` | `GEOIP,LAN`, country `GEOIP`, `GEOSITE`, `IP-ASN` | Supported. Country, site and ASN matches need locked native geodata. |
| `[Rule]` | `PROCESS-NAME`, `PROCESS-PATH` and their `-WILDCARD` and `-REGEX` variants | Supported where process metadata is available. |
| `[Rule]` | `AND`, `OR`, `NOT` | Supported with parenthesized operands. |
| `[Rule]` | Named `RULE-SET` and `DOMAIN-SET` | Supported as references to native rule sets. |
| `[Rule]` | `no-resolve` | Supported for IP and resource conditions. |
| `[Rule]` | `pre-matching` | Accepted; it only affects when Surge applies a reject. |
| `[Rule]` | `extended-matching`, other rule modifiers | Ignored. The supported rule still applies. |
| `[Rule]` | Policies `DIRECT`, `REJECT`, `REJECT-DROP` | Supported as the corresponding native actions. |
| `[Rule]` | Policies `REJECT-NO-DROP`, `REJECT-TINYGIF` | Approximated by native `reject`, with a report note. |
| `[Rule]` | `FINAL`, `MATCH` | Unsupported. The profile owns its final rule. |
| `[Rule]` | URL or file `RULE-SET` and `DOMAIN-SET`, `URL-REGEX`, `USER-AGENT`, `SCRIPT`, `SUBNET`, `CELLULAR-RADIO` | Unsupported. |
| `[MITM]` | `hostname` with `%APPEND%` or `%INSERT%` | Supported. Wildcards, exclusions, and ports including `:0` retain their native meaning. |
| `[MITM]` | Bare `hostname` | Approximated as append. |
| `[MITM]` | `h2`, `skip-server-cert-verify` | Supported for `true` and `false`. |
| `[MITM]` | `hostname-disabled`, `tcp-connection`, `client-source-address`, CA settings | Ignored. Use an overlay to remove hostnames. The module cannot supply a CA. |
| `[MITM]` | Other settings | Unsupported. |
| `[URL Rewrite]` | `header`, `302`, `307` | Supported with a replacement. A double-quoted URL pattern is accepted. |
| `[URL Rewrite]` | `reject`, `reject-no-drop`, `reject-200`, `reject-img`, `reject-tinygif`, `reject-dict`, `reject-array`, `reject-drop` | Supported as native responses `error`, `error`, `200`, `gif`, `gif`, `dict`, `array`, and `drop`. Omit the replacement or write `-`. |
| `[Header Rewrite]` | Request and response `header-add`, `header-del`, `header-replace`, `header-replace-regex` | Supported. Omitted direction defaults to `http-request`. |
| `[Header Rewrite]` | `Content-Length`, `Transfer-Encoding`, other framing or hop-by-hop headers | Unsupported. |
| `[Body Rewrite]` | `http-request` or `http-response` with pattern/replacement pairs | Supported. |
| `[Body Rewrite]` | `http-request-jq` and `http-response-jq` with an inline filter | Supported with optional single or double outer quotes. |
| `[Body Rewrite]` | `jq-path=` | Unsupported. Modules cannot load local filter files. |
| `[Map Local]` | Inline `text`, `json`, `base64`, `tiny-gif` | Supported. `tiny-gif` uses the built-in image. |
| `[Map Local]` | HTTP(S) `data` with any supported `data-type` | Supported as a locked file. Remote `json` and `text` set their content types unless given an explicit header. |
| `[Map Local]` | `header` and `status-code` | Supported. Headers use `Name:value\|Name:value` or standard Base64 encoding of that list. Values containing spaces can be quoted. |
| `[Map Local]` | Local file `data` | Unsupported. Only the profile's module `file` can open a local file. |
| `[Host]` | Static IPs, DNS server entries, aliases | Unsupported. DNS hosts are owned by the native DNS configuration. |
| `[General]`, `[Replica]`, `[Proxy]`, `[Proxy Group]`, `[WireGuard …]`, `[Ruleset]`, `[Ruleset …]` | All entries | Ignored. Modules cannot change general settings or define policies, tunnels, or rule sets. |
| `[Script]` | `http-request` and `http-response` with an HTTP(S) source | Converted to native script declarations when the source is pinned. |
| `[Panel]`, `[MTProto]`, `[SSID Setting]`, `[Snell Server]`, unknown sections | All entries | Unsupported. |

The report lists line numbers, section names, statuses and short explanations. Counts distinguish imported and unavailable entries. `partial` indicates ignored or unsupported lines. `can_apply` is false when conversion reports an error. Valid entries still contribute when the report is partial. Native validation runs after composition, including checks for MITM hostnames and locked rule resources.

## Scripts

The name on the left of `=` becomes the display name. Reka substitutes module arguments before parsing script settings. A setting ends at a comma followed by another `key=` or at the end of the line, so values can contain commas, equals signs and unescaped quotes, as in embedded JSON arguments. Double quotes around a value are removed, and `\"` inside them stands for a quote.

| Surge setting | Conversion |
| --- | --- |
| `type`, `pattern` | Imports `http-request` and `http-response` with a required RE2 URL pattern. |
| `requires-body`, `binary-body-mode` | Accept `1`, `0`, `true` and `false` regardless of case. Both default to `false`. |
| `max-size` | Byte limit. `0` and `-1` use the platform hard limit. Positive values are capped at that limit. Omission uses the platform default. |
| `timeout`, `argument` | Time limit in seconds from 1 to 3600, default 5. `argument` is preserved as a string. |
| `engine` | Accepts `auto`, `jsc` and `webview`, default `auto`. Desktop platforms ignore this setting. The iOS client chooses the engine. |
| `script-path` | Requires a remote HTTP(S) URL. Relative and local paths are skipped. |
| `script-update-interval` | Positive values are clamped to 300–604800 seconds. Reka uses the module interval when omitted or set to `0` or `-1`, with a default of 86400 seconds. The Surge manual specifies the default and leaves these two explicit values undefined. |
| `debug` | Accepted and ignored. |

Imported scripts use `format: surge`. The report skips other types, including `cron`, `generic`, `event`, `dns` and `rule`, and rows with a missing `type`. For HTTP scripts, keys such as `full-header-mode`, `wake-system`, `cronexp` and `event-name` are unsupported. Unknown settings, malformed values and incompatible patterns also skip the entire row. Reka currently supports script configuration, import and refresh. Execution will be integrated separately. [Surge scripting manual](https://manual.nssurge.com/scripting/overview.html)

## Refresh and caching

`module add` acquires the module and its resources before committing the profile entry and source snapshot together. Scheduled refreshes check enabled remote modules. Local modules are read on addition or explicit refresh. Manual refresh also works for disabled modules. Enabling a module without a matching snapshot acquires one during enablement.

Acquisition uses conditional requests, redirects, transport timeouts, backoff and stale status. The original module and the converted input after argument expansion are each limited to 16 MiB. A module can reference up to 32 distinct Map Local URLs of at most 15 MiB each and up to 128 distinct script URLs of at most 2 MiB each. The complete bundle is limited to 32 MiB. A successful refresh emits `module.updated`. A failed module or Map Local download or a rejected transaction preserves the previous snapshot and records a failure code. [Subscription downloads and caches](subscriptions.md#acquisition-and-caches)

Script sources are pinned after Map Local files. If a script download fails, Reka retains a usable cached copy that matches the previous lock. With no such copy, the report marks the line `module.script-unavailable` and the rest of the module remains available. A failed script is retried after its update interval or 30 minutes, whichever is shorter. Refresh status identifies each failed script by the SHA-256 of its URL and a short error code such as `body_too_large`. For remote modules, the earliest due entry determines the next check. If several lines reference the same script URL, its shortest interval applies.

When `SetModuleArguments` (or `rekactl module set-arguments`) makes an enabled module reference a Map Local or script URL absent from its snapshot, the service acquires a new snapshot and commits it with the arguments. Direct profile edits use the current lock until the module is refreshed. Exports include the original module text and its resource blobs.

## CLI and control API

```sh
./bin/rekactl module preview ./filters.sgmodule -argument PROXY='Example route'
./bin/rekactl module add filters https://example.com/filters.sgmodule -argument PROXY='Example route'
./bin/rekactl module add local-filters -file /path/to/filters.sgmodule -disabled
./bin/rekactl module list
./bin/rekactl module report filters
./bin/rekactl module set-arguments filters -argument PROXY=direct
./bin/rekactl module refresh filters
./bin/rekactl module disable filters
./bin/rekactl module enable filters
./bin/rekactl module remove filters
```

Use `-position N` to insert at a zero-based module index, `-interval N` to set the remote refresh interval, or `-argument NAME=VALUE` repeatedly. `set-arguments` replaces the argument map, and passing no arguments restores defaults. The CLI waits for refresh unless `-async` is set. Pass `-` to preview from stdin, or put `-json` before `module` for machine-readable output.

The control API exposes `AddModule`, `RemoveModule`, `SetModuleEnabled`, `SetModuleArguments`, `RefreshModule`, `ListModules`, `GetModuleReport`, and `PreviewModule`. Mutating profile calls use `base_revision`. `ListModules` returns source type, status, metadata, argument declarations and the available effective report summary. `GetModuleReport` returns the current effective report for an enabled module. `PreviewModule` uses current effective policies and performs no network or configuration writes. The preview reports remote Map Local references and scripts as unavailable without a lock. The preview, report and list summary include script counts and the lock status of convertible script lines. `GetCapabilities` advertises `surge-module` in `source_formats`. [Control API](control-api.md#surge-模块)

## Mobile preparation

Mobile apps can pass an ordered `deviceModules` list when preparing native profiles or imported subscriptions such as Clash. Device modules follow modules declared by the profile. If an ID appears in both lists, the profile declaration takes precedence. Supply app-managed snapshot paths for enabled modules in `modules`. With `rebindSnapshot`, omit `deviceModules` to keep the archived list or pass `[]` to clear it.

App-managed module snapshots continue to support Map Local locks. The kernel service acquires script locks for its own snapshots.
