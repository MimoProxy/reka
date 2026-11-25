# Surge, Loon and Stash modules

Reka loads Surge `.sgmodule`, Loon `.plugin` and `.lpx`, and Stash `.stoverride` modules from a URL or an absolute file path. The profile owns the module settings. The source snapshot pins the original text, remote Map Local files and script sources by SHA-256. Validation and planning use those pinned bytes.

## Profile configuration

```yaml
schema-version: 1
modules:
  - id: filters
    enabled: true
    url: https://example.com/filters.sgmodule
    format: surge
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

The corresponding entry in `sources.yaml` contains `id`, `module`, and `lock`. `module` records the selected format, the SHA-256 identity of the declared URL or `file:` plus the path, and the module's display name and description when present. `lock.root` identifies the original text. `lock.resources` holds the URL identity and content hash for each `map-local` or `script` resource. Use profile `modules` to activate snapshots and `{module: ID}` to place their rules. Module snapshot entries cannot also define native source fields.

## Format detection

Set `format` to `surge`, `loon`, or `stash` to choose the parser. Omit it for automatic detection. A recognized filename or URL path extension takes precedence over the document contents. The extensions are `.sgmodule` for Surge, `.plugin` and `.lpx` for Loon, and `.stoverride`, `.yaml` and `.yml` for Stash. Matching is case-insensitive and excludes URL query strings.

For an unrecognized extension, Reka checks the first significant line after skipping a BOM and comments. A section heading or `#!` metadata indicates a line-based module. An `[Argument]` section, `#!loon_version`, Loon JSON or dictionary and array reject actions, or an `if ${url}` expression selects Loon. Other line-based modules use Surge. A top-level YAML mapping with `name`, `http`, `rules`, or `script-providers` selects Stash. Unidentified content uses the historical Surge default. Changing the explicit format to a different dialect requires a fresh snapshot.

## Surge parameters and policy references

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

## Surge conversion support

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
| `[Script]` | `http-request`, `http-response`, `cron`, `generic` and `event` with an HTTP(S) source | Converted to native script declarations when the source is pinned. |
| `[Panel]`, `[MTProto]`, `[SSID Setting]`, `[Snell Server]`, unknown sections | All entries | Unsupported. |

The report lists line numbers, section names, statuses and short explanations. Counts distinguish imported and unavailable entries. `partial` indicates ignored or unsupported lines. `can_apply` is false when conversion reports an error. Valid entries still contribute when the report is partial. Native validation runs after composition, including checks for MITM hostnames and locked rule resources.

## Loon plugins

| Section | Conversion |
| --- | --- |
| Metadata | `name`, `desc`, `icon`, and `category` are displayed. Other keys are informational. |
| `[Argument]` | `input`, `select`, and `switch`. The first value is the default. A `select` override outside the choices is used with a warning. |
| `[Rule]` | Uses the shared rule converter. `PROXY` uses the profile argument or plugin default when supplied, then resolves against effective policies. With no argument, Reka resolves a policy named `PROXY`. Loon response-specific routing rejects use native `reject`, and `REJECT-DROP` uses `reject-drop`. |
| `[Rewrite]`, `[URL Rewrite]` | URL changes and redirects, reject responses, header edits, inline JSON and regex body edits, and Map Local-compatible mock responses. |
| `[Script]` | `http-request`, `http-response`, `request`, `response`, `cron`, `generic`, and `network-changed` with an HTTP(S) script URL. Disabled entries are skipped and `tag` is the display name. Scripts use `format: loon`. HTTP scripts default to a 10-second timeout, and the other types default to 300 seconds. |
| `[MITM]` | `hostname` with optional `%APPEND%` or `%INSERT%`. Other MITM settings are ignored. |
| `[Map Local]` | Uses the same inline and locked remote response formats as Surge. |

Declared `{name}` placeholders expand in plugin text. Undeclared single-brace placeholders stay literal, including regex quantifiers. Expressions also accept `${name}`, and Surge-style `{{{name}}}` works with Loon modules. `argument=[{Player},{Enabled}]` passes an object as `$argument`. A `switch` becomes a JavaScript boolean, and other values become strings. A quoted `argument="..."` is passed as a string. Native script declarations can express an object using `argument-type: object` and an `argument` string containing a JSON object. [Loon legacy scripts](https://nsloon.app/en/docs/Script/)

A `cron` entry starts with a quoted expression or an argument placeholder, using five fields or six fields with seconds first. `generic` runs on demand and `network-changed` becomes an `event` script with `event-name: network-changed`. Both are described in [background scripts](#background-scripts). Loon's legacy syntax runs only the first `network-changed` entry. Reka follows the newer syntax and runs every enabled entry. `img-url` and `img_url` are display settings and are ignored. [Loon scripts](https://nsloon.app/en/docs/Script/script_v2)

The expression subset has the form below. It matches the URL and accepts the optional case-insensitive `i` flag and a named capture. In redirect targets, `${capture[1]}` expands to the first capture. Supported calls include reject responses, redirects, `script` with optional object arguments, and request or response `json.delete`, `json.replace`, and `json.jq`. Other conditions, combined conditions, other flags and remote `jq_file` filters are reported as unsupported. [Loon expressions](https://nsloon.app/en/docs/Rewrite/rewrite_v2/)

```ini
[Rewrite]
request if ${url} ~= /^https:\/\/example\.test\/(.*)/i as capture then redirect(302, "https://example.net/${capture[1]}")

[Script]
response if ${url} ~= /^https:\/\/example\.test/ then script("https://example.test/hook.js", {${Player}, ${Enabled}}) with requires_body=true
cron ${Schedule} then script("https://example.test/daily.js", {${Player}}) with tag="Daily", timeout=120
generic then script("https://example.test/panel.js", "mode=compact") with tag="Panel", img_url="network"
network-changed then script("https://example.test/changed.js") with tag="Changed"
```

## Stash overrides

| YAML path | Conversion |
| --- | --- |
| `name`, `desc`, `icon`, `category` | Display metadata. Other metadata keys are informational. |
| `rules` | Clash-style rule strings. Named `RULE-SET` entries can refer to existing native rule sets. `MATCH` and remote rule-set URLs are unsupported. |
| `http.mitm` | Hostname strings, including exclusions with `-` and `%APPEND%` or `%INSERT%` prefixes. |
| `http.url-rewrite` | `302`, `307`, `transparent`, and reject responses. `transparent` changes the URL directly. |
| `http.header-rewrite` | Request and response header add, delete, replace, and regex replacement. |
| `http.body-rewrite` | Inline request or response jq filters and regex replacements. |
| `http.mock` | Inline responses with status, headers, and text, JSON, or Base64 data. |
| `http.script`, `script-providers` | A request or response script selects its provider by `name`. The provider supplies an HTTP(S) `url` and optional `interval`. Acquisition pins the script source and execution uses `format: stash`. |
| `cron.script` | Each entry selects a provider by `name` and becomes a `cron` script. `cron` is required, with five fields or six fields with seconds first. `argument` and `timeout` are optional. [Stash scheduled tasks](https://stash.wiki/en/script/scheduled-tasks) |
| `tiles` | Each tile selects a provider by `name` and becomes a `generic` script. Stash runs tile scripts without a request and shows the object passed to `$done`, which matches an on-demand generic run. `argument` and `timeout` are converted. `interval`, `title`, `content`, `icon`, `backgroundColor`, `url`, and `collapsed` are display settings and are ignored. Reka does not refresh tiles on the `interval`. [Stash tiles](https://stash.wiki/en/script/tile) |

The importer skips Stash arguments, provider-based body rewrites, and proxy, DNS, controller, and other local settings. A missing script provider is reported on the script entry. YAML parser errors prevent application, and report positions refer to the original YAML nodes, including folded rewrite strings. [Stash HTTP rewrites](https://stash.wiki/en/http-engine/rewrite)

## Surge scripts

The name on the left of `=` becomes the display name. Reka substitutes module arguments before parsing script settings. A setting ends at a comma followed by another `key=` or at the end of the line, so values can contain commas, equals signs and unescaped quotes, as in embedded JSON arguments. Double quotes around a value are removed, and `\"` inside them stands for a quote.

| Surge setting | Conversion |
| --- | --- |
| `type`, `pattern` | Imports `http-request`, `http-response`, `cron`, `generic` and `event`. A RE2 URL pattern is required for HTTP scripts. |
| `cronexp` | Required for `cron`. Accepts five fields (minute through weekday) or six fields (with seconds first). A quoted value can contain commas. |
| `event-name` | Required for `event`. `network-changed` runs on network changes. Other names are retained as unsupported. |
| `wake-system` | Accepts `1`, `0`, `true` and `false`. Reka preserves this setting for compatibility and schedules only while the kernel is running. |
| `requires-body`, `binary-body-mode` | Apply to HTTP scripts. Accept `1`, `0`, `true` and `false` regardless of case. Both default to `false`. |
| `max-size` | HTTP script byte limit. `0` and `-1` use the platform hard limit. Positive values are capped at that limit. Omission uses the platform default. |
| `timeout`, `argument` | Time limit in seconds from 1 to 3600, default 5. `argument` is preserved as a string. |
| `engine` | Accepts `auto`, `jsc` and `webview`, default `auto`. Desktop platforms ignore this setting. The iOS client chooses the engine. |
| `script-path` | Requires a remote HTTP(S) URL. Relative and local paths are skipped. |
| `script-update-interval` | Positive values are clamped to 300–604800 seconds. Reka uses the module interval when omitted or set to `0` or `-1`, with a default of 86400 seconds. The Surge manual specifies the default and leaves these two explicit values undefined. |
| `debug` | Accepted and ignored. |

Imported scripts use `format: surge`. The report skips unsupported types such as `dns` and `rule`, rows with a missing `type`, unknown settings such as `full-header-mode`, and rows with invalid settings or patterns. [Surge scripting manual](https://manual.nssurge.com/scripting/overview.html)

### Script execution

Reka runs `http-request` and `http-response` scripts during MITM forwarding over HTTP/1.1 and HTTP/2. Desktop platforms and Android use goja. On iOS, script execution requires a client-provided engine. Without an engine, an HTTP match is recorded as `unsupported` and the exchange passes through unchanged.

Each request is processed in this order: URL rewrite → request header rewrite → Map Local → request body rewrite → request script → upstream → response header rewrite → response body rewrite → response script → client. The Surge manual states that body rewrites run before scripts. It does not order Map Local and scripts; Reka treats Map Local as the end of processing, so neither request nor response scripts run for a local response. A response returned by a request script is likewise written to the client without response rewrites or response scripts. [Surge body rewrite](https://manual.nssurge.com/http/body-rewrite.html)

- Request scripts match the rewritten URL. Response scripts match the URL that was finally sent upstream. As in Surge, only the first matching script of each type runs, in composition order. If that script is skipped for size, an open circuit or a failure, later scripts are not tried.
- With `requires-body: false` the body is not buffered and the script sees it as `undefined`. A body supplied to `$done` still replaces the message.
- With `requires-body: true` the body is buffered up to the smaller of `max-size` and the platform hard limit (desktop and Android: default 10 MiB, hard limit 32 MiB; iOS: 512 KiB for both). Bodies over the limit, before or after decoding, skip the script, are forwarded with their original encoding and are recorded as `oversize`.
- Scripts see decoded bodies. `gzip`, `deflate`, `br` and identity are supported; when a response script needs the body, the upstream `Accept-Encoding` is limited to these. A body with another or a malformed encoding skips the script and is recorded as `failed`. A replaced body drops the old `Content-Encoding` and `Transfer-Encoding` and gets a new `Content-Length`. An unchanged body is written with its original bytes and encoding. A buffered chunked response is written back with a fixed length.
- A request script can change the URL, headers and body, return a response without contacting the upstream, or abort. A changed URL must be a valid HTTPS URL; a new host or port is routed again. A response script can change the status, headers and body, or abort. Abort closes the client connection without a response.
- Exceptions, timeouts, an open circuit, a busy host, or a session that ends without `$done` leave the exchange as it was before the script. A bare `$done()` passes through with `format: surge`. With `loon` and `stash` it aborts a request script and passes a response script through.
- The request and response scripts of one exchange share `$request.id`.

### Background scripts

- `cron` runs on its schedule in the local time zone while the kernel is running. On wake, the scheduler skips a trigger more than one minute overdue and calculates the next occurrence from the current time. `wake-system` is a compatibility setting and cannot wake the device.
- `generic` runs on demand through `RunScript` or `rekactl script-run`.
- `event` with `event-name: network-changed` runs after a network change. The kernel combines repeated notifications within one second. Other event names are accepted and listed as unsupported.

These scripts run independently of MITM. `RunScript` can also start supported cron and event scripts. A script ID can have one active run at a time across all trigger types. An overlapping trigger is recorded as `overlap` and discarded. `$request` and `$response` are undefined. The JSON argument to `$done` is available in the run record. [Control API](control-api.md#background-scripts)

### Script services

- `$httpClient` routes with the active rules by default. `policy` selects an outbound or group by ID or display name, or the built-in `DIRECT` and `REJECT`; IDs win over names, and unknown or ambiguous names return an error to the script. `policy-descriptor` is not supported. The timeout defaults to 5 seconds, as in Surge, and is bounded by the script session. Request and response bodies are each limited to the platform's default script body size. Requests dial the selected outbound directly, so they never pass through an inbound and are never intercepted again. Destinations on a loopback or unspecified address, including names that resolve to one, are rejected when the port belongs to a kernel listener. `insecure` skips server certificate verification, `auto-redirect` controls redirects, and `auto-cookie` uses a temporary cookie jar for that request and its redirects.
- `$persistentStore` is shared by the whole kernel process, with Surge's naming: scripts with the same script path share the default key, and explicit keys are shared by all scripts. A script with neither a download URL nor a file path uses its ID as its path. Limits on desktop and Android are 4 MiB per value and 16 MiB in total; on iOS they are 256 KiB and 1 MiB. Keys are at most 1 KiB, and the total counts both keys and values. A write over a limit returns `false`. When the kernel has a state directory, writes are coalesced over one second and saved atomically to `scripts/store.json` with mode `0600`, and pending writes are flushed on shutdown. Without a state directory the store is kept in memory.
- `$notification.post` publishes a `script.notification` control API event for clients to display. Each script refills 10 notifications per minute with a burst of 5, and at most 60 are accepted in any one-minute window across all scripts. Dropped notifications are counted in the MITM status. [Events](control-api.md)
- `$utils.geoip` and the ASN lookups have no runtime data source yet and return `null`.
- Background run records capture up to 64 lines and 16 KiB of `console` output per run. Set `mitm.script-log: true` in `local.yaml` to also write script console output to the kernel log at debug level with the script ID. [MITM settings](configuration-reference.md)

## Refresh and caching

`module add` acquires the module and its resources before committing the profile entry and source snapshot together. Scheduled refreshes check enabled remote modules. Local modules are read on addition or explicit refresh. Manual refresh also works for disabled modules. Enabling a module without a matching snapshot acquires one during enablement.

Acquisition uses conditional requests, redirects, transport timeouts, backoff and stale status. Some module hosts serve modules and scripts only to the app a format targets, so the module, its Map Local files and its scripts are requested with that app's user agent: Surge iOS for Surge modules, Loon for Loon plugins and Stash for Stash overrides. The user agent is kept across redirects. It is not part of the cache key, so cached entries stay valid. The original module and the converted input after argument expansion are each limited to 16 MiB. A module can reference up to 32 distinct Map Local URLs of at most 15 MiB each and up to 128 distinct script URLs of at most 2 MiB each. The complete bundle is limited to 32 MiB. A successful refresh emits `module.updated`. A failed module or Map Local download or a rejected transaction preserves the previous snapshot and records a failure code. [Subscription downloads and caches](subscriptions.md#acquisition-and-caches)

Script sources are pinned after Map Local files. If a script download fails, Reka retains a usable cached copy that matches the previous lock. With no such copy, the report marks the line `module.script-unavailable` and the rest of the module remains available. A failed script is retried after its update interval or 30 minutes, whichever is shorter. Refresh status identifies each failed script by the SHA-256 of its URL and a short error code such as `body_too_large`. For remote modules, the earliest due entry determines the next check. If several lines reference the same script URL, its shortest interval applies.

When `SetModuleArguments` (or `rekactl module set-arguments`) makes an enabled module reference a Map Local or script URL absent from its snapshot, the service acquires a new snapshot and commits it with the arguments. Direct profile edits use the current lock until the module is refreshed. Exports include the original module text and its resource blobs.

## CLI and control API

```sh
./bin/rekactl module preview ./filters.sgmodule -argument PROXY='Example route'
./bin/rekactl module preview ./filters.plugin -argument PROXY=direct
./bin/rekactl module add filters https://example.com/filters.sgmodule -argument PROXY='Example route'
./bin/rekactl module add overrides https://example.com/download -format stash
./bin/rekactl module add local-filters -file /path/to/filters.sgmodule -disabled
./bin/rekactl module list
./bin/rekactl module report filters
./bin/rekactl module set-arguments filters -argument PROXY=direct
./bin/rekactl module refresh filters
./bin/rekactl module disable filters
./bin/rekactl module enable filters
./bin/rekactl module remove filters
```

Use `-format` on `add` or `preview` to select a dialect, `-position N` to insert at a zero-based module index, `-interval N` to set the remote refresh interval, or `-argument NAME=VALUE` repeatedly. `set-arguments` replaces the argument map, and passing no arguments restores defaults. The CLI waits for refresh unless `-async` is set. Pass `-` to preview from stdin, or put `-json` before `module` for machine-readable output.

The control API exposes `AddModule`, `RemoveModule`, `SetModuleEnabled`, `SetModuleArguments`, `RefreshModule`, `ListModules`, `GetModuleReport`, and `PreviewModule`. Mutating profile calls use `base_revision`. `ListModules` returns format, source type, status, metadata, argument declarations and the available effective report summary. `GetModuleReport` returns the current effective report for an enabled module. `PreviewModule` accepts optional `format` and `filename` fields, uses current effective policies, and performs no network or configuration writes. The preview reports remote Map Local references and scripts as unavailable without a lock. The preview, report and list summary include script counts and the lock status of convertible script lines. `GetCapabilities` advertises `surge-module`, `loon-module`, and `stash-module` in `source_formats`. [Control API](control-api.md#模块)

## Mobile preparation

Mobile apps can pass an ordered `deviceModules` list when preparing native profiles or imported subscriptions such as Clash. Device modules follow modules declared by the profile. If an ID appears in both lists, the profile declaration takes precedence. Supply app-managed snapshot paths for enabled modules in `modules`. With `rebindSnapshot`, omit `deviceModules` to keep the archived list or pass `[]` to clear it.

App-managed and kernel-service snapshots pin both Map Local files and script sources. Mobile module preview accepts an explicit `format` or a `filename` hint for raw text. An existing snapshot supplies its pinned format.
