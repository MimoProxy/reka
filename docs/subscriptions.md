# Background subscriptions and providers

Remote acquisition wraps the existing native source/import transactions. It supports scheduled and manual HTTP(S) refreshes, conditional caches, immutable original documents and referenced HTTP/inline providers. Runtime protocol, DNS, automatic-group and rule execution support remains the [documented subset](clash-support.md); rule resources execute as described in [rule resources](rule-resources.md).

## CLI

With Reka running:

```sh
./bin/rekactl subscription set airport 'https://subscription.example/list' -interval 3600 -nodes-only
./bin/rekactl subscription list
./bin/rekactl subscription refresh airport
./bin/rekactl subscription pause airport
./bin/rekactl subscription resume airport
./bin/rekactl subscription remove airport
```

`set` versions the definition and preserves an existing snapshot. The daemon's scheduler notices enabled definitions. `refresh` explicitly checks the root and all referenced providers and waits for a result. `pause` disables automatic checks; manual refresh remains available. `resume` restores the schedule, including any remaining backoff. `remove` removes only the refresh definition, preserving the materialized snapshot and its resource lock.

Use a secret reference and supply the URL through stdin, for example from a private file:

```sh
./bin/rekactl secret set subscriptions/airport/url < /path/to/private-url.txt
./bin/rekactl subscription set airport secret://subscriptions/airport/url -nodes-only
```

`-format auto|clash|links`, `-nodes-only` and `-allow-partial` follow [local import semantics](clash-import.md). Full incomplete conversions are blocked by default. Adding a subscription does not modify profile routing or machine listeners. After the first successful refresh, reference the source using the existing [imports/overlay contract](source-overlays.md).

## Versioned definition

A source may contain:

```yaml
id: airport
subscription:
  url: secret://subscriptions/airport/url
  format: auto
  interval: 3600
  nodes-only: false
  allow-partial: false
  paused: false
  headers:
    - {name: Authorization, value: secret://subscriptions/airport/authorization}
# outbounds/groups/rules and lock are the last successful materialization
```

Interval 0 means 3600 seconds; explicit intervals are 30–604800 seconds. Inline URLs and every header value are masked in ordinary configuration reads and conflict differences. Masks round-trip by stored field identity; `ConfigureSubscription` restores masked headers by name. Explicit `reveal` remains available. Prefer secret references because revision documents and original downloaded bodies otherwise contain inline credentials in owner-only files.

## Acquisition and caches

- Only HTTP/HTTPS GET, normal certificate verification, 15-second request timeout and 60-second whole-refresh timeout. At most 4 source jobs run at once; same-source requests share the running job.
- Each resource is limited to 16 MiB, the complete bundle to 32 MiB, with at most 16 referenced providers and two explicit geodata assets. Header size and redirects are bounded too.
- Cross-origin redirects discard custom/authentication headers and URL user info; HTTPS-to-HTTP redirects are refused. Only the configured user-owned URL/headers resolve `secret://`. A remotely declared provider cannot read local secrets.
- Downloads use a direct HTTP transport rather than environment proxy variables. Android passes the host's socket `protect()` callback to subscription connections and Go DNS sockets. Desktop default-route/TUN bypass is covered by [system takeover](network-takeover.md).
- ETag and Last-Modified are sent only with a hash-verified body locked in the active revision. A 304 without a complete valid cached body is an error. Background checks respect root/provider intervals; manual checks bypass the timers. A shorter configured interval takes effect without waiting for the old interval to expire.
- Bodies and validators remain staged until the complete bundle converts, validates and commits. Bad downloads, malformed content, unsupported conversion or a rejected transaction keep the previous snapshot and validators. First failure produces `failed`, never an empty successful source.
- Failures mark the source stale and back off exponentially from 30 seconds to at most 30 minutes. Status has safe error codes, last attempt/success, next attempt, revision and root hash; it does not include download URLs or header values.

## Providers

Example root document:

```yaml
proxy-providers:
  pool:
    type: http
    url: https://provider.example/proxies.yaml
    interval: 1800
    header:
      User-Agent: [Reka]
  extra:
    type: inline
    payload: [{name: backup, type: direct}]
proxy-groups:
  - {name: Choice, type: select, use: [pool, extra]}
rules: ["MATCH,Choice"]
```

Normally only resources referenced by group `use`/include-all, DNS rule-set selectors or `RULE-SET` conditions (including logical operands and sub-rule blocks) are fetched. Nodes-only mode deliberately includes all declared proxy providers and skips rule providers. HTTP proxy payloads must contain a nonempty `proxies` list; inline payloads are lists of proxy mappings. Missing providers, malformed payloads, nested providers and unsupported provider options reject the bundle. No partial provider network failure is accepted, even with allow-partial.

Provider nodes have stable IDs derived from `provider-name/original-node-name`; the original node name remains the display name. Two providers can both contain `Node` without an identity collision. A root node whose name collides with that combined identity is rejected. `use` expands providers and members in declared order; group `filter`/`exclude-filter` and `include-all[-proxies/-providers]` are supported using original display names and provider identities. Active provider health checks become explicit generated `provider-health-…` url-test groups; their observations remain runtime state and lazy checks start when a member is used. Provider-level filter/override transformations and download routing through a named proxy remain unsupported.

`path` is an ignored compatibility hint, never a filesystem destination. `type: file` is not implemented. Remote provider credentials use their explicitly declared URL/headers; root credentials are not inherited. Provider intervals and headers are handled independently.

Referenced rule providers support HTTP/inline acquisition and execution with `domain`/`ipcidr`/`classical` YAML or text payloads, and MRS v1 domain/IP payloads. Invalid entries or corrupt bytes reject the candidate. Reka also supports explicit SHA-locked GeoIP/GeoSite protobuf assets via `-geoip` and `-geosite`, recursive logic and sub-rules; see [rule resource semantics and bounds](rule-resources.md). The existing transaction and stale-state guarantees apply to the whole resource bundle.

## Locking, conflicts and recovery

Original documents are immutable SHA-256 blobs in `<state-root>/resources/sha256/`, with owner-only access. The source's versioned `lock` identifies the root and every referenced resource, its kind/name/request identity and rule format/behavior. Original URLs are not part of the public lock. Revision reads/restores and commits verify locked blobs locally; they do not download anything. No blob garbage collection runs yet, preserving all historical revision references.

Downloads occur outside the configuration mutex. At commit, unrelated profile/overlay/local/other-source changes are rebased up to three times. An edit or deletion of the same source rejects the fetched result instead of overwriting it. Successful refresh changes only that source; existing manual selections and overlays remain subject to normal reference validation. A removed selected node does not silently become DIRECT.

The native snapshot and complete resource lock commit together. Blobs are synced before the revision is written; cache promotion follows activation. A crash before cache promotion can lose a validator optimization, but cannot activate half a bundle. Restart/restore uses the pinned native snapshot and original resources. Shutdown cancels network requests, waits for workers and then closes the runtime.

## API and events

- `ConfigureSubscription`: `{source_id, base_revision, subscription}`; null subscription removes the definition. Definition edits go through ConfigService and do no networking inside the transaction.
- `ListSubscriptions`: safe observed statuses.
- `RefreshSubscription`: `{source_id, wait}`; default returns `refreshing` promptly, `wait: true` waits for completion. Multiple requests for one source share the job.
- `subscription.updated` events contain the same safe status. Request/library error strings containing URLs are not published.

Validate/Plan remain network-free. Fetching is performed by the scheduler or explicit refresh, and every activation still uses the ordinary configuration transaction.
