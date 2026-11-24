# Sources and overlays

The source layer accepts **normalized native snapshots**. [Local Clash/share-link conversion](clash-import.md) runs before this layer; [background downloads, provider resources and stale-cache reporting](subscriptions.md) feed it too. [Surge modules](modules.md) keep their original text in a locked source snapshot and convert it during composition.

## Documents and ownership

Each immutable revision contains `profile.yaml`, `local.yaml`, `sources.yaml` and `overlay.yaml`. The last two are empty when upgrading a state root created before sources and overlays existed; old revisions remain readable without rewriting them. Restore restores all four documents as a new revision.

Sources hold imported content. The profile decides what to use and where to place rules. The overlay holds persistent user edits. Local settings own machine-specific listeners, logging, and `mitm.enabled` and `mitm.ca`. Composition is defaults → sources → profile → overlay → local settings.

Local source and import operations remain network-free. The importer and the refresh worker submit a replacement `sources` document through the same `PlanConfiguration`/`CommitConfiguration` transaction. Replacing sources alone preserves the other documents byte for byte. Concurrent changes use the existing base-revision conflict checks.

## Minimal example

`sources.yaml`:

```yaml
schema-version: 1
sources:
  - id: airport
    outbounds:
      - {id: a, name: First route, type: direct}
      - {id: b, name: Second route, type: direct}
    groups:
      - {id: proxy, type: select, members: [a, b], selected: a}
    rules:
      - {id: remote, match: {domain-suffix: example.org}, outbound: proxy}
```

The two direct routes make the example runnable without a remote server. Real snapshots can use any currently supported native outbound type and `secret://` references.

`profile.yaml`:

```yaml
schema-version: 1
imports:
  - {source: airport, outbounds: true, groups: true}
rules:
  - {id: lan, match: {domain-suffix: [lan, local]}, outbound: direct}
  - {source: airport}
  - {id: final, match: {all: true}, outbound: airport/proxy}
```

Use `modules` and `{module: ID}` for locked module snapshots. They have their own [composition order](modules.md#composition).

`imports` selects `outbounds`, `groups`, `rule-sets`, `sub-rules`, and `rewrites`. At least one selection must be true. Import each source once. Rules are included separately. A `{source: airport}` marker expands the source's ordered rules exactly at that location. A marker cannot also contain `match` or `outbound`. It may have an ID to address the marker in the original profile. Expanding the same rules twice produces duplicate IDs and is refused.

`overlay.yaml`:

```yaml
schema-version: 1
patches:
  - {op: set, path: /groups/airport~1proxy/selected, value: airport/b}
  - {op: set, path: /outbounds/airport~1a/name, value: My first route}
  - {op: remove, path: /rules/airport~1remote}
  - op: insert
    path: /rules
    before: final
    value: {id: my-rule, match: {domain: my.test}, outbound: reject}
```

`local.yaml`:

```yaml
listeners:
  - {id: mixed, type: mixed, listen: "127.0.0.1:17890"}
```

On an empty state root:

```sh
./bin/reka -state-root /tmp/reka-demo -profile profile.yaml -local local.yaml \
  -sources sources.yaml -overlay overlay.yaml
```

In another terminal:

```sh
./bin/rekactl -state-root /tmp/reka-demo get sources
./bin/rekactl -state-root /tmp/reka-demo origin /groups/airport~1proxy/selected
./bin/rekactl -state-root /tmp/reka-demo select airport/proxy airport/a
./bin/rekactl -state-root /tmp/reka-demo plan -sources refreshed-sources.yaml
./bin/rekactl -state-root /tmp/reka-demo commit -sources refreshed-sources.yaml
./bin/rekactl -state-root /tmp/reka-demo get overlay
```

`select` on an imported group records its choice in the overlay. Repeated selections update the existing last selection patch, rather than growing another patch on every click. Selecting a profile-owned group keeps the existing profile edit behavior.

## IDs, overrides and diagnostics

A source ID and its resource IDs use the native stable-ID syntax (letters/digits/`.`/`_`/`-`, maximum 64; first character a letter/digit). **All source rules need IDs**, so reordering does not silently change their identity. IDs are supplied by the normalizing importer; display names are independent.

Composed IDs are `source/id`. Source group members, selected members and rule targets refer to resources inside their source. Undeclared `direct` and `reject` refer to built-in actions; if the source explicitly declares such an ID, its local resource wins. Other unknown references remain source-scoped and fail validation, rather than binding to a similarly named profile resource.

API paths use JSON Pointer escaping, so the ID `airport/proxy` is one segment, `airport~1proxy`. Profile group members and rule targets use the unescaped ID. Different sources can use the same local IDs.

A profile outbound or group with the exact imported ID replaces that whole object. Use the overlay for partial edits. Patches execute in order. For resource lists, `set` and `remove` target existing resources by stable ID. `set` may add optional fields, and resource identity stays fixed. `insert` targets a resource list and adds a resource with a new native stable ID. Use literal IDs for `before` and `after`.

Removing a node disables it. Its group references and selections must also be repaired explicitly. Missing sources, deleted or renamed targets, stale overlay paths, invalid selections and cycles refuse the transaction; the previous revision keeps running. There is no automatic fallback to DIRECT or guessed rename association.

`effective.provenance` records the layer, document, original path, line and column; imported fields also name their source. Overlay edits record the origin they replaced. Semantic errors point to the source/overlay document rather than generated YAML. `effective.source_hashes` records SHA-256 of each normalized snapshot's canonical YAML mapping (including its ID and comments); revision metadata separately hashes the complete four document files. Enabled modules contribute hashes of their snapshot identities, locks, and profile argument overrides.

## HTTP rewrites and MITM hostnames

Set `rewrites: true` to import a source's `mitm`, `http-rewrites`, `header-rewrites`, `body-rewrites`, and `map-local`. The imported rewrites run before the profile's rules in each list, in `imports` order. A profile rewrite with the same `source/id` replaces the imported rule in place. The profile's MITM hostnames come first, followed by imported hostnames in `imports` order. Defaults, imported sources, the profile, and the overlay set the MITM booleans `h2`, `skip-server-cert-verify`, and `quic-block` in that order, with the last explicit value winning.

In `sources.yaml`, define the rewrite and hostname list.

```yaml
sources:
  - id: filters
    mitm: {hostnames: ['*.example.com', 'obsolete.example.net']}
    http-rewrites:
      - {id: ads, match: '^https://ads\.example\.com/', action: reject}
```

In `profile.yaml`, import the rewrite resources.

```yaml
schema-version: 1
imports:
  - {source: filters, rewrites: true}
```

In `overlay.yaml`, remove the imported rewrite, remove the second hostname, and place an exclusion before the wildcard.

```yaml
patches:
  - {op: remove, path: /http-rewrites/filters~1ads}
  - {op: remove, path: '/mitm/hostnames/#1'}
  - {op: insert, path: /mitm/hostnames, before: '#0', value: '-pinned.example.com'}
```

For the hostname list, `#N` is a zero-based position in the list as it exists at that edit. Omitting `before` and `after` appends the hostname. The first hostname match wins, so placing the exclusion ahead of `*.example.com` excludes `pinned.example.com`. For the full field reference, see [MITM and HTTP rewriting](configuration-reference.md#11-mitm-与-http-重写).

## Transactions and editing

The API accepts whole `sources`/`overlay` strings and `sources_patch`/`overlay_patch` structural edits alongside the existing profile/local fields. They participate in validation, planning, operation identity, conflict reporting and crash recovery. Submit one request for related changes that must be atomic. No HTTP requests or subscriptions are refreshed during validation or planning.

`rekactl get`, `validate`, `plan`, `commit`, `set` and `remove` support the new documents (`-sources`/`-overlay` for edit commands). `GetCapabilities` advertises `source_formats: ["native", "clash", "links", "surge-module"]`.

The candidate directory exports all four YAML files. Each saved file is committed individually, so use the API for changes that require several documents together. Invalid candidates stay on disk with `.errors` and do not change the active revision.

API reads mask inline usernames, passwords and UUIDs in profile/source/overlay documents. Sending the masked documents back preserves values at their stored paths. Prefer `secret://` references for credentials. Resolved credentials are excluded from effective-configuration JSON. Conflict differences are masked too. As with profiles, revision files themselves retain inline credentials with owner-only permissions.

The same namespace and overlay paths apply to named `rule-sets` and `sub-rules`. A source rule marker includes its rule dependencies; imports that select only nodes/groups leave those dependencies inactive. See [Rule resources](rule-resources.md) for explicit resource imports, guards and provenance.
