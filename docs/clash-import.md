# Clash subscription import

The importer converts local Clash YAML or share-link text into one native source snapshot. This local command resolves inline providers but does not download HTTP resources. [Background subscriptions and provider acquisition](subscriptions.md) happen outside this pure conversion path. Neither path changes the profile/local settings/overlay. Runtime support remains limited to the current native protocols and rules. See the generated [field support table](clash-support.md).

Conversion has been checked against a small set of real, anonymized subscriptions: all of their VMess and VLESS nodes convert. Providers, rule sets, logical rules and explicit GeoIP/GeoSite assets are covered in [rule resources](rule-resources.md); automatic groups and DNS in their own documents. Some subscription rules and auxiliary groups still need references or options Reka does not support; a partial import is not evidence of complete subscription compatibility.

## Preview and apply

Start Reka normally, then preview a local file:

```sh
./bin/rekactl import -source airport subscription.yaml
./bin/rekactl -json import -source airport subscription.yaml
```

A report gives imported/total counts, unavailable resources, ignored fields, original-name-to-ID mappings and diagnostics with document, path, line and column. The JSON result also contains normalized `sources` YAML with credentials masked. Preview has no side effects. A blocked preview exits nonzero.

The default full conversion reports unsupported nodes, groups, rules, provider fields and DNS fields; **any unavailable content blocks application**. To import just the supported nodes explicitly:

```sh
./bin/rekactl import -source airport -nodes-only subscription.yaml
./bin/rekactl import -source airport -nodes-only -apply subscription.yaml
```

`-nodes-only` intentionally excludes groups, rules and DNS. Remote refresh includes proxy-provider nodes; pure local import can expand inline proxy providers. Add profile references/groups using the existing [sources and overlays](source-overlays.md) contract. For example, get the node's stable ID from the preview, reference `airport/p-…` in a profile group and keep machine listeners in local settings.

After reviewing the report, `-allow-partial` explicitly accepts omitted resources and options:

```sh
./bin/rekactl import -source airport -allow-partial subscription.yaml
./bin/rekactl import -source airport -allow-partial -apply subscription.yaml
```

Partial mode can change routing: unavailable rules are absent and unsupported members/groups are excluded. A remaining select group selects its first available member, which may be an explicitly listed DIRECT. This mode is not full compatibility. User selections already stored in the overlay survive only if their target still exists; otherwise the normal transaction rejects the refresh. Unknown targets are never guessed or automatically converted to DIRECT. All-unsupported nodes-only input is rejected as empty.

`-apply` first plans, then commits the normalized snapshot through ConfigService. Repeating an import under the same source ID replaces that source only. Other sources and profile/overlay/local documents remain intact. The usual base-version, plan-hash, operation-ID, preparation and recovery guarantees apply. Import does not automatically rewrite profile references or enable imported rules/DNS. Activate a source DNS explicitly with `dns: {from: airport, listen: "127.0.0.1:5353"}`; imported remote listen addresses are ignored.

## Stable identities and metadata

Names are matched exactly, including Unicode, whitespace and slashes. The importer generates portable IDs `p-<96-bit SHA-256 prefix>` for nodes and `g-<prefix>` for groups from their original names. Reordering, server changes and credential rotation keep the ID; renaming produces a new one. Duplicate names across nodes/groups and reserved DIRECT/REJECT names are errors. Native source namespacing still adds `source/`.

Rule IDs hash the normalized condition, modifiers and target; preceding insertions do not rename existing distinct rules. Identical repeated rules receive an occurrence suffix. Rule order is preserved. Group `icon` and display name survive in `effective.group_metadata`; display metadata does not rebuild protocol instances.

Select groups retain supported members in original order. Unsupported group types are never approximated as select. Cycles and unknown members make the relevant group unavailable; availability pruning is independent of definition order. Unsupported protocol options invalidate their node, rather than silently changing its transport, TLS or authentication. Known VMess-only `cipher`/`alterId` fields on VLESS are tolerated with an ignored-field diagnostic.

## Sharing links

```sh
./bin/rekactl import -source links -format links -apply links.txt
```

Auto-detection supports plain or base64-encoded lists. Implemented node formats are VLESS (`security=none/tls/reality`, TCP/WS/gRPC/HTTPUpgrade), Shadowsocks SIP002 (base64 user-info or legacy complete authority), conventional base64-JSON VMess, Trojan, Hysteria2/`hy2` and TUIC v5 URLs. Unknown query options, duplicate query parameters, plugins and unsupported transports do not silently disappear. `#` comment lines and blank lines are skipped.

## API

`GetCapabilities` advertises `source_formats: ["native", "clash", "links"]` and the machine-readable `import_support` field matrix.

Pure conversion:

```json
{"method":"ImportSource","params":{"import":{"source_id":"airport","format":"clash","data":"proxies: ...","nodes_only":true},"reveal":false}}
```

Response: `report`, normalized `sources` YAML and `masked` count. `reveal: true` explicitly requests inline credentials; normal reads are masked.

The existing `ValidateConfiguration`, `PlanConfiguration` and `CommitConfiguration` accept an additive `import` field:

```json
{
  "base_revision": 12,
  "import": {"source_id":"airport","format":"auto","data":"proxies: ...","nodes_only":true},
  "operation_id": "refresh-airport-13",
  "plan_hash": "<from PlanConfiguration>"
}
```

Whole documents/patches are built first, then import replaces/inserts the named source. A single request can also update profile references or an overlay when these must change atomically. Incomplete imports return `invalid` with their diagnostics, leaving the active revision unchanged. Import request data participates in operation identity; the normalized four documents participate in the plan hash. `ImportSource` preview output with masked credentials is for review; submit the original input in the transaction, not its masked preview.

### File providers, transformations and download routes

Set the local subscription `provider-directory` (or `rekactl subscription set
-provider-directory /absolute/directory ...`) before refreshing file providers.
Provider `path` values resolve inside that directory using `os.Root`; traversal,
absolute paths and symlinks escaping the root fail. Pure import never reads files:
`ImportProviders` accepts already loaded and locked resource bytes.

Proxy-provider filters run against original names, in backtick-separated filter
priority, before overrides. Structured overrides, regex name replacement,
prefix/suffix and the pinned reference's `override-expr` subset run before node
validation. Unknown options or invalid output reject the bundle.

A provider's `proxy` uses an already active outbound/group; missing or rejected
routes fail without direct fallback. An HTTP provider may declare startup
`payload`: on its initial transport/status failure this is locked as the actual
resource and listed in `fallback_resources`. A later failure preserves the
committed snapshot. Invalid response bodies do not select startup fallback.
