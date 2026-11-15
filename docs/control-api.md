# Reka control API (version 1, draft)

## Transport

- macOS and Linux: a Unix domain socket, by default `<state-root>/control.sock`, mode 0600. Connections from another user (other than root) are refused after checking the peer's credentials.
- Windows: a named pipe, by default `\\.\pipe\reka-<hash of user and state root>`. Its DACL admits only the current user and LocalSystem, remote clients are rejected, and each client's process token is checked.
- Android: the host calls the library directly (`Native.call`); the messages are the same.

Each message is one frame: a 4-byte big-endian length, then that many bytes of JSON. Frames are limited to 16 MiB.

```json
{"id": 7, "method": "GetStatus", "params": {}}
{"id": 7, "result": {...}}
{"id": 7, "error": {"code": "conflict", "message": "..."}}
{"event": {"epoch": "9f2c...", "seq": 41, "type": "config.committed", "time": "...", "data": {...}}}
```

A session must start with `Hello`:

```json
{"id": 1, "method": "Hello", "params": {"versions": [1], "client": "my-gui/1.0"}}
```

The server picks a version both sides speak (`unsupported_version` otherwise) and returns its `epoch`, which changes on every start.

## Methods

| method | params | result |
| --- | --- | --- |
| `GetCapabilities` | | API and schema versions, outbound, listener and group types, rule conditions, Shadowsocks methods, TLS fingerprints, platform, process lookup |
| `GetStatus` | | active revision, runtime generation, listeners, outbounds, connections, draining instances |
| `GetConfiguration` | `reveal` | `revision`, `profile`, `local` (inline credentials masked unless `reveal`), `effective` with `provenance`, `diagnostics` |
| `ValidateConfiguration` | change | `valid`, `diagnostics` |
| `PlanConfiguration` | change | `plan`, `plan_hash`, `diagnostics`, or `conflict` |
| `CommitConfiguration` | change + `operation_id`, `plan_hash`, `message` | result |
| `GetOperation` | `operation_id` | result |
| `ListRevisions` | | `active`, `revisions` (newest first) |
| `RestoreRevision` | `revision`, `base_revision`, `operation_id` | result |
| `ListConnections` | `offset`, `limit` (≤ 1000) | `total`, `connections` |
| `CloseConnections` | `ids` or `all: true` | `closed` |
| `ExplainRoute` | `destination` (`host:port`), `network`, `source`, `addresses`, `resolve`, `process` | matched rule, group chain, outbound and instance fingerprint; `undetermined` when an ip rule needs a lookup that was not allowed |
| `Subscribe` | `types`, `epoch`, `after` | starts pushing events |
| `Unsubscribe` | | |
| `SetSecret` | `name`, `value`, `apply` (default true: recompile so outbounds pick it up) | `ref`, `apply` result |
| `DeleteSecret`, `ListSecrets` | `name` | names only, never values |

A **change** is relative to `base_revision`, which must be the active revision:

```json
{
  "base_revision": 12,
  "profile": "schema-version: 1\n...",
  "local": "...",
  "patch": [
    {"op": "set", "path": "/groups/proxy/selected", "value": "hk"},
    {"op": "insert", "path": "/rules", "before": "final", "value": {"match": {"domain": "a.test"}, "outbound": "direct"}},
    {"op": "remove", "path": "/rules/old-rule"}
  ],
  "local_patch": []
}
```

Whole documents and patches can be combined; patches apply afterwards. Paths use IDs, never list indexes (unless an element has no ID: `#3`). Patched documents keep their comments.

A commit **result**:

```json
{"operation_id": "op-...", "state": "committed", "revision": 13, "generation": 20, "plan": {...}, "diagnostics": [...]}
```

`state` is `committed`, `rejected` (nothing changed; see `error.code`: `conflict` with `conflict.changes`, `invalid`, `prepare_failed`, `blocked`, `plan_changed`, `bad_request`) or `failed` (the switch failed and the previous revision was restored; `degraded` if a listener could not be put back). A result is final once returned: it is recorded under the operation ID before it is sent, and repeating the request with the same ID returns it again. The same ID with different content is refused (`operation_reused`).

## Events

`Subscribe` takes an optional cursor (`epoch`, `after`). If the cursor is from this epoch and still in the server's history, missed events are replayed; otherwise the first event is a `snapshot` with the current state. Types: `config.committed`, `config.rejected`, `runtime.generation`, `candidate.invalid`. Each subscriber has a bounded queue; if it reads too slowly, events are dropped and the next delivered event carries `dropped` with the count.
