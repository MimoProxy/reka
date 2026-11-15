# GUI integration contract

The kernel owns every setting that changes network behavior. A GUI may persist its window/theme/layout preferences, but ports, rules, group choices, DNS, sources and takeover are committed to the kernel. Use [API version 1](control-api.md) over a user-restricted local socket/pipe; Android uses the identical JSON objects through JNI.

The native Python/Tk prototype in `examples/gui/client.py` is an independent implementation of framing, request IDs, Hello, events and error handling. It edits all four masked documents, plans a revision-bound change, displays the plan, and commits with a stable operation ID. It supports retrying an uncertain commit with the original request after reconnecting. It never stores a second network configuration on disk.

```sh
python3 examples/gui/client.py --control unix:///path/to/control.sock
# Windows service:
python examples/gui/client.py --control pipe://reka-service
```

Python 3.9+ with Tk is required for the window. The transport client itself uses only the standard library and is testable without Tk. `python3 tools/client-smoke.py` exercises the independent client against an isolated production daemon on Unix; it verifies handshake, capabilities, plan/commit, stale-revision conflict, idempotent retry, events and offline refusal. That contract test does not assert visual polish or Windows GUI rendering.

A production GUI should:

1. Negotiate Hello and discover capabilities; do not infer support from a protocol name or platform name.
2. Load all configuration layers with the active `revision`; keep credentials masked unless the user explicitly reveals them.
3. Validate and plan the exact candidate. Display diagnostics, conflicts, takeover interruption and restart requirements. A changed editor invalidates its previous plan.
4. Commit the exact request with `base_revision`, `plan_hash`, and an operation ID retained until its final result is known. On transport loss, retry the identical request or use `GetOperation`; do not generate a new ID for an uncertain outcome.
5. Subscribe with an epoch/sequence cursor. Snapshot, dropped events, changed epochs and reconnects require a fresh snapshot. Mark state stale and disable submission while disconnected. Do not overwrite unsaved editor contents when an event arrives.
6. Display runtime state separately from configuration intent, including `start_error` and `runtime.network.state`. A stored TUN setting does not imply a running VPN or working IPv6.

Stable IDs in patch paths must escape `/` as `~1` and `~` as `~0`. Source IDs and overlay edits must be retained across subscription refresh. Showing the effective view is useful for provenance, but it is not a replacement configuration document.

The service installer grants access to one explicit UID/SID. Do not broaden the socket permissions or named-pipe ACL to connect a GUI. For Android descriptor and lifecycle coordination, see [Android integration](android-integration.md).
