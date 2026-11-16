# Process ownership and cumulative application traffic

`process` is an explicit profile/local object:

```yaml
process:
  mode: always
```

The local object replaces the profile object. Omission or an empty mode uses
`rule`, retaining the existing lazy behavior. `always` collects ownership once
for each admitted route evaluation, even when no process condition is reached.
`rule` looks up ownership only when a live routing condition needs it. `off`
does not query the OS and live owner conditions receive unknown ownership.
Changing the policy affects new flows; existing flow metadata is immutable.
`ExplainRoute` can still receive explicit simulated process information.

Connection metadata includes `process_path`, optional `process_uid`, and
`process_pid` when the platform supplies it. Unavailable values are omitted,
never inferred from another application. Darwin's pinned searcher already
identifies a socket PID; the source-hashed overlay now preserves that PID in
the returned ownership object. UID zero and missing UID remain distinct.

`GetProcessTraffic` accepts `offset` and `limit` (default 100, maximum 1000).
It returns `epoch`, `sampled_at`, `total`, `offset`, `limit`, `mode`, `supported`,
`max_entries`, and `rows`. Each row contains a stable `id`, optional
`process_path`/`process_uid`, `upload_total`, `download_total`,
`active_connections`, and `total_connections`. Rows use stable creation order.
All counters cover the current core process and survive configuration changes
and flow closure. Epoch changes on core restart; these are not historical
cross-session totals. Internal DNS and outbound probes do not create entries.

Aggregation is by executable path plus known UID, deliberately excluding PID
to avoid reusing the identity of a terminated process. Traffic from unavailable
owners is retained in one `unknown` row. A maximum of 1024 concrete executable
identities is retained, with at most two additional rows for unknown owners and
`overflow`. New identities beyond the cap, and paths longer than 4096 bytes,
accumulate in the overflow row. Counters are never evicted or silently dropped.
`rule` and `off` can therefore report traffic under unknown ownership; use
`always` for application attribution independent of route predicates.

Counts are successfully forwarded user payload bytes in both TCP directions
and UDP destination flows. They use the same byte points as `GetTraffic`.
TCP and UDP connection counts describe relayed flows; rejected routes and
outbound handshakes that fail before relay are excluded. Active counts retire
once while cumulative bytes remain available. During concurrent forwarding,
a page is a best-effort sampling of monotonic atomic counters.

Verification includes real loopback TCP/UDP traffic retained after closure,
concurrent cardinality overflow, unknown attribution, mode behavior without
owner rules, local override validation, and actual Darwin socket PID lookup.

The Darwin cross-process HTTP test is explicit: compile the sagernet test
binary, then execute it directly with `REKA_TEST_PROCESS_OWNER_INTEGRATION=1`
and `-test.run TestDarwinHTTPProxyFindsCurlProcess`. Some test-runner sandbox
contexts expose only the querying process's socket rows through Darwin's PCB
table, even though an independently launched executable can read the concrete
client's socket ownership. The integration assertion still requires the actual
`/usr/bin/curl` path, UID and PID; unknown ownership does not count as success.

When the Darwin global PCB view cannot find the client, Reka also attempts
same-user `proc_pidfdinfo` socket ownership. This does not elevate privileges or
invoke external commands. A shared, single-flight 200 ms snapshot has a 100 ms
scan budget, at most 2048 PIDs, 16384 socket queries and 8192 retained socket
entries. A miss inside the TTL can refresh new PIDs and applications already
seen with sockets, with a 25 ms budget and at most one incremental refresh per
10 ms. Admission is bounded to 64 callers; excess work remains unknown. TCP requires the exact source and destination tuple. Unconnected UDP
may match the client's local or wildcard bind only when no different PID is
ambiguous. Before returning a cached owner, Reka checks the process birth time,
UID and the same FD's current protocol and tuple again. Closed descriptors and
PID/port reuse therefore do not keep an obsolete application attribution. When
the OS denies access or the budget is exceeded, unavailable owners remain
unknown and their bytes stay accounted in the unknown bucket.
