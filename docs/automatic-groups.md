# Automatic groups and health checks

Groups form a validated acyclic graph. Manual selections remain versioned configuration; health measurements and automatic choices are observed state.

```yaml
groups:
  - id: auto
    type: url-test
    members: [hk, jp]
    url: https://www.gstatic.com/generate_204
    interval: 300        # seconds
    timeout: 5000        # milliseconds
    tolerance: 50        # milliseconds; keep a healthy current member within tolerance
    lazy: true
  - id: backup
    type: fallback
    members: [hk, jp]
    lazy: false
  - id: balanced
    type: load-balance
    members: [hk, jp]
    strategy: consistent-hashing
  - id: proxy
    type: select
    members: [auto, backup, balanced, direct]
    selected: auto
```

`url-test` picks the fastest healthy member, with tolerance to avoid unnecessary switching. `fallback` picks the first healthy member in declared order. When every check fails, these groups attempt their first configured member; they never add an implicit DIRECT route. `load-balance` distributes among healthy members (configured members before observations) using round-robin or consistent hashing. A manual explicit `selected` value takes precedence.

Native `include-all: true` expands native outbounds, confined to the same source namespace for source groups. `filter` and `exclude-filter` are RE2 expressions over display names. Imported Clash `use`, `include-all`, `include-all-proxies` and `include-all-providers` expand while preserving provider identity and original names. `disable-udp` rejects UDP routed through that group chain.

Probes run through the actual tested outbound. At most four probes run concurrently per generation, with up to four workers per group. They are cancellable, use the configured timeout, read at most 4096 response bytes, do not follow redirects, and treat HTTP 200–399 as healthy. Defaults: interval 300 s, timeout 5000 ms, lazy true, the URL shown above. Limits: interval ≤604800 s, timeout ≤60000 ms. Lazy jobs start after group/member use; route explanation alone does not start jobs or advance round-robin.

Active provider `health-check` fields (`enable`, `url`, `interval`, `timeout`, `lazy`) become explicit generated `provider-health-…` url-test groups in the source. Disabled checks are ignored; nodes-only import does not create jobs. Provider-level transforms/filter/override and file providers remain unavailable.

```sh
./bin/rekactl group-status
./bin/rekactl -json group-status
./bin/rekactl select proxy backup
```

`GetGroupStatus` returns each automatic group's `id`, `type`, observed `selected`, and member `alive`, `delay_ms`, `checked`. URLs are absent from observed status. Health checks never create a configuration revision, alter a parent select group, or rewrite a source snapshot. Rule-only updates inherit unchanged observations; node/group changes recheck. Shutdown cancels and waits for workers. Existing flows keep their original outbound lease regardless of a later health choice.

Consistent hashing uses stable rendezvous hashing over the destination registrable domain (or IP). Its exact member mapping differs from mihomo's randomized jump-hash implementation; it stays stable across restarts and adding a member only moves keys to that member. Health timing, HTTP success range and scheduling are Reka behavior, not a claim of complete mihomo equivalence.
