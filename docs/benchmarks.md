# Reproducible performance measurements

Measured on 2026-11-16 at source checkpoint `3623b7e`, on one Mac16,10 (Apple M4, 10 logical CPUs, 24 GiB RAM, macOS 27.2.1, arm64). The [raw download results and binary build information](benchmarks/2026-11-16-macos-arm64.json) and [raw rule results](benchmarks/2026-11-16-rules.json) accompany this report.

## SOCKS downloads

Each core runs separately on the same host, with a loopback origin and a loopback controlled Shadowsocks server (`aes-128-gcm`). Each of DIRECT and Shadowsocks uses two warmups and five measured 32 MiB downloads. Every download checks its SHA-256. CPU is child user plus system time across startup, warmups and measurements. RSS describes the child process, including mapped code and runtime overhead.

The reference binaries were built locally from mihomo v1.19.34 and sing-box v1.14.4. Reka uses Go 1.27.4; the two references use Go 1.27.3. Their executable version strings, full build tags and module versions are retained in the raw results. The runs are sequential and the host is not otherwise isolated, so these small samples describe this workload and include scheduling noise.

| Core | Route | Median MiB/s | Range MiB/s | Child CPU s | Idle RSS MiB | Peak RSS MiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| reka | direct | 2419.4 | 2345.2–2612.0 | 0.0516 | 21.7 | 22.7 |
| mihomo | direct | 2527.0 | 2417.1–2612.7 | 0.0471 | 33.8 | 34.4 |
| sing-box | direct | 2464.2 | 2380.6–2585.1 | 0.0596 | 34.4 | 36.8 |
| reka | shadowsocks | 2365.7 | 2263.7–2404.3 | 0.1169 | 22.1 | 26.3 |
| mihomo | shadowsocks | 2270.2 | 2192.3–2398.4 | 0.1470 | 33.5 | 37.4 |
| sing-box | shadowsocks | 2339.6 | 2321.4–2413.5 | 0.1156 | 33.9 | 36.1 |

The test covers local TCP throughput, process CPU and RSS. Public-network latency, every proxy protocol, Android battery life and production traffic mixes require their own measurements.

To reproduce, build `bin/reka`, `bin/rekactl` and `bin/benchserver` with the ordinary locked build flags; build the two pinned reference cores, then run:

```sh
python3 tools/compare-bench.py --mihomo /path/to/mihomo --sing-box /path/to/sing-box --mib 32 --samples 5 --output bin/comparison.json
```

## Configuration and rule indexes

`tools/rulebench` measures complete configuration transactions for 10,000 domain rules (three warmups, 20 samples), then 100,000 lookups each in 100,000-domain and 1,000,000-domain immutable indexes. A lookup must return the expected action. Retained heap is the post-GC compilation delta, with input data already allocated before the baseline. Query timings exclude network I/O. Percentiles use the sorted sample at `floor((n-1)*p)`.

| Workload | Entries | P50 ms | P95 ms | Retained heap MiB | Compile ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| rule-only-commit | 10000 | 55.047625 | 56.432709 | — | — |
| rule-set-query | 100000 | 0.000125 | 0.000250 | 8.77 | 29.84 |
| rule-set-query | 1000000 | 0.000250 | 0.000417 | 107.32 | 377.92 |

The 10,000-rule commit P95 is below the original 500 ms target. Binary-size and current-draw limits were not specified numerically; measured values are recorded without inventing a pass threshold.

```sh
OVERLAY=$(python3 tools/build-overlay.py)
go run -modfile bin/build.mod -overlay "$OVERLAY" \
  -tags with_gvisor,with_utls,badlinkname,tfogo_checklinkname0,reka_minimal \
  -ldflags '-checklinkname=0' ./tools/rulebench -samples 20 -queries 100000
```
