<div align="center">

<h1>Reka</h1>

<p><strong>English</strong> · <a href="README.zh-CN.md">简体中文</a></p>

<p>A proxy core in Go that owns its configuration and changes it without restarting or dropping connections</p>

<p>
  Reka takes its name from the Russian word “Река,” meaning “river.”<br />
  Change the course, and the water keeps flowing.
</p>

</div>

Reka (the Reka proxy core) is a headless proxy kernel for macOS, Windows and Android. It is being built as the core of the [Mimo](https://github.com/MimoProxy/Mimo) clients, and any GUI can drive it through its control API.

> **Reka 1.1.0.** Download packages from the [release page](https://github.com/MimoProxy/reka/releases/tag/v1.1.0). Builds are unsigned; verify the supplied SHA-256 checksums, build metadata and corresponding source. See the [validation scope](docs/validation.md), [benchmarks](docs/benchmarks.md) and [changelog](CHANGELOG.md).

Version 1.1 adds [atomic profile switching on Unix](docs/profile-switching.md), native GeoIP/GeoSite/ASN rules, process traffic accounting, protocol sniffing, VLESS XHTTP and additional control operations. Profile switching keeps independent histories and subscriptions and retains the original profile on failure. Takeover parameter changes can still rebuild TUN and interrupt its flows. The standalone macOS companion is separate from the original Mimo; these release assets distribute the core and library.

## Why

Clash-style cores read one flat configuration file. GUIs regenerate it, API changes live only in memory, and subscription refreshes overwrite edits; many changes need a reload that drops connections. Reka is designed around two rules:

- **One source of truth.** The kernel owns the configuration. Files, the CLI, the API and GUIs all commit through the same versioned transaction, which is only reported successful once it is running and on disk.
- **Changes without restarts.** Rules, group selections, nodes and listeners change by diffing resources. Connections that are already open keep the outbound they started with until they end.

## What works today

- **Configuration**: a native YAML profile plus per-machine local settings, composed with a recorded origin for every field. Strict parsing with line, column and field-path diagnostics. Edits made by the kernel keep your comments.
- **Sources and overlays**: explicit imports with source namespaces, rule insertion points and persistent parameter/selection edits. Replacing a snapshot uses the same configuration transaction and rejects dangling references. Local Clash/share-link conversion is available with an explicit compatibility report; background HTTP(S) refreshes and referenced HTTP/inline/file providers are available with pinned originals and conditional caches.
- **Transactions**: revision history and restore, conflict detection between clients, idempotent retries by operation ID, crash recovery at every step, and hand-edited files committed through the same path.
- **Hot updates**: outbounds are reused or replaced by fingerprint and drained before closing; listeners bind the new port before the old one stops; a port that is already in use is caught before anything changes.
- **Routing**: ordered first-match rules (`domain`, `domain-suffix`, `domain-keyword`, `domain-regex`, `ip-cidr`, `src-ip-cidr`, `dst-port`, `src-port`, `network`, `process-name`, match-all), with indexed domain rules, locked rule sets/geodata, recursive logic and sub-rules, and route explanations that make no network requests.
- **Protocols**: mixed, SOCKS5 and HTTP listeners, including per-destination UDP; DIRECT, REJECT, HTTP, SOCKS5, SSH (TCP forwarding), Shadowsocks, ShadowsocksR, VLESS + REALITY + Vision + XUDP, VMess, Trojan, AnyTLS, Hysteria v1, Hysteria2, TUIC v5 and Snell v5/v6 outbounds; VLESS encryption also carries Vision over the documented stream transports; VMess/VLESS/Trojan support WS, gRPC, HTTPUpgrade and H2, with generic multiplex. VMess, VLESS, Trojan and AnyTLS support ShadowTLS/Restls/JLS security carriers. Shadowsocks includes all seven documented plugin families. The REALITY client is Reka's own and supports X25519MLKEM768.
- **DNS and groups**: scoped DNS policy/bootstrap/fallback/hosts caches, DoT/DoH/DoQ/DoH3, hosts aliases and generation-aware persisted Fake IP; select/url-test/fallback/load-balance with bounded health probes and separate observed state.
- **Secrets**: `secret://` references stored in the macOS Keychain, Windows DPAPI, an Android Keystore callback, or a 0600 file.
- **Recent additions**: bounded HTTP/TLS/QUIC sniffing, VLESS XHTTP with independent download settings, listener authentication, process/UID/inbound rules and DNS concurrency/stale caching; see [feature expansion](docs/feature-expansion.md).
- **Control API**: length-prefixed JSON over a Unix socket or a Windows named pipe, restricted to the current user, with an event stream; `rekactl` on the command line.
- **System takeover**: local network intent, production TUN routing/DNS hijack, conditional OS-setting recovery, and launchd/SCM installation. Rule-only updates retain the device; runtime verification scope is documented.
- **Android**: JNI/Kotlin binding, borrowed/duplicated VpnService descriptors, protect callbacks, app routing and explicit host VPN rebuilds.

## Build

Go 1.27 or later.

```sh
make build        # bin/reka and bin/rekactl
make test         # unit and end-to-end tests
make android      # bin/android/libreka.so (needs ANDROID_HOME and the NDK)
```

## Quick start

`profile.yaml`:

```yaml
schema-version: 1
outbounds:
  - id: my-ss
    type: shadowsocks
    server: ss.example
    port: 8388
    method: 2022-blake3-aes-128-gcm
    password: secret://outbounds/my-ss/password
groups:
  - id: proxy
    type: select
    members: [my-ss, direct]
rules:
  - match: {domain-suffix: [lan, local]}
    outbound: direct
  - match: {ip-cidr: [10.0.0.0/8, 192.168.0.0/16], no-resolve: true}
    outbound: direct
  - match: {all: true}
    outbound: proxy
```

`local.yaml`:

```yaml
listeners:
  - {id: mixed, type: mixed, listen: "127.0.0.1:7890"}
```

```sh
./bin/reka -profile profile.yaml -local local.yaml   # imported as revision 1; waits for its secret
printf '%s' '<base64 key>' | ./bin/rekactl secret set outbounds/my-ss/password   # now it runs
./bin/rekactl status
./bin/rekactl select proxy direct                     # applied without dropping connections
./bin/rekactl explain www.example.com:443 -resolve
./bin/rekactl revisions
./bin/rekactl restore 1
```

The state lives in `~/Library/Application Support/Reka` (macOS), `%LOCALAPPDATA%\Reka` (Windows) or `~/.local/state/reka` (Linux); pass `-state-root` to use another directory. The active configuration is also exported to `<state-root>/edit/`: saving a change there commits it.

## Documentation

- [Candidate validation](docs/validation.md) · [Benchmarks and raw data](docs/benchmarks.md)
- [Distribution and installation](docs/distribution.md)
- [System takeover](docs/network-takeover.md)
- [GUI integration and native example](docs/gui-integration.md)
- [Android integration](docs/android-integration.md)
- [Optional Clash-compatible controller](docs/clash-api.md)
- [Configuration and usage guide (中文)](docs/configuration.md)
- [Configuration field reference (中文)](docs/configuration-reference.md)
- [Background subscriptions and providers](docs/subscriptions.md)
- [DNS and Fake IP](docs/dns.md)
- [Automatic groups and health checks](docs/automatic-groups.md)
- [Rule resources, logic and geodata](docs/rule-resources.md)
- [Clash import and limits](docs/clash-import.md)
- [Field support table](docs/clash-support.md)
- [Sources and overlays](docs/source-overlays.md)
- [Control API and Python client (中文)](docs/control-api.md)

## License

[GPL-3.0](LICENSE). Reka builds on protocol components from the [sing-box](https://github.com/SagerNet/sing-box) family (sing, sing-tun, sing-vmess, sing-shadowsocks and others); it is an independent project and is not affiliated with or endorsed by sing-box.
