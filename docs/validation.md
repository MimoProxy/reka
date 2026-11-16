# 1.0 candidate validation

This records the implemented M0–M4 scope and the checks completed on 2026-11-16. Packages remain unsigned staging builds until release review and publication. The [configuration reference](configuration.md), [Clash support matrix](clash-support.md), [distribution guide](distribution.md) and [reproducible benchmarks](benchmarks.md) describe the supported contracts.

## Automated checks

- [Implementation checkpoint `3623b7e`: CI](https://github.com/MimoProxy/reka/actions/runs/43827766878) passed all 15 jobs: native tests on macOS, Windows and Linux amd64/arm64; six desktop cross-builds; Android arm64 build; full Linux race/checkptr; and the pinned compatibility reference.
- [Windows installers](https://github.com/MimoProxy/reka/actions/runs/43827766758) passed on both native architectures: fresh installation, configuration-preserving upgrade, owner-change refusal and uninstall with retained state.
- [Stability checkpoint `82ebc37`](https://github.com/MimoProxy/reka/actions/runs/43826051118) passed the configured parser/DNS/rule fuzz targets and 600-second live-stream hot-update soak. An earlier independent one-hour soak completed 15,434 commits and 63,433,740 verified bytes with zero forced closes. These durations do not establish 24-hour endurance.
- [Dedicated real Android CI at `82ebc37`](https://github.com/MimoProxy/reka/actions/runs/43826613960) passed JNI loopback, Kotlin/Keystore/restart and VPN checks on ARM64 API 37. Its exclusive one-shot runner was removed after completion. The change from `82ebc37` to `3623b7e` changes only three `_test.go` port-allocation fixtures; product code, dependencies and build scripts are identical.

Local `make test`, `make vet` and `make race` also passed. Vision and SOCKS UDP use ordinary race/checkptr checks without their former conditional exemptions. Security-carrier tests cover 120 protocol/transport combinations, plus 72 combinations against independent unmodified peers from mihomo v1.19.34. ShadowTLS v2 also passed 6,000 repeated HTTP/2/gRPC combinations across standard TLS and uTLS, with separate TLS 1.2/1.3, small-record, concurrent-write and close checks.

## Platform runtime scope

| Platform | Completed checks | Scope |
| --- | --- | --- |
| macOS | Three TUN stacks; dual-stack default-route TCP/UDP and HTTPS; rule update without TUN replacement; native system proxy and launchd; crash recovery; actual sleep/manual wake; Wi-Fi loss/return | Scheduled automatic wake was not established |
| macOS alternate gateway | Home network → IPv4 hotspot → home network; DNS over TCP/UDP through IPv4/IPv6 TUN addresses; HTTPS on the hotspot; dual-stack HTTPS after return; same device and generation | Hotspot had no physical IPv6 router; its IPv6 HTTPS was unavailable. Return recovery took 4.15 s. Original manual IP, gateway, DNS and proxy preferences were restored |
| macOS coexistence | Stash global takeover plus Reka's two explicit test-host routes, with physical-interface binding | This is the tested split of ownership; it does not establish arbitrary simultaneous global takeovers |
| Windows | Standalone dual-stack full takeover and three-stack targeted forwarding; service ownership and crash restart; sleep/resume and adapter loss/return; final system-proxy recovery; five real-host repetitions of carriers, ShadowTLS and TFO/MPTCP | Full takeover was tested at the earlier platform checkpoint; final protocol and system-proxy checks preserved the user's active Mimo session |
| Android | Real full IPv4/IPv6 VPN; all/include/exclude app routing; actual UID/package and Fake IP process rules; HTTPS, DNS, socket protection; rule-only update; explicit fd/stack/MTU rebuild; Wi-Fi loss/return | Final full-VPN and short memory checks used the same library that passed the dedicated device CI; the test VPN was released afterwards |

Windows coexistence has an explicit constraint: with Mimo's global TUN active, an exclusive WFP DNS-blocking filter was present and the second TUN's UDP DNS probe timed out. The test restored its routes/settings and retained Mimo. Concurrent VPN configurations must coordinate DNS ownership; this case is not counted as a coexistence pass.

Saved-node sampling passed Snell, VMess and VLESS HTTPS/UDP. Separate controlled remote Trojan, Hysteria2 and TUIC peers passed correct-credential HTTPS/UDP and rejected wrong credentials; temporary remote resources were removed. This is protocol sampling, not a connectivity guarantee for every imported node.

## Android resources and power

The locked, Wi-Fi, uncharged A/B measurement used checkpoint `bb23832`, with identical diagnostic polling in both phases and no held wake lock:

| Phase | Elapsed s | Charge used mAh | Whole-phone mean mA | Go sys MiB | Go heap in-use MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 1815.630 | 43 | 85.26 | 13.6–13.9 | 1.9 |
| Full VPN | 1799.995 | 44 | 88.00 | 13.9 | 2.6–3.2 |

The observed difference is 2.74 mA; the combined endpoint quantization bound is 3.98 mA. That bound comes from the charge counter resolution and is not a statistical confidence interval. No numerical additional-current budget was declared, so the result does not assert a numerical power-budget pass.

The final CI library received a separate foreground idle diagnostic, not another long battery run: Go sys 13.6 MiB, VPN heap 2.3–2.4 MiB, and one goroutine after stopping. This meets the original idle Go memory ranges (sys 12–16 MiB, heap 2–4 MiB) for that workload. A separate repeated rebuild stress run reached 18.6 MiB sys/3.2 MiB heap; it is retained as a pressure result. Java/UI, mapped library pages and total process RSS/PSS are separate from these Go metrics. The earlier long power observation is not relabeled as a measurement of the final binary.

Temporary background/precise-alarm allowances were restored. Short interactive tests keep only their own window awake; power tests retain ordinary screen-off behavior.

## Compatibility and distribution boundaries

The original 32 groups of partial/unsupported fields were audited against the pinned reference. Implemented options include ECH/certificate identities, VLESS encryption and Vision combinations, generic mux/Brutal options, all seven SS plugin families, standalone ShadowTLS/Restls/JLS, Hysteria2 Realm/obfuscation/port hopping, provider overrides and health status filters, rule actions/geodata and DNS transports/options. The support table retains meaningful boundaries: the documented protocol set, explicit locked resources/local DNS activation, diagnosed inert options, and relay removed by the reference. The contract does not promise every protocol in mihomo.

All 151 saved node entries (including repeated subscription snapshots) converted in the final local corpus check. Pure conversion still reports unavailable rule/geodata resources, unknown targets and invalid bootstrap DNS instead of silently applying incomplete configurations. The subscription acquisition path supplies explicitly owned resources before activation.

Distribution verification covers six desktop archives, Android arm64 library archive, two unsigned macOS packages and exact corresponding source, with per-artifact hashes, build metadata, linked-module notices and dependency source ZIPs. A clean module/build cache using only the packaged file module proxy rebuilt both commands and ran a real daemon/CLI control exchange. Android 16 KiB segment alignment is structurally checked; this is separate from testing a physical 16 KiB-page device. Linux system takeover, iOS and Mimo GUI integration remain outside M0–M4.
