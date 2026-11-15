# System takeover

Network settings live only in `local.yaml`; sources and profiles cannot install OS routes or a system proxy. All edits use the same validate → plan → commit transaction as other configuration. Discover `network_modes` and `tun_stacks` through `GetCapabilities`.

```yaml
network:
  mode: tun
  service: Wi-Fi              # macOS network service; not an interface name
  tun:
    stack: mixed              # mixed, system, gvisor
    mtu: 1500
    address4: 172.19.0.1/30
    address6: fdfe:dcba:9876::1/126
    dns-hijack: true
    # routes: [223.5.5.5/32]   # absent = default routes for configured families
    # exclude-routes: [10.0.0.0/8]
    # bind-interface: en1      # optional explicit physical interface
```

Configure profile DNS with explicit `nameserver` and `default-nameserver` IP endpoints before full takeover. `system` upstreams are rejected in full mode because the OS resolver may point back to Reka. Node and subscription bootstrap use the explicit resolver and the same socket bypass as other internal traffic. Bootstrap and node-resolution endpoints cannot depend on the proxy they resolve.

Only configured address families are captured; `runtime.network.ipv6: false` means IPv6 is not claimed. DNS hijacking consumes TCP/UDP port 53 locally, including the Windows gateway DNS address. Other traffic to a TUN's own address is dropped. Encrypted application DNS follows normal routing and is not intercepted as port-53 DNS.

The runtime reuses a TUN device for rule/selection changes. Address, stack, route, MTU, app routing and mode changes are marked `network_changed` and `interrupts` in the plan and can interrupt TUN flows. The socket guard follows the current physical default interface for **new sockets** and never resets existing generations; recognizable VPN interfaces are refused as bypass interfaces. Reka does not fight another VPN for settings.

For a system proxy:

```yaml
listeners:
  - {id: mixed, type: mixed, listen: "127.0.0.1:7890"}
network:
  mode: system-proxy
  proxy-listener: mixed
  service: Wi-Fi             # macOS only
```

macOS reads HTTP, HTTPS and SOCKS endpoints with `networksetup` and commits each endpoint atomically through SystemConfiguration preferences (`scutil --prefs`), including removal of empty prior endpoints; Windows sets WinINet proxy values for the service's explicit owner SID. Applications using other proxy stacks may ignore these settings. PAC/WPAD and authenticated macOS system proxies are refused when their prior state cannot be preserved by this implementation. The service owner's Windows user registry hive must be loaded. Changing a Windows setting from LocalSystem may require applications in another interactive session to reopen their network session; session-wide notification is not asserted by the tests.

An OS file lock on the state root is acquired before recovery; another live kernel cannot have its settings mistaken for crash residue. The lock is released automatically on process death.

Before each DNS/proxy mutation, `<state-root>/network/ownership.json` durably records the old and installed values. Stop and next-start recovery restore a value only while it still equals the installed value. An external change is preserved. Failed recovery remains in the journal and surfaces as `Degraded`; explicitly commit `mode: off` to retry cleanup before enabling takeover again. Do not delete the journal to hide a failure. Routes belong to sing-tun and its process-owned device; Reka does not add a second route manager.

macOS DNS uses the explicitly selected network service. On a service change, update `network.service` through a planned transaction. Interface monitoring updates new outbound socket bindings; it does not promise uninterrupted existing TCP sessions after the underlying network disappears. Sleep/wake, network transitions, and coexistence require platform runtime acceptance.

Service installation is separate from enabling takeover. See [distribution and installation](distribution.md). Linux intentionally offers loopback mode only in 1.0.
