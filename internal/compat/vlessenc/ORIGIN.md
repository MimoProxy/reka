# VLESS encryption component

This directory adapts the standalone VLESS encryption transport from
[MetaCubeX/mihomo v1.19.34](https://github.com/MetaCubeX/mihomo/tree/v1.19.34/transport/vless/encryption),
distributed under GPL-3.0-or-later (repository root LICENSE). The original
Xray source revision pointers remain in `doc.go`.

Original source SHA-256:

| File | SHA-256 |
| --- | --- |
| client.go | `1a8fa0684c3d1eded06fd98892e4077e96c70c7ba66cec942db2a04d87d9b405` |
| common.go | `dc75721ecccf5ba74eabac20faaf6fad27f73ed1c322c5cd1c72f732b6c1242b` |
| doc.go | `f2d18460adbbaf7f3f7878bb4f77539455113d9d3ec61778cd5cacc6643fc0e6` |
| factory.go | `92549f444f593910b0f92b6efcee5331c156085c0b6a5d007efd00af7ec6bdc9` |
| key.go | `e4b963257e379bdd6ddeb86eac7b7171e99202a5db8506fc2899dd773138363e` |
| server.go | `0b9f4f76bced3aab0ad6f34a2fd842e58452f1f2431159b1b78ada4a94983643` |
| xor.go | `64ef398cac48e0c88fbf9e3f5180a26cb9a0acc0d7c14d73d18dc1f0e646ac1b` |

Local changes: Go's standard ML-KEM and random APIs replace their forwarding
forks; the already pinned BLAKE3 and CPU feature packages replace equivalents;
a bounded local write-buffer pool replaces the application's pool; read and
write state is serialized; resumed session keys are copied before appending.
Client handshakes support context cancellation (including padding delays),
relay keys and padding have explicit budgets, and test-server session cleanup
stops immediately on close. These changes do not alter valid wire framing.
Reka owns configuration, socket protection, generations and transport lifetime.
