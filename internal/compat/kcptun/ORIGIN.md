# kcptun carrier

Config defaults, block cipher selection, KCP setup and snappy framing follow
[MetaCubeX/mihomo v1.19.34](https://github.com/MetaCubeX/mihomo/tree/v1.19.34/transport/kcptun),
GPL-3.0-or-later (repository root LICENSE).

Original SHA-256:

- `common.go`: `a4b163ce53cad8a57a1c3e7aadab2290f7d761864e4870e2bbf67b4ce7019d0d`
- `comp.go`: `6f2d9fa33d743527974f414e348d348e188716f9417e85d7e7dfa166a042721a`
- `client.go`: `48f1a6abb29e0302077dbc82b3187662a8669ea33dc6e4a5fe20205c4ff4b5e2`

Reka owns and bounds the pool, closes every physical socket on reset/close, drains retired carriers, and uses its existing patched sing-box SMux component. The reference server remains in a separate test process.
