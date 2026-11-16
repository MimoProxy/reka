# XHTTP client compatibility component

Adapted from [MetaCubeX/mihomo v1.19.34](https://github.com/MetaCubeX/mihomo/tree/v1.19.34/transport/xhttp), GPL-3.0-or-later (repository root LICENSE). Only the stream transport is reused; the reference router and application are not linked.

Original SHA-256:

- `client.go`: `b68cd9b79071066689728e08b0dd7e2fc7f732475911b2c1c29f7065143f00be`
- `config.go`: `2583662af1643c31852f01bf173a3f28ab62d4b53dd51ff27d8f733e0c8fd00f`
- `reuse.go`: `b74b64a71750cecc874b7916494710bcf72b48107e22042bf02f6a4ef9ed227d`
- `xpadding.go`: `57d4e53073b5bb2736217a6bb5cf36dc19392db4538b6cbdef88d0e433435129`
- `browser.go`: `41190e5e5a4bf811491620ff676efb4fbc7f8cf9d89a534213118bb2270babf5`
- `conn.go`: `9d641aa888089c9af028b14aac6aa543ee5e5d1db1a42ee690f412fdb49e9eac`

Local changes: standard HTTP, tracing and random APIs; local UUID/address helpers; caller-owned protected dial callbacks; synchronized close, deadline and response handoff; transport lifetimes managed by the outbound. HTTP/2 uses x/net/http2 over caller-supplied TLS/REALITY streams; HTTP/3 uses the existing locked SagerNet QUIC component. No implicit physical dial fallback is allowed.
