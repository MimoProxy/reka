# ShadowsocksR client compatibility component

Adapted from [MetaCubeX/mihomo v1.19.34](https://github.com/MetaCubeX/mihomo/tree/v1.19.34/transport/ssr), GPL-3.0-or-later (repository root LICENSE). The client combines the [SSR outbound](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/adapter/outbound/shadowsocksr.go) with the [legacy Shadowsocks stream ciphers](https://github.com/MetaCubeX/mihomo/tree/v1.19.34/transport/shadowsocks). The Clash importer follows the [share-link converter](https://github.com/MetaCubeX/mihomo/tree/v1.19.34/common/convert) and the Clash API uses the upstream adapter name.

Original SHA-256:

- `transport/ssr/obfs/base.go`: `faeb4c6f4bf0314716d1bf3a259d9e6b1540cdc0e64ff6a80930ca7cd242e5dc`
- `transport/ssr/obfs/http_post.go`: `1002b82dc2ca354dc28eb54f7ce22caeb854d8315bf089eeb2d08e39f2b21ca9`
- `transport/ssr/obfs/http_simple.go`: `e3e6f27783747791999a7760b7477a43724a3bf3facd8fbb49f246623cdb2da3`
- `transport/ssr/obfs/obfs.go`: `11859a00608be5be386201807b9fbd1b09901832da3498ec721f01e6de9c4750`
- `transport/ssr/obfs/plain.go`: `95b35b7c13a7e039f1d7ab64b7ed9ef8e2507433c543f4616f3fcad8381364c8`
- `transport/ssr/obfs/random_head.go`: `483fc073bcbeebf9d2653d647561289e0b0d3038b13904ef95a9a7d586dadf8b`
- `transport/ssr/obfs/tls1.2_ticket_auth.go`: `13f6cf3d3c98af8f1495b653958ee173fea24a62c2a0b48e2b6954caa8fa007a`
- `transport/ssr/protocol/auth_aes128_md5.go`: `07640f8078380f1d07fa486f1f93f303028f6db8189fef148d47d58194226580`
- `transport/ssr/protocol/auth_aes128_sha1.go`: `b5f315576213a4de0d97a18fd3850300bf53b39439b3e7d420e0533347ff67fc`
- `transport/ssr/protocol/auth_chain_a.go`: `5bf6d8dd19cd536959a87b9a2e4122081f0c884e92b5bf1214fb19e33a0922cd`
- `transport/ssr/protocol/auth_chain_b.go`: `d9744bb6ab8442322dde53f1d04a1463826e9d3d19f224b559acaeb4a41adf0a`
- `transport/ssr/protocol/auth_sha1_v4.go`: `17fe796b487a009e5884fe191d6d066ed02c3604a18cbcdc4d471c7eb0973bb9`
- `transport/ssr/protocol/base.go`: `5692d00a0c7ec0d16db6b12762f2c7fd2ac1e4aa4ece56064a4e8a3652f65cd5`
- `transport/ssr/protocol/origin.go`: `154c03908768a8f25473998191cf75877847aa43cc46dbe169e8c549b4e8bb26`
- `transport/ssr/protocol/packet.go`: `ed3afa30d04750baf1f654a4a2b4ba144b63ecf958480d7ea1edf3cb83d80452`
- `transport/ssr/protocol/protocol.go`: `a7d5187aef74567a0831fcf1562f74394daffe1fd39e6b6721e49ef697d7309e`
- `transport/ssr/protocol/stream.go`: `068890f6d0854e93f663d5f6f981e99889f9a9fb5a4e35ec490805bcf5aa0189`
- `transport/ssr/tools/bufPool.go`: `fa8b7971e9d17eac28ba9845cc1d1005be080de3372e88d9a4cb24956f5e00df`
- `transport/ssr/tools/crypto.go`: `08ca9150b7469da33a8b59b3cabf139744da46438131a5766578611bb8c8bd5f`
- `transport/ssr/tools/random.go`: `52910c546816a963678d5c0759c80b008acc6b431d2c36dc5e948e51090e9fa4`
- `transport/shadowsocks/shadowstream/chacha20.go`: `609ffd7ae3d4c4584dcc8db862287d4a32aa27edcb46383b2794e70eaa80dfa4`
- `transport/shadowsocks/shadowstream/cipher.go`: `adee0a8aa40890d55da84c35540591e55457d06ea16a5d608b6a64e7f8deafdc`
- `transport/shadowsocks/shadowstream/packet.go`: `6c728d301378d88df2eb38f678c673fa552f4f8c49f8522dc68658a7c30aaedd`
- `transport/shadowsocks/shadowstream/stream.go`: `5f1379b3c9b05c82fc7339e610715ccf4d678eb538c5aacc8d54da7ead180ab4`
- `transport/shadowsocks/core/cipher.go`: `4787c4ed21ffe6c8dbc9cdb22a1cb4b012b360f2f423ad2fdf9d7ab8695dc24d`
- `adapter/outbound/shadowsocksr.go`: `afa7a8a9dd1ac1f903a779bba98e91cfdc0e792593b91b01cf561750eba4127a`
- `common/convert/converter.go`: `04d4adc156a10eef5ead596803670c867cf150c4d4cd43166a364896a1a5db7e`
- `common/convert/base64.go`: `ddd06d18900a5e0e1aa765a1c30211730ff35fb081a9b08d390080282d7360cb`
- `constant/adapters.go`: `ac639e5f9d3b07c80455ff43a189a63a456eee04da5cababf3792a955ad13bc2`

## Local changes

- `client.go` assembles obfs, stream encryption and protocol framing around caller-owned sockets. The backend supplies its sing-box dialer. TCP sends the SOCKS5 destination during setup. UDP applies the cipher and protocol to each addressed datagram and bypasses obfs. Address encoding uses sing's SOCKS serializer.
- `cipher.go`, `stream.go` and `packet.go` implement the stream-method allowlist, IV exchange and datagram framing. Both `none` and `dummy` use a zero-length IV and a 16-byte key derived from the password. The stream cipher and auth protocols share the original MD5-based KDF in `tools`.
- ChaCha20 uses `golang.org/x/crypto/chacha20`. The IETF and XChaCha20 variants use their native nonce lengths. For original ChaCha20 the client prepends four zero bytes to the eight-byte IV and begins with counter zero. The resulting keystream matches the original for the first 2^32 blocks (256 GiB). Each direction enforces that limit and closes the stream with an error before generating another block. The same guard protects the other two ChaCha20 methods.
- `obfs`, `protocol` and `tools` retain the upstream algorithms and file layout. Temporary buffers use Go or sing buffers. Random selections use `math/rand/v2`, cryptographic randomness uses `crypto/rand`, and timestamps use `time.Now`. The port returns transport errors to the caller. As upstream does, invalid numeric user IDs fall back to the method key and a random ID.
- Independent read and write locks permit full-duplex use and concurrent close. Authentication connection IDs are shared under a lock. Cipher state, packet padding and scratch space belong to each connection, direction or datagram. Decoders validate frame offsets before slicing and close streams on invalid authentication frames.
- The HTTP obfuscators use a reduced set of upstream desktop user agents. HTTP headers and TLS ticket records can span reads. Random-head and ticket handshakes cap queued writes at 1 MiB and close the connection on overflow. As in mihomo, random-head consumes the first underlying read as the peer's random response. That response has no length field, so fragmentation of the random response can affect interoperability.
- Cipher lookup accepts mixed case. Obfs and protocol use the exact names from the mihomo registries. Native configurations default to `plain` and `origin`. Clash YAML requires both names. The importer reports malformed base64 in link fields and assigns a stable endpoint name when remarks are empty.
