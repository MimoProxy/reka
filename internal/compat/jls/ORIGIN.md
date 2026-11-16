# JLS client transport

The uTLS ClientHello authentication adapter is adapted from
[MetaCubeX/mihomo v1.19.34](https://github.com/MetaCubeX/mihomo/tree/v1.19.34/transport/jls),
GPL-3.0-or-later (repository root LICENSE). Product binaries use the standalone
locked `jls-tls` component, never the reference application's router.

Original SHA-256:

- `jls.go`: `a78656201b1fad684c371ad1ca6c4ebf63c1ef834751c76bd5b5003cc724aac4`
- `utls.go`: `c531573ad38a1bc1295feadc6884a452745604151267908c4573ae0cdd85eb3d`

Local changes: standard HTTP, random and time APIs; system CA roots; scoped immutable client configuration. The uTLS wire authentication is retained. Empty or unknown fingerprints select native JLS like the reference.
