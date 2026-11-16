# Independent XHTTP test peer

This helper links the unmodified XHTTP server from locked mihomo v1.19.34 and its VLESS framing component. It is excluded from ordinary builds by the `reka_reference` build tag. It creates only temporary loopback listeners. The handler echoes payloads, or forwards to an explicitly configured loopback fixture for encrypted VLESS/Vision composition tests; it never dials an arbitrary VLESS destination.

From the repository root:

```sh
GOCACHE=/tmp/reka-go-cache go build -modfile tools/mihomodiff/go.mod \
  -tags reka_reference -ldflags '-checklinkname=0' \
  -o /tmp/reka-xhttp-reference ./tools/xhttpref
OVERLAY=$(python3 tools/build-overlay.py)
GOCACHE=/tmp/reka-go-cache REKA_XHTTP_REFERENCE=/tmp/reka-xhttp-reference \
  go test -modfile bin/build.mod -overlay "$OVERLAY" -race \
  -tags with_gvisor,with_utls,badlinkname,tfogo_checklinkname0,reka_minimal \
  -ldflags '-checklinkname=0' ./internal/backend/sagernet ./internal/compat/xhttp \
  -run 'TestXHTTP|TestResponseHandoff|TestClientRetains|TestRejectUnbounded' \
  -count=1 -timeout 3m
```

Coverage includes H1/H2/H3 and all three XHTTP modes; actual VLESS TCP and XUDP with ordinary TLS/uTLS; Reka REALITY against an independent sing-box security bridge and the original XHTTP peer; separate H2 upload/H3 download with distinct certificate identities; independent upload/download XMUX settings; scoped DNS and automatic ECH lookup; cancellation, response handoff races and leased hot replacement. A loopback relay composes the unmodified transport with a VLESS encryption/Vision fixture and verifies inner TLS data and XUDP across all nine protocol/mode combinations. The security bridges are test compositions, not a claim that an arbitrary remote service accepts every combination. Public-network/CDN and Android runtime interoperability need separate environment-specific checks.
