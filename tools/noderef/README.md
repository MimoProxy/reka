# Independent interoperability server

This isolated module pins the unmodified sing-box v1.14.4 CLI for temporary
controlled-node tests. It is never linked into the Reka executable or library.

Build from the repository root:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go -C tools/noderef build -mod=mod -trimpath \
  -tags with_gvisor,with_utls,with_quic,badlinkname,tfogo_checklinkname0 \
  -ldflags '-checklinkname=0 -s -w' -o ../../bin/reference-node-windows.exe \
  github.com/sagernet/sing-box/cmd/sing-box
```

`tools/remote-nodes.py` creates temporary Trojan, Hysteria2 and TUIC listeners,
generated credentials and a one-day test certificate. Windows inbound firewall
rules accept only the named client IP. A scheduled cleanup also runs independently
after 15 minutes. The normal cleanup verifies removal of the owned process,
firewall rules and scheduled task, and deletes credentials.

The credential-free report identifies this as a controlled LAN test, not a test
of a commercial subscription or an arbitrary WAN path.
