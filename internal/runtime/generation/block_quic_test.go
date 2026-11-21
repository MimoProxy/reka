package generation

import (
	"context"
	"fmt"
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestRouteBlockQUIC(t *testing.T) {
	const profile = `schema-version: 1
routing: {block-quic: %s}
outbounds:
  - {id: node, type: socks, server: 127.0.0.1, port: 9}
  - {id: named-direct, type: direct}
groups:
  - {id: proxy, type: select, members: [node], selected: node}
  - {id: direct-group, type: select, members: [named-direct], selected: named-direct}
rules:
  - {match: {domain: direct.test}, outbound: direct}
  - {match: {domain: named-direct.test}, outbound: direct-group}
  - {match: {domain: reject.test}, outbound: reject}
  - {match: {domain: drop.test}, outbound: reject-drop}
  - {match: {all: true}, outbound: proxy}
`
	cases := []struct {
		name, network, protocol, domain string
		port                            uint16
		outbound                        string
		blockProxy, blockAll            bool
	}{
		{"UDP 443 via proxy", "udp", "", "proxy.test", 443, "node", true, true},
		{"UDP 443 via direct", "udp", "", "direct.test", 443, "direct", false, true},
		{"UDP 443 via named direct", "udp", "", "named-direct.test", 443, "named-direct", false, true},
		{"TCP 443", "tcp", "", "proxy.test", 443, "node", false, false},
		{"UDP non-443 sniffed QUIC", "udp", "quic", "proxy.test", 8443, "node", true, true},
		{"UDP 53", "udp", "", "proxy.test", 53, "node", false, false},
		{"reject rule", "udp", "quic", "reject.test", 443, "reject", false, false},
		{"drop rule", "udp", "quic", "drop.test", 443, "reject-drop", false, false},
	}
	e := NewEngine(EngineOptions{HostPacketFlow: true})
	defer e.Close()
	for i, mode := range []string{"off", "proxy", "all"} {
		t.Run(mode, func(t *testing.T) {
			eff, ds := compile.Compile(fmt.Appendf(nil, profile, mode), nil, compile.Options{})
			if ds.HasErrors() {
				t.Fatal(ds)
			}
			prepared, err := e.Prepare(eff)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.Activate(prepared, uint64(i+1)); err != nil {
				t.Fatal(err)
			}
			for _, tt := range cases {
				t.Run(tt.name, func(t *testing.T) {
					rt := e.route(context.Background(), sagernet.Metadata{
						InboundType: "tun", Network: tt.network, Protocol: tt.protocol,
						Destination: sagernet.Destination{Domain: tt.domain, Port: tt.port},
					})
					var tag string
					if rt.Outbound != nil {
						defer rt.Release()
						tag = rt.Outbound.Tag()
					}
					wantTag, wantReason := tt.outbound, ""
					if tt.outbound == "reject" {
						wantTag = ""
					}
					if mode == "proxy" && tt.blockProxy || mode == "all" && tt.blockAll {
						wantTag, wantReason = "", "block-quic"
					}
					info := rt.Info.(*FlowInfo)
					if tag != wantTag || info.Outbound != tt.outbound || info.RejectReason != wantReason {
						t.Fatalf("routed to %q (rule selected %q), reject reason %q; want %q (rule selected %q), reason %q",
							tag, info.Outbound, info.RejectReason, wantTag, tt.outbound, wantReason)
					}
				})
			}
		})
	}
}
