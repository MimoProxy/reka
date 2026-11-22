package generation

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestDirectOutboundIPVersion(t *testing.T) {
	base, diagnostics := compile.Compile([]byte("schema-version: 1\n"), nil, compile.Options{})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	engine := NewEngine(EngineOptions{})
	defer engine.Close()

	ipv4 := netip.MustParseAddr("127.0.0.1")
	ipv6 := netip.IPv6Loopback()
	v6Socket, err := net.ListenPacket("udp6", "[::1]:0")
	if err == nil {
		v6Socket.Close()
	}
	hasIPv6 := err == nil
	for i, tc := range []struct {
		policy, strategy string
		results          []netip.Addr
		want             netip.Addr
	}{
		{"dual", "", []netip.Addr{ipv4}, ipv4},
		{"ipv4", "ipv4_only", []netip.Addr{ipv6}, netip.Addr{}},
		{"ipv6", "ipv6_only", []netip.Addr{ipv4}, netip.Addr{}},
		{"ipv4-prefer", "prefer_ipv4", []netip.Addr{ipv6, ipv4}, ipv4},
		{"ipv6-prefer", "prefer_ipv6", []netip.Addr{ipv4, ipv6}, ipv6},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			updated, err := base.WithIPVersion(tc.policy)
			if err != nil {
				t.Fatal(err)
			}
			direct, _ := updated.Outbound("direct")
			if got := specFor(direct); got != (sagernet.DirectSpec{DomainStrategy: tc.strategy}) {
				t.Fatalf("direct spec = %+v, want strategy %q", got, tc.strategy)
			}
			previous := engine.OutboundInstance("direct")
			prepared, err := engine.Prepare(updated)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := engine.Activate(prepared, uint64(i+1)); err != nil {
				t.Fatal(err)
			}
			outbound := engine.OutboundInstance("direct")
			if outbound == nil || outbound == previous {
				t.Fatal("direct outbound was not rebuilt")
			}
			if tc.want.Is6() && !hasIPv6 {
				t.Skip("IPv6 loopback unavailable")
			}

			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			ctx = sagernet.WithLookup(ctx, func(context.Context, string) ([]netip.Addr, error) {
				return slices.Clone(tc.results), nil
			})
			conn, err := outbound.Dial(ctx, "udp", "target.test:53")
			if conn != nil {
				defer conn.Close()
			}
			if !tc.want.IsValid() {
				if err == nil || err.Error() != "no address for target.test" {
					t.Fatalf("wrong-family DNS result was not filtered: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := conn.RemoteAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(); got != tc.want {
				t.Fatalf("dialed %s, want %s", got, tc.want)
			}
		})
	}
}
