//go:build with_gvisor

package generation

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
)

func TestWireGuardPeerUsesBackendResolverWithoutConfiguredDNS(t *testing.T) {
	server, queries := pinFlowDNS(t)
	engine := NewEngine(EngineOptions{})
	defer engine.Close()
	engine.backend.Resolver().Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, network, server)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	answers, err := engine.lookupEndpointPeer(ctx, "peer.test.")
	if err != nil || queries.Load() == 0 || !slices.ContainsFunc(answers, netip.Addr.IsLoopback) {
		t.Fatalf("backend DNS lookup returned %v, %v", answers, err)
	}
}

func TestWireGuardInnerDNSAndPeerBootstrap(t *testing.T) {
	stale, staleQueries := pinFlowDNS(t)
	policy, policyQueries := pinFlowDNS(t)
	bootstrap, peerQueries := pinFlowDNS(t)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	profile := func(proxyDNS string) string {
		return fmt.Sprintf(`schema-version: 1
outbounds:
  - id: tunnel
    type: wireguard
    server: peer.test
    port: %d
    protocol:
      private-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
      public-key: Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=
      address: [192.0.2.1/32]
      reserved: [1, 2, 3]
dns:
  nameserver: [%q]
  proxy-server-nameserver: [%q]
  nameserver-policy: [{id: internal, pattern: '+.internal.test', servers: [%q]}]
rules: [{match: {all: true}, outbound: tunnel}]
`, peer.LocalAddr().(*net.UDPAddr).Port, stale, proxyDNS, policy)
	}
	engine := NewEngine(EngineOptions{})
	defer engine.Close()
	first := pinFlowApply(t, engine, profile(stale), "", 1)
	second := pinFlowApply(t, engine, profile(bootstrap), "", 2)
	out := second.outbounds["tunnel"]
	if out != first.outbounds["tunnel"] {
		t.Fatal("DNS-only reload replaced the WireGuard outbound")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	route := engine.route(ctx, sagernet.Metadata{Network: "tcp", Destination: sagernet.Destination{Domain: "flow.internal.test", Port: 443}})
	if route.Outbound != out || route.Lookup == nil {
		t.Fatal("missing WireGuard route resolver")
	}
	defer route.Release()
	if _, err := route.Lookup(ctx, "flow.internal.test"); err != nil {
		t.Fatal(err)
	}
	_, g := engine.current()
	// A probe resolves its inner destination through the same DNS policy.
	conn, err := out.Dial(g.probeLookupContext(ctx, out), "udp", "probe.internal.test:53")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if policyQueries.Load() != 2 || staleQueries.Load() != 0 || peerQueries.Load() != 0 {
		t.Fatalf("inner lookups reached policy=%d stale=%d peer=%d", policyQueries.Load(), staleQueries.Load(), peerQueries.Load())
	}
	// The first outgoing tunnel packet triggers the separate peer lookup.
	conn, err = out.Dial(ctx, "udp", "198.51.100.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	checkWireGuardHandshake(t, conn, peer, [3]byte{1, 2, 3})
	if peerQueries.Load() == 0 || staleQueries.Load() != 0 || policyQueries.Load() != 2 {
		t.Fatalf("handshake lookups reached policy=%d stale=%d peer=%d", policyQueries.Load(), staleQueries.Load(), peerQueries.Load())
	}
}
