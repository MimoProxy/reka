package generation

import (
	"context"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/platform"
	"io"
	"net/netip"
	"strings"
	"testing"
)

func TestTUNUDPHasItsOwnCapability(t *testing.T) {
	hooks := &platform.NetworkHooks{StartTUN: func(platform.TUNConfig) (io.Closer, string, error) {
		return io.NopCloser(strings.NewReader("")), "test", nil
	}}
	e := NewEngine(EngineOptions{StateRoot: t.TempDir(), NetworkHooks: hooks})
	defer e.Close()
	eff, ds := compile.Compile([]byte("schema-version: 1\nrules: [{match: {all: true}, outbound: direct}]"), nil, compile.Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	// Fake OS hook isolates the real generation router on every CI platform.
	eff.Network = platform.Network{Mode: "tun"}
	p, err := e.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Activate(p, 1); err != nil {
		t.Fatal(err)
	}
	md := sagernet.Metadata{Inbound: "tun", InboundType: "tun", Network: "udp", Source: netip.MustParseAddrPort("192.0.2.2:5000"), Destination: sagernet.Destination{Addr: netip.MustParseAddr("192.0.2.3"), Port: 9999}}
	rt := e.route(context.Background(), md)
	if rt.Outbound == nil {
		t.Fatal("enabled TUN UDP rejected by loopback listener capability")
	}
	rt.Release()
	md.InboundType = "mixed"
	rt = e.route(context.Background(), md)
	if rt.Outbound != nil {
		rt.Release()
		t.Fatal("unknown loopback listener inherited TUN UDP capability")
	}
}
