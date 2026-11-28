package generation

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestWithNetworkStrategyKeepsPinnedDialers(t *testing.T) {
	base, diagnostics := compile.Compile([]byte(`schema-version: 1
outbounds:
  - {id: plain, type: shadowsocks, server: 127.0.0.1, port: 1, method: aes-128-gcm, password: test}
  - {id: pinned, type: shadowsocks, server: 127.0.0.1, port: 1, method: aes-128-gcm, password: test, dialer: {interface-name: en9}}
  - {id: fast-open, type: shadowsocks, server: 127.0.0.1, port: 1, method: aes-128-gcm, password: test, dialer: {tfo: true}}
  - {id: chained, type: shadowsocks, server: 127.0.0.1, port: 1, method: aes-128-gcm, password: test, dialer: {proxy: plain}}
`), nil, compile.Options{})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	if _, err := base.WithNetworkStrategy("sideways"); err == nil {
		t.Fatal("unknown strategy accepted")
	}
	same, err := base.WithNetworkStrategy("")
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := same.Outbound("plain")
	before := plain.Fingerprint
	if plain.Dialer != nil {
		t.Fatal("empty strategy changed a dialer")
	}
	updated, err := base.WithNetworkStrategy("fallback")
	if err != nil {
		t.Fatal(err)
	}
	if updated.NetworkStrategyOverride != "fallback" {
		t.Fatal("override not recorded")
	}
	for id, want := range map[string]string{"plain": "fallback", "direct": "fallback", "pinned": "", "fast-open": "", "chained": ""} {
		out, ok := updated.Outbound(id)
		if !ok {
			t.Fatal("missing outbound", id)
		}
		got := ""
		if out.Dialer != nil {
			got = out.Dialer.NetworkStrategy
		}
		if got != want {
			t.Errorf("%s strategy = %q, want %q", id, got, want)
		}
	}
	plain, _ = updated.Outbound("plain")
	if plain.Fingerprint == before {
		t.Fatal("strategy did not change the outbound fingerprint")
	}
	var options map[string]any
	if err := json.Unmarshal(specFor(plain).(sagernet.ProxySpec).Options, &options); err != nil {
		t.Fatal(err)
	}
	if options["network_strategy"] != "fallback" {
		t.Fatalf("options = %v", options)
	}
	if original, _ := base.Outbound("plain"); original.Dialer != nil {
		t.Fatal("override modified the base profile")
	}
}

func TestNetworkStrategyValidation(t *testing.T) {
	for _, tc := range []struct{ dialer, want string }{
		{"{network-strategy: sideways}", "network-strategy must be"},
		{"{network-strategy: hybrid, interface-name: en0}", "cannot be combined"},
		{"{network-strategy: fallback, tfo: true}", "cannot be combined"},
		{"{network-strategy: fallback, network-fallback-delay: 20000}", "network-fallback-delay"},
	} {
		_, diagnostics := compile.Compile([]byte(`schema-version: 1
outbounds:
  - {id: node, type: shadowsocks, server: 127.0.0.1, port: 1, method: aes-128-gcm, password: test, dialer: `+tc.dialer+`}
`), nil, compile.Options{})
		if !diagnostics.HasErrors() || !strings.Contains(diagnostics.Error(), tc.want) {
			t.Errorf("%s: diagnostics = %v", tc.dialer, diagnostics)
		}
	}
	eff, diagnostics := compile.Compile([]byte(`schema-version: 1
outbounds:
  - {id: node, type: shadowsocks, server: 127.0.0.1, port: 1, method: aes-128-gcm, password: test, dialer: {network-strategy: hybrid, network-fallback-delay: 150}}
`), nil, compile.Options{})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	node, _ := eff.Outbound("node")
	var options map[string]any
	if err := json.Unmarshal(protocolOptions(node), &options); err != nil {
		t.Fatal(err)
	}
	if options["network_strategy"] != "hybrid" || options["fallback_delay"] != "150ms" {
		t.Fatalf("options = %v", options)
	}
}

// The direct outbound dials through the host-reported networks once Wi-Fi
// assist is on: before any report it opens an ordinary socket, with an empty
// report it has no network, and with a report it binds to the listed one.
func TestDirectOutboundUsesReportedNetworks(t *testing.T) {
	loopback := loopbackInterface(t)
	base, diagnostics := compile.Compile([]byte("schema-version: 1\n"), nil, compile.Options{})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	updated, err := base.WithNetworkStrategy("fallback")
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(EngineOptions{})
	defer engine.Close()
	prepared, err := engine.Prepare(updated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Activate(prepared, 1); err != nil {
		t.Fatal(err)
	}
	target := echoListener(t)
	dial := func() error {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		conn, err := engine.OutboundInstance("direct").Dial(ctx, "tcp", target)
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("assist")); err != nil {
			return err
		}
		reply := make([]byte, len("assist"))
		_, err = io.ReadFull(conn, reply)
		return err
	}
	if err := dial(); err != nil {
		t.Fatal("dial before any report:", err)
	}
	engine.SetNetworkInterfaces([]sagernet.NetworkInterface{})
	if err := dial(); err == nil || !strings.Contains(err.Error(), "no available network interface") {
		t.Fatal("dial without networks:", err)
	}
	engine.SetNetworkInterfaces([]sagernet.NetworkInterface{{Name: loopback.Name, Type: "wifi"}})
	if err := dial(); err != nil {
		t.Fatal("dial over the reported network:", err)
	}
	if other := nonLoopbackInterface(); other != nil {
		// The preferred network cannot reach a loopback address, so the
		// connection has to fall back to the second one.
		engine.SetNetworkInterfaces([]sagernet.NetworkInterface{{Name: other.Name, Type: "wifi"}, {Name: loopback.Name, Type: "cellular"}})
		started := time.Now()
		if err := dial(); err != nil {
			if strings.Contains(err.Error(), "operation not permitted") {
				t.Skip("binding sockets to an interface is not permitted here")
			}
			t.Fatal("fallback dial:", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatal("fallback took", elapsed)
		}
	}
}

func loopbackInterface(t *testing.T) net.Interface {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			return iface
		}
	}
	t.Skip("host has no loopback interface")
	return net.Interface{}
}

func nonLoopbackInterface() *net.Interface {
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			if addrs, _ := iface.Addrs(); len(addrs) > 0 {
				return &iface
			}
		}
	}
	return nil
}

func echoListener(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return l.Addr().String()
}
