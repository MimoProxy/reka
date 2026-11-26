package generation

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/testnet"
	D "github.com/miekg/dns"
)

func TestPacketAddrResolvesDestinationWithNormalDNS(t *testing.T) {
	var normal, proxy atomic.Int32
	server := func(ip string, calls *atomic.Int32) string {
		packet, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		s := &D.Server{PacketConn: packet, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
			calls.Add(1)
			m := new(D.Msg)
			m.SetReply(q)
			rr, _ := D.NewRR(q.Question[0].Name + " 30 IN A " + ip)
			m.Answer = []D.RR{rr}
			w.WriteMsg(m)
		})}
		ready := make(chan struct{})
		s.NotifyStartedFunc = func() { close(ready) }
		go s.ActivateAndServe()
		<-ready
		t.Cleanup(func() { s.Shutdown() })
		return packet.LocalAddr().String()
	}
	primary, bootstrap := server("192.0.2.7", &normal), server("192.0.2.8", &proxy)
	engine := NewEngine(EngineOptions{})
	defer engine.Close()
	testnet.RetryAddr(t, func(address netip.AddrPort) error {
		input := fmt.Sprintf(`schema-version: 1
outbounds: [{id: node, type: vless, server: 127.0.0.1, port: 9, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, packet-encoding: packetaddr}]
listeners: [{id: ingress, type: socks, listen: %q, udp: true}]
dns: {nameserver: [%q], proxy-server-nameserver: [%q]}
rules: [{match: {all: true}, outbound: node}]
`, address, primary, bootstrap)
		eff, ds := compile.Compile([]byte(input), nil, compile.Options{})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		prepared, err := engine.Prepare(eff)
		if err != nil {
			return err
		}
		_, err = engine.Activate(prepared, 1)
		return err
	})
	route := engine.route(context.Background(), sagernet.Metadata{Inbound: "ingress", InboundType: "socks", Network: "udp", Destination: sagernet.Destination{Domain: "packet.test", Port: 53}})
	if route.Outbound == nil {
		t.Fatal("route rejected")
	}
	defer route.Release()
	if route.Destination == nil || route.Destination.Domain != "" || route.Destination.Addr.String() != "192.0.2.7" {
		t.Fatal("packetaddr destination was not resolved", route.Destination)
	}
	if normal.Load() != 1 || proxy.Load() != 0 {
		t.Fatal("wrong DNS scope", normal.Load(), proxy.Load())
	}
}

func TestMappedPacketDestinationByOutbound(t *testing.T) {
	const dnsProfile = `schema-version: 1
dns:
  nameserver: [192.0.2.53]
  use-hosts: true
  hosts: [{id: mapped.test, addresses: [%s]}]
`
	e := NewEngine(EngineOptions{HostPacketFlow: true})
	t.Cleanup(e.Close)
	original := netip.MustParseAddr("192.0.2.20")
	pinFlowApply(t, e, fmt.Sprintf(dnsProfile, original), "", 1)
	if _, err := e.ExchangeDNS(t.Context(), new(D.Msg).SetQuestion("mapped.test.", D.TypeA)); err != nil {
		t.Fatal(err)
	}
	// The new DNS answer differs. IP-only encodings must keep the address
	// that was returned to the client before the reload.
	base := fmt.Sprintf(dnsProfile, "192.0.2.21")
	const packet = ", uuid: b831381d-6324-4d53-ad4f-8cda48b30811, packet-encoding: packetaddr"
	for i, tc := range []struct {
		name, outbound string
		wantDomain     bool
	}{
		{"SOCKS", "socks", true},
		{"VLESS packetaddr", "vless" + packet, false},
		{"VMess packetaddr", "vmess" + packet, false},
		{"multiplexed UDP", "vless" + packet + ", multiplex: {enabled: true}", true},
		{"native UDP with multiplexed TCP", "vless" + packet + ", multiplex: {enabled: true, only-tcp: true}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := base + fmt.Sprintf(`outbounds: [{id: relay, server: 192.0.2.42, port: 8443, type: %s}]
rules:
  - {match: {domain: observed.test}, outbound: relay}
  - {match: {all: true}, outbound: reject}
`, tc.outbound)
			pinFlowApply(t, e, profile, "", uint64(i+2))
			md := sagernet.Metadata{
				Network: "udp", InboundType: "tun", SniffedDomain: "observed.test",
				Destination: sagernet.Destination{Addr: original, Port: 8443},
			}
			rt := e.route(t.Context(), md)
			if rt.Release != nil {
				defer rt.Release()
			}
			if rt.Outbound == nil || rt.Outbound.Tag() != "relay" {
				t.Fatalf("sniffed domain did not select relay: %+v", rt.Info)
			}
			got := md.Destination
			if rt.Destination != nil {
				got = *rt.Destination
			}
			want := sagernet.Destination{Addr: original, Port: md.Destination.Port}
			if tc.wantDomain {
				want = sagernet.Destination{Domain: "mapped.test", Port: md.Destination.Port}
			}
			if got != want {
				t.Fatalf("outbound destination = %+v, want %+v", got, want)
			}
		})
	}
}
