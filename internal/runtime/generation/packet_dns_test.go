package generation

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
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
	port, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := port.Addr().String()
	port.Close()
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
	engine := NewEngine(EngineOptions{})
	defer engine.Close()
	prepared, e := engine.Prepare(eff)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = engine.Activate(prepared, 1); e != nil {
		t.Fatal(e)
	}
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
