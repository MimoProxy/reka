//go:build with_gvisor

package generation

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
	RD "github.com/MimoProxy/reka/internal/dns"
	D "github.com/miekg/dns"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

func TestPacketFlowRuleDNSEvents(t *testing.T) {
	const profile = `schema-version: 1
groups: [{id: egress, type: select, members: [reject-drop]}]
rules:
  - {match: {ip-cidr: 192.0.2.0/24}, outbound: egress}
  - {match: {all: true}, outbound: egress}
`
	eff, diagnostics := compile.Compile([]byte(profile), nil, compile.Options{})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	engine := NewEngine(EngineOptions{HostPacketFlow: true})
	t.Cleanup(func() { engine.Close() })
	fakeRange := netip.MustParsePrefix("198.19.0.0/24")
	resolver, err := RD.New(RD.Config{Nameservers: []string{"192.0.2.53"}, IPv6: true}, RD.Options{
		Exchange: func(_ context.Context, _ RD.Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
			question := q.Question[0]
			// Keep the lookup's start and completion observably separate.
			time.Sleep(5 * time.Millisecond)
			if question.Name == "missing.test." {
				return nil, errors.New("upstream unavailable")
			}
			records := []string{"A 192.0.2.8", "A 198.51.100.8"}
			if question.Qtype == D.TypeAAAA {
				records = []string{"AAAA 2001:db8::8", "AAAA 2001:db8::9"}
			}
			reply := new(D.Msg).SetReply(q)
			for _, record := range records {
				rr, err := D.NewRR(question.Name + " 30 IN " + record)
				if err != nil {
					return nil, err
				}
				reply.Answer = append(reply.Answer, rr)
			}
			return reply, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.Retire)
	prepared, err := engine.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	prepared.dns = resolver
	if _, err := engine.Activate(prepared, 1); err != nil {
		t.Fatal(err)
	}
	client := ruleDNSPacketFlowClient(t, engine)
	const trigger = "IP-CIDR,192.0.2.0/24,egress"
	for _, tc := range []struct {
		domain, source, rule string
		counts               []int
	}{
		{domain: "target.test", source: "upstream", rule: trigger, counts: []int{2, 2}},
		{domain: "missing.test", source: "error", rule: "MATCH,egress", counts: []int{0, 0}},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			target, err := engine.fake.Allocate(resolver.Generation(), tc.domain, fakeRange, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			addr := tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(target), Port: 8000}
			conn, err := gonet.DialContextTCP(ctx, client, addr, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			trace := waitRuleDNSConnectionTrace(t, ctx, engine, netip.AddrPortFrom(target, addr.Port).String())
			defer engine.CloseConnections([]uint64{trace.ID})
			events := trace.Events
			want := []string{"accepted", "fakeip", "rule_lookup", "dns"}
			if tc.source != "error" {
				want = append(want, "rule_addr")
			}
			want = append(want, "matched", "path", "dial", "ready")
			var kinds []string
			for i, event := range events {
				kinds = append(kinds, event.Kind)
				if event.T < 0 || i > 0 && event.T < events[i-1].T {
					t.Fatalf("connection events out of order: %+v", events)
				}
			}
			if !slices.Equal(kinds, want) {
				t.Fatalf("event kinds = %v, want %v", kinds, want)
			}
			ruleLookup, dns := events[2], events[3]
			if ruleLookup.Name != trigger || dns.T <= ruleLookup.T || dns.Name != tc.domain ||
				dns.Code != tc.source || !slices.Equal(dns.N, tc.counts) || dns.MS == nil || *dns.MS < 5 ||
				events[len(events)-4].Name != tc.rule {
				t.Fatalf("unexpected route diagnostics: %+v", events)
			}
			if tc.source != "error" {
				address := events[4]
				if address.Addr != "192.0.2.8" || address.Peer != "2001:db8::8" {
					t.Fatalf("unexpected route addresses: %+v", address)
				}
			}
		})
	}
}

func waitRuleDNSConnectionTrace(t *testing.T, ctx context.Context, engine *Engine, destination string) api.ConnectionTrace {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		for _, conn := range engine.backend.Connections() {
			trace, ok := engine.backend.ConnectionTrace(conn.ID, "")
			if ok && trace.Destination == destination {
				return trace
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("no active trace for %s: %v", destination, ctx.Err())
		case <-ticker.C:
		}
	}
}

func ruleDNSPacketFlowClient(t *testing.T, engine *Engine) *stack.Stack {
	t.Helper()
	const mtu = 1280
	device := &ruleDNSTestDevice{channel.New(64, mtu, "")}
	flow, err := engine.AttachPacketFlow(device, mtu, netip.MustParsePrefix("198.18.0.1/30"), netip.MustParsePrefix("2001:db8::1/64"), 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { flow.Close() })
	endpoint := channel.New(64, mtu, "")
	t.Cleanup(endpoint.Close)
	client, err := tun.NewGVisorStack(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	address := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{
		Address: tun.AddressFromAddr(netip.MustParseAddr("198.18.0.2")), PrefixLen: 30,
	}}
	if err := client.AddProtocolAddress(tun.DefaultNIC, address, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var link sync.WaitGroup
	for _, pair := range [][2]*channel.Endpoint{{endpoint, device.Endpoint}, {device.Endpoint, endpoint}} {
		link.Go(func() {
			for packet := pair[0].ReadContext(ctx); packet != nil; packet = pair[0].ReadContext(ctx) {
				frame := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(packet.ToView())})
				packet.DecRef()
				pair[1].InjectInbound(ipv4.ProtocolNumber, frame)
				frame.DecRef()
			}
		})
	}
	t.Cleanup(func() { cancel(); link.Wait() })
	return client
}

type ruleDNSTestDevice struct{ *channel.Endpoint }

func (d *ruleDNSTestDevice) Name() (string, error)                { return "rule-dns-test", nil }
func (d *ruleDNSTestDevice) Start() error                         { return nil }
func (d *ruleDNSTestDevice) Close() error                         { d.Endpoint.Close(); return nil }
func (d *ruleDNSTestDevice) Read([]byte) (int, error)             { return 0, io.ErrClosedPipe }
func (d *ruleDNSTestDevice) Write([]byte) (int, error)            { return 0, io.ErrClosedPipe }
func (d *ruleDNSTestDevice) UpdateRouteOptions(tun.Options) error { return io.ErrClosedPipe }

func (d *ruleDNSTestDevice) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return d.Endpoint, stack.NICOptions{}, nil
}

func (d *ruleDNSTestDevice) WritePacket(packet *stack.PacketBuffer) (int, error) {
	var packets stack.PacketBufferList
	packets.PushBack(packet)
	if n, _ := d.WritePackets(packets); n != 1 {
		return 0, io.ErrShortWrite
	}
	return packet.Size(), nil
}
