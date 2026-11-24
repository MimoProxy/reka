//go:build with_gvisor

package sagernet

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/platform"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	tun "github.com/sagernet/sing-tun"
)

func TestPacketFlowJudgePreMatchBypassesAdmission(t *testing.T) {
	for _, network := range []struct {
		name     string
		protocol uint8
	}{
		{"tcp", uint8(header.TCPProtocolNumber)},
		{"udp", uint8(header.UDPProtocolNumber)},
	} {
		for _, verdict := range []struct {
			name   string
			action PreMatchAction
			want   tun.FlowAction
		}{
			{"reject", PreMatchReject, tun.ActionReject},
			{"drop", PreMatchDrop, tun.ActionDrop},
		} {
			t.Run(network.name+"/"+verdict.name, func(t *testing.T) {
				inbound, logs := newJudgeFlowTestInbound(t)
				h := &packetFlowHandler{
					TUNInbound: inbound,
					tcp:        newPacketFlowTable(1),
					udp:        newPacketFlowTable(1),
					logger:     newLogger(inbound.b.slog, "packet-flow"),
				}
				flow := &PacketFlow{handler: h}
				table := &h.tcp
				if network.name == "udp" {
					table = &h.udp
				}
				source := netip.MustParseAddrPort("198.18.0.2:50000")
				admittedSource := netip.AddrPortFrom(source.Addr(), source.Port()+1)
				admittedTarget := netip.MustParseAddrPort("192.0.2.1:443")
				target := netip.MustParseAddrPort("192.0.2.2:443")
				inbound.b.SetPreMatch(func(md Metadata) PreMatchVerdict {
					if md.Destination.Addr == target.Addr() {
						return PreMatchVerdict{Action: verdict.action}
					}
					return PreMatchVerdict{Action: PreMatchContinue}
				})
				judgeBlocked := func(wantSlots int) {
					t.Helper()
					if got := h.JudgeFlow(network.protocol, source, target, nil).Action; got != verdict.want {
						t.Fatalf("JudgeFlow returned %v, want %v", got, verdict.want)
					}
					if len(h.tcp.flows)+len(h.udp.flows) != wantSlots || table.flows[packetFlowKey{source, target}] != nil {
						t.Fatalf("pre-match changed admission slots: TCP %d, UDP %d", len(h.tcp.flows), len(h.udp.flows))
					}
					if stats := flow.Stats(); stats != (PacketFlowStats{}) {
						t.Fatalf("pre-match changed admission statistics: %+v", stats)
					}
					if !h.lastWarning.IsZero() || strings.Contains(logs.String(), "level=WARN") {
						t.Fatalf("pre-match triggered an admission warning: %s", logs.String())
					}
				}
				judgeBlocked(0)
				if got := h.JudgeFlow(network.protocol, admittedSource, admittedTarget, nil).Action; got != tun.ActionAccept {
					t.Fatalf("continue returned %v, want accept", got)
				}
				admittedKey := packetFlowKey{admittedSource, admittedTarget}
				admitted := table.flows[admittedKey]
				if admitted == nil {
					t.Fatal("continue did not reserve a slot")
				}
				judgeBlocked(1)
				admitted.reserved = time.Time{}
				admitted.last.Store(time.Now().Add(-packetFlowEvictionIdle).UnixNano())
				admitted.close = func() {}
				judgeBlocked(1)
				if table.flows[admittedKey] != admitted || admitted.evicted {
					t.Fatal("pre-match evicted an existing flow")
				}

				inbound.b.SetPreMatch(func(Metadata) PreMatchVerdict { return PreMatchVerdict{Action: PreMatchContinue} })
				if got := h.JudgeFlow(network.protocol, source, target, nil).Action; got != tun.ActionAccept {
					t.Fatalf("continue with an idle victim returned %v, want accept", got)
				}
				if !admitted.evicted || table.flows[admittedKey] != nil || table.flows[packetFlowKey{source, target}] == nil {
					t.Fatal("continue did not replace the idle flow")
				}
				if got := h.JudgeFlow(network.protocol, admittedSource, admittedTarget, nil).Action; got != tun.ActionReject {
					t.Fatalf("continue at capacity returned %v, want reject", got)
				}
				if got, want := flow.Stats(), packetFlowTestStats(network.name, 1, 1); got != want {
					t.Fatalf("continue changed admission statistics: got %+v, want %+v", got, want)
				}
				if !strings.Contains(logs.String(), network.name+" connection limit reached (limit 1)") {
					t.Fatalf("continue at capacity produced no admission warning: %s", logs.String())
				}
			})
		}
	}
}

func TestPacketFlowJudgeDNSBeforePreMatch(t *testing.T) {
	inbound, logs := newJudgeFlowTestInbound(t)
	inbound.cfg.DNSHijack = true
	inbound.b.SetPreMatch(func(Metadata) PreMatchVerdict {
		t.Fatal("DNS hijack invoked pre-match")
		return PreMatchVerdict{Action: PreMatchReject}
	})
	h := &packetFlowHandler{
		TUNInbound: inbound,
		tcp:        newPacketFlowTable(0),
		udp:        newPacketFlowTable(0),
		logger:     newLogger(inbound.b.slog, "packet-flow"),
	}
	source := netip.MustParseAddrPort("198.18.0.2:50000")
	target := netip.MustParseAddrPort("198.18.0.1:53")
	if got := h.JudgeFlow(uint8(header.TCPProtocolNumber), source, target, nil).Action; got != tun.ActionAccept {
		t.Fatalf("TCP DNS returned %v, want accept", got)
	}
	if got := h.JudgeFlow(uint8(header.UDPProtocolNumber), source, target, nil).Action; got != tun.ActionHijackDNS {
		t.Fatalf("UDP DNS returned %v, want DNS hijack", got)
	}
	if got := (&PacketFlow{handler: h}).Stats(); got != (PacketFlowStats{}) || len(h.tcp.flows)+len(h.udp.flows) != 0 || logs.String() != "" {
		t.Fatalf("DNS hijack changed flow admission: %+v, %s", got, logs.String())
	}
}

func TestTUNJudgePreservesLocalAndOtherProtocolActions(t *testing.T) {
	inbound, _ := newJudgeFlowTestInbound(t)
	source := netip.MustParseAddrPort("198.18.0.2:50000")
	target := netip.MustParseAddrPort("192.0.2.1:443")
	tcp, udp, icmp := uint8(header.TCPProtocolNumber), uint8(header.UDPProtocolNumber), uint8(header.ICMPv4ProtocolNumber)
	for _, protocol := range []uint8{tcp, udp, icmp} {
		if got := inbound.JudgeFlow(protocol, source, target, nil).Action; got != tun.ActionAccept {
			t.Fatalf("protocol %d without pre-match returned %v, want accept", protocol, got)
		}
	}
	inbound.cfg.DNSHijack = true
	inbound.b.SetPreMatch(func(Metadata) PreMatchVerdict {
		t.Fatal("pre-match called for an existing TUN decision")
		return PreMatchVerdict{Action: PreMatchReject}
	})
	for _, tc := range []struct {
		protocol uint8
		target   netip.AddrPort
		want     tun.FlowAction
	}{
		{tcp, netip.MustParseAddrPort("198.18.0.1:443"), tun.ActionDrop},
		{udp, netip.MustParseAddrPort("[2001:db8::1]:443"), tun.ActionDrop},
		{udp, netip.MustParseAddrPort("[::ffff:198.18.0.1]:443"), tun.ActionDrop},
		{icmp, netip.MustParseAddrPort("198.18.0.1:0"), tun.ActionDrop},
		{icmp, netip.MustParseAddrPort("192.0.2.1:0"), tun.ActionAccept},
		{uint8(header.ICMPv6ProtocolNumber), netip.MustParseAddrPort("[2001:db8::2]:0"), tun.ActionAccept},
		{tcp, netip.MustParseAddrPort("198.18.0.1:53"), tun.ActionAccept},
		{udp, netip.MustParseAddrPort("198.18.0.1:53"), tun.ActionAccept},
	} {
		if got := inbound.JudgeFlow(tc.protocol, source, tc.target, nil).Action; got != tc.want {
			t.Errorf("protocol %d to %s returned %v, want %v", tc.protocol, tc.target, got, tc.want)
		}
	}
}

func newJudgeFlowTestInbound(t *testing.T) (*TUNInbound, *packetFlowTestLog) {
	t.Helper()
	logs := new(packetFlowTestLog)
	b := New(Options{Logger: slog.New(slog.NewTextHandler(logs, nil))})
	t.Cleanup(func() { _ = b.Close() })
	return &TUNInbound{
		b: b, ctx: t.Context(),
		cfg: platform.TUNConfig{Address4: "198.18.0.1/30", Address6: "2001:db8::1/64"},
	}, logs
}
