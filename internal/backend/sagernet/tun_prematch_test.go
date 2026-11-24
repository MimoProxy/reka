package sagernet

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestTUNPreMatchMetadata(t *testing.T) {
	for _, addresses := range []struct {
		name, source, target string
	}{
		{"IPv4", "192.0.2.2:12345", "203.0.113.1:443"},
		{"IPv6", "[2001:db8:1::2]:12345", "[2001:db8:2::1]:443"},
		{"mapped IPv4", "[::ffff:192.0.2.2]:12345", "[::ffff:203.0.113.1]:443"},
	} {
		for _, transport := range []struct {
			network  string
			protocol uint8
		}{
			{N.NetworkTCP, syscall.IPPROTO_TCP},
			{N.NetworkUDP, syscall.IPPROTO_UDP},
		} {
			t.Run(addresses.name+"/"+transport.network, func(t *testing.T) {
				backend := New(Options{Logger: testLogger(t)})
				defer backend.Close()
				inbound := &TUNInbound{b: backend, ctx: t.Context()}
				source := netip.MustParseAddrPort(addresses.source)
				target := netip.MustParseAddrPort(addresses.target)
				var judged Metadata
				backend.SetPreMatch(func(md Metadata) PreMatchVerdict {
					judged = md
					return PreMatchVerdict{Action: PreMatchContinue}
				})
				prepared := make(chan Metadata, 1)
				routed := make(chan Metadata, 1)
				backend.SetPrepareFlow(func(_ context.Context, md Metadata) PreparedFlow {
					prepared <- md
					return PreparedFlow{Route: func(_ context.Context, md Metadata) Route {
						routed <- md
						return Route{}
					}}
				})
				if verdict := inbound.JudgeFlow(transport.protocol, source, target, nil); verdict.Action != tun.ActionAccept {
					t.Fatalf("JudgeFlow action = %v, want accept", verdict.Action)
				}
				want := Metadata{
					Inbound: "tun", InboundType: "tun", InboundProtocol: "TUN", Network: transport.network,
					Source: source, Destination: Destination{Addr: target.Addr().Unmap(), Port: target.Port()}, Local: target,
				}
				if judged != want {
					t.Fatalf("JudgeFlow metadata = %+v, want %+v", judged, want)
				}

				client, conn := connectionEventPipe(t)
				done := make(chan struct{})
				onClose := func(error) { close(done) }
				src, dst := M.SocksaddrFromNetIP(source), M.SocksaddrFromNetIP(target)
				if transport.network == N.NetworkTCP {
					inbound.NewConnectionEx(t.Context(), conn, src, dst, onClose)
				} else {
					packetConn := eventTestPacketConn{eventTestConn{conn, net.UDPAddrFromAddrPort(target)}}
					inbound.NewPacketConnectionEx(t.Context(), bufio.NewPacketConn(packetConn), src, dst, onClose)
					if err := client.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					if _, err := io.WriteString(client, "datagram"); err != nil {
						t.Fatal(err)
					}
				}
				for _, stage := range []struct {
					name string
					seen <-chan Metadata
				}{
					{"PrepareFlow", prepared}, {"Route", routed},
				} {
					select {
					case got := <-stage.seen:
						if got != judged {
							t.Fatalf("%s metadata = %+v, JudgeFlow metadata = %+v", stage.name, got, judged)
						}
					case <-time.After(3 * time.Second):
						t.Fatalf("%s did not receive metadata", stage.name)
					}
				}
				_ = client.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("connection did not close")
				}
			})
		}
	}
}

func TestTUNPreMatchHistory(t *testing.T) {
	for _, tt := range []struct {
		name    string
		action  PreMatchAction
		want    tun.FlowAction
		out     string
		proto   uint8
		network string
	}{
		{"reject", PreMatchReject, tun.ActionReject, "reject", syscall.IPPROTO_TCP, N.NetworkTCP},
		{"drop", PreMatchDrop, tun.ActionDrop, "reject-drop", syscall.IPPROTO_UDP, N.NetworkUDP},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				store := history.NewBounded(16, 64<<10, history.Connections)
				scope := history.Scope{ProfileID: "test-profile", Generation: 4, Revision: 5}
				backend := New(Options{
					History: store, Logger: testLogger(t),
					HistoryScope: func() history.Scope { return history.Scope{ProfileID: "other-profile", Generation: 6} },
				})
				defer backend.Close()
				inbound := &TUNInbound{b: backend, ctx: t.Context()}
				source := netip.MustParseAddrPort("192.0.2.2:12345")
				target := netip.MustParseAddrPort("203.0.113.1:443")
				info := &api.FlowInfo{
					RuleIndex: 3, RuleID: "deny", Rule: "MATCH," + tt.out,
					Chain: []string{"filtered", tt.out}, Outbound: tt.out,
				}
				backend.SetPreMatch(func(Metadata) PreMatchVerdict {
					return PreMatchVerdict{Action: tt.action, Info: info, Scope: scope}
				})
				if verdict := inbound.JudgeFlow(tt.proto, source, target, nil); verdict.Action != tt.want {
					t.Fatalf("JudgeFlow action = %v, want %v", verdict.Action, tt.want)
				}
				synctest.Wait()
				page, err := store.List(history.Connections, scope.ProfileID, history.ListOptions{})
				if err != nil || len(page.Rows) != 1 {
					t.Fatalf("connection history = %+v, %v, want one row", page, err)
				}
				var trace api.ConnectionTrace
				if err := json.Unmarshal(page.Rows[0].Data, &trace); err != nil {
					t.Fatal(err)
				}
				if trace.Scope != scope || trace.ID == 0 || trace.Inbound != "tun" || trace.Network != tt.network ||
					trace.Source != source.String() || trace.Destination != target.String() ||
					trace.RuleIndex != info.RuleIndex || trace.RuleID != info.RuleID || trace.Rule != info.Rule ||
					trace.Outbound != info.Outbound || !slices.Equal(trace.Chain, info.Chain) {
					t.Fatalf("unexpected pre-matched flow trace: %+v", trace)
				}
				if trace.CloseReason != "rejected" || trace.ErrorStage != "pre-match" || trace.EndedAt.IsZero() ||
					trace.Upload != 0 || trace.Download != 0 || trace.ReadyAt != nil || backend.ConnectionCount() != 0 {
					t.Fatalf("expected completed rejection without traffic or live relay: %+v", trace)
				}
			})
		})
	}
}

func TestTUNPreMatchDoesNotWaitForDebugLog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader, writer := io.Pipe()
		backend := New(Options{Logger: slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelDebug}))})
		defer backend.Close()
		defer reader.Close()
		defer writer.Close()
		inbound := &TUNInbound{b: backend, ctx: t.Context()}
		backend.SetPreMatch(func(Metadata) PreMatchVerdict { return PreMatchVerdict{Action: PreMatchReject} })
		source := netip.MustParseAddrPort("192.0.2.2:12345")
		target := netip.MustParseAddrPort("203.0.113.1:443")
		judged := make(chan tun.FlowAction, 1)
		go func() { judged <- inbound.JudgeFlow(syscall.IPPROTO_TCP, source, target, nil).Action }()
		synctest.Wait()
		select {
		case action := <-judged:
			if action != tun.ActionReject {
				t.Fatalf("JudgeFlow action = %v, want reject", action)
			}
		default:
			t.Fatal("JudgeFlow is waiting for the debug log writer")
		}
		logged := make(chan string, 1)
		go func() {
			var buf [256]byte
			n, _ := reader.Read(buf[:])
			logged <- string(buf[:n])
		}()
		synctest.Wait()
		select {
		case entry := <-logged:
			if !strings.Contains(entry, `msg="pre-match reject `+target.String()+`"`) {
				t.Fatalf("unexpected log entry: %s", entry)
			}
		default:
			t.Fatal("missing pre-match debug log")
		}
	})
}
