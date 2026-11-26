package sagernet

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	rt "github.com/MimoProxy/reka/internal/runtime"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	M "github.com/sagernet/sing/common/metadata"
)

type ssrEchoRouter struct{ adapter.Router }

func (ssrEchoRouter) RouteConnection(_ context.Context, conn net.Conn, _ adapter.InboundContext) error {
	_, err := io.Copy(conn, conn)
	return err
}

func TestHotSwapDrainsSSR(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	in, err := shadowsocks.NewInbound(b.ctx, ssrEchoRouter{}, b.componentLogger("inbound", "shadowsocks", "echo"), "echo", option.ShadowsocksInboundOptions{Method: "none"})
	if err != nil {
		t.Fatal(err)
	}
	peer := in.(adapter.TCPInjectableInbound)
	newOutbound := func(tag string) *Outbound {
		t.Helper()
		out, err := b.NewOutbound(tag, ProxySpec{
			Type: "ssr", Server: "127.0.0.1", Port: 8388, Method: "none", Password: "test-password",
			Detour: &DetourSpec{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				client, server := net.Pipe()
				done := make(chan struct{})
				go func() {
					defer close(done)
					defer server.Close()
					peer.NewConnection(ctx, server, adapter.InboundContext{}, nil)
				}()
				t.Cleanup(func() {
					_ = client.Close()
					_ = server.Close()
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("Shadowsocks inbound did not finish")
					}
				})
				return client, nil
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	old := newOutbound("old")
	retired := make(chan int64, 1)
	routing := rt.New(map[string]*Outbound{"proxy": old}, rt.Options{
		OnClosed: func(_ string, generation uint64, forced int64, err error) {
			if err != nil {
				t.Errorf("closing SSR outbound: %v", err)
			}
			if generation == 1 {
				retired <- forced
			}
		},
	})
	t.Cleanup(routing.Close)
	acquire := runtimeRoute(t, routing)
	open := func(want *Outbound) net.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		route := acquire(ctx, Metadata{})
		if route.Release != nil {
			t.Cleanup(route.Release)
		}
		if route.Outbound != want {
			t.Fatal("route selected the wrong SSR outbound")
		}
		conn, err := route.Outbound.out.DialContext(ctx, "tcp", M.ParseSocksaddr("echo.test:443"))
		if err != nil {
			t.Fatal(err)
		}
		leased := &leasedConn{Conn: conn, release: route.Release}
		t.Cleanup(func() { _ = leased.Close() })
		return leased
	}

	oldConn := open(old)
	ssrStreamEcho(t, oldConn, "before replacement")
	fresh := newOutbound("fresh")
	if _, err := routing.Commit(map[string]*Outbound{"proxy": fresh}); err != nil {
		_ = fresh.Close()
		t.Fatal(err)
	}
	freshConn := open(fresh)
	ssrStreamEcho(t, freshConn, "new connection")
	if !old.Lease().Retired() || old.Active() != 1 || fresh.Active() != 1 {
		t.Fatalf("retired = %v, old leases = %d, new leases = %d", old.Lease().Retired(), old.Active(), fresh.Active())
	}
	select {
	case <-retired:
		t.Fatal("SSR outbound closed with an active lease")
	default:
	}
	ssrStreamEcho(t, oldConn, "during drain")
	if err := oldConn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case forced := <-retired:
		if forced != 0 {
			t.Fatalf("retired SSR outbound force-closed %d leases", forced)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retired SSR outbound did not close after draining")
	}
	ssrStreamEcho(t, freshConn, "after drain")
}

func ssrStreamEcho(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != payload {
		t.Fatalf("SSR echo = %q, want %q, err = %v", reply, payload, err)
	}
}
