package sagernet

// End-to-end hot swap: internal/runtime publishes snapshots of outbound
// instances and retires the ones a commit drops; real connections relay
// through a mixed inbound the whole time. (Production code depends the
// other way round, runtime on backend; only this test imports runtime.)

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rt "github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/testnet"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
)

// runtimeRoute routes every connection to the snapshot's "proxy" outbound,
// leasing it through the runtime.
func runtimeRoute(t *testing.T, r *rt.Runtime[*Outbound]) RouteFunc {
	pick := func(s *rt.Snapshot[*Outbound]) (*Outbound, bool) {
		out, ok := s.Resources["proxy"]
		return out, ok
	}
	return func(context.Context, Metadata) Route {
		_, out, release, ok, err := r.Acquire(pick)
		if err != nil {
			t.Error(err)
		}
		if !ok {
			return Route{}
		}
		return Route{Outbound: out, Release: release}
	}
}

// TestHotSwapUnderLoad replaces the outbound every 10ms while 8 clients
// keep opening, using and closing connections. (Each connection costs three
// sockets and leaves TIME_WAIT entries behind; heavier churn exhausts
// macOS's ephemeral ports when the test is repeated.) Every connection must
// complete intact, and every replaced instance must be closed after
// draining, never force-closed.
func TestHotSwapUnderLoad(t *testing.T) {
	b := New(Options{Logger: testLogger(t), HalfCloseTimeout: testHalfClose})
	t.Cleanup(func() { b.Close() })
	newDirect := func() *Outbound {
		out, err := b.NewOutbound("proxy", DirectSpec{})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	var closes atomic.Int64
	runtime := rt.New(map[string]*Outbound{"proxy": newDirect()}, rt.Options{
		DrainTimeout: 10 * time.Second,
		OnClosed: func(_ string, _ uint64, forced int64, err error) {
			closes.Add(1)
			if forced != 0 || err != nil {
				t.Errorf("instance closed with forced=%d err=%v", forced, err)
			}
		},
	})
	b.SetRoute(runtimeRoute(t, runtime))
	var in *Inbound
	socks := testnet.RetryAddr(t, func(address netip.AddrPort) (err error) {
		in, err = b.NewMixedInbound("mixed-in", address)
		return err
	})
	t.Cleanup(func() { in.Close() })
	target := echoServer(t)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var conns, failed atomic.Int64
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := openStream(t, socks, target, false)
				time.Sleep(time.Duration(20+conns.Load()%60) * time.Millisecond)
				if err := s.finish(); err != nil {
					failed.Add(1)
					t.Errorf("connection: %v", err)
				}
				conns.Add(1)
			}
		}()
	}
	var commits int64
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := runtime.Commit(map[string]*Outbound{"proxy": newDirect()}); err != nil {
			t.Fatal(err)
		}
		commits++
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	runtime.Close()
	st := runtime.Stats()
	t.Logf("commits=%d connections=%d failed=%d closed-instances=%d acquire-retries=%d",
		commits, conns.Load(), failed.Load(), closes.Load(), st.Retries)
	if want := commits + 1; closes.Load() != want {
		t.Fatalf("closed %d instances, want %d", closes.Load(), want)
	}
	if st.Forced != 0 || st.Retiring != 0 {
		t.Fatalf("stats after close: %+v", st)
	}
}

// TestHotSwapDrainsMultiplex repeats the TestCloseSemanticsMultiplex case that cut a stream
// (closing a multiplexed outbound mid-transfer), but through the runtime:
// the old instance is retired, keeps carrying its stream, and closes only
// once that stream ends.
func TestHotSwapDrainsMultiplex(t *testing.T) {
	ssPass := newSSPassword()
	server := ssServer(t, ssMethod, ssPass, true)
	b := New(Options{Logger: testLogger(t), HalfCloseTimeout: testHalfClose})
	t.Cleanup(func() { b.Close() })
	newMux := func(tag string) *Outbound {
		out, err := shadowsocks.NewOutbound(b.ctx, b.router, b.componentLogger("outbound", "shadowsocks", tag), tag, option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: server.Port()},
			Method:        ssMethod,
			Password:      ssPass,
			Multiplex:     &option.OutboundMultiplexOptions{Enabled: true, Protocol: "smux"},
		})
		if err != nil {
			t.Fatal(err)
		}
		adopted, err := b.adoptOutbound(tag, "shadowsocks", out)
		if err != nil {
			t.Fatal(err)
		}
		return adopted
	}
	a := newMux("A")
	closedA := make(chan int64, 1)
	runtime := rt.New(map[string]*Outbound{"proxy": a}, rt.Options{
		DrainTimeout: 10 * time.Second,
		OnClosed: func(id string, gen uint64, forced int64, _ error) {
			if gen == 1 {
				closedA <- forced
			}
		},
	})
	t.Cleanup(runtime.Close)
	b.SetRoute(runtimeRoute(t, runtime))
	var in *Inbound
	socks := testnet.RetryAddr(t, func(address netip.AddrPort) (err error) {
		in, err = b.NewMixedInbound("mixed-in", address)
		return err
	})
	t.Cleanup(func() { in.Close() })
	target := echoServer(t)

	old := openStream(t, socks, target, false)
	time.Sleep(300 * time.Millisecond)
	bOut := newMux("B")
	if _, err := runtime.Commit(map[string]*Outbound{"proxy": bOut}); err != nil {
		t.Fatal(err)
	}
	fresh := openStream(t, socks, target, false)
	time.Sleep(400 * time.Millisecond)

	if !a.Lease().Retired() || a.Active() != 1 {
		t.Fatalf("A retired=%v active=%d, want retired with 1 relay", a.Lease().Retired(), a.Active())
	}
	if bOut.Active() != 1 {
		t.Fatalf("B has %d relays, want 1", bOut.Active())
	}
	select {
	case <-closedA:
		t.Fatal("A closed while its stream was still running")
	default:
	}
	if err := old.finish(); err != nil {
		t.Fatalf("stream on the retired multiplexed instance: %v", err)
	}
	select {
	case forced := <-closedA:
		if forced != 0 {
			t.Fatalf("A force-closed %d leases", forced)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("A not closed after its stream ended")
	}
	if err := fresh.finish(); err != nil {
		t.Fatalf("stream on B: %v", err)
	}
	t.Logf("old stream %d bytes, new stream %d bytes", old.received.Load(), fresh.received.Load())
}
