package sagernet

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	rt "github.com/MimoProxy/reka/internal/runtime"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestHotSwapDrainsHysteria(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	newOutbound := func(tag string) (*Outbound, net.Conn) {
		t.Helper()
		spec, client := hysteriaTestPipeService(t, b, tag, "")
		return hysteriaTestOutbound(t, b, tag, spec, option.HysteriaOutboundOptions{}), client
	}

	old, oldTransport := newOutbound("old")
	fresh, freshTransport := newOutbound("fresh")
	retired := make(chan error, 1)
	routing := rt.New(map[string]*Outbound{"proxy": old}, rt.Options{
		OnClosed: func(_ string, generation uint64, forced int64, err error) {
			if forced != 0 {
				t.Errorf("generation %d force-closed %d leases", generation, forced)
			}
			if generation == 1 {
				retired <- err
			}
		},
	})
	t.Cleanup(routing.Close)
	acquire := runtimeRoute(t, routing)
	open := func(want *Outbound) net.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		route := acquire(ctx, Metadata{})
		if route.Release != nil {
			t.Cleanup(route.Release)
		}
		if route.Outbound != want {
			t.Fatalf("route selected %v, want %s", route.Outbound, want.Tag())
		}
		conn, err := route.Outbound.out.DialContext(ctx, "tcp", M.ParseSocksaddr("192.0.2.1:443"))
		if err != nil {
			t.Fatal(err)
		}
		c := &leasedConn{Conn: conn, release: route.Release}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	oldStream := open(old)
	hysteriaCheckEcho(t, oldStream, "before swap")
	if _, err := routing.Commit(map[string]*Outbound{"proxy": fresh}); err != nil {
		t.Fatal(err)
	}
	freshStream := open(fresh)
	hysteriaCheckEcho(t, freshStream, "new connection")
	if !old.Lease().Retired() || old.Active() != 1 || fresh.Active() != 1 {
		t.Fatalf("retired = %v, old/fresh leases = %d/%d", old.Lease().Retired(), old.Active(), fresh.Active())
	}
	hysteriaCheckEcho(t, oldStream, "during drain")
	if err := oldStream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-retired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retired outbound stayed open after draining")
	}

	// net.Pipe rejects deadlines once the QUIC client has closed its transport.
	if err := oldTransport.SetDeadline(time.Time{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("retired QUIC transport still accepts deadlines, err = %v", err)
	}
	hysteriaCheckEcho(t, freshStream, "after drain")
	if err := freshStream.Close(); err != nil {
		t.Fatal(err)
	}
	routing.Close()
	if err := freshTransport.SetDeadline(time.Time{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("replacement QUIC transport still accepts deadlines, err = %v", err)
	}
}
