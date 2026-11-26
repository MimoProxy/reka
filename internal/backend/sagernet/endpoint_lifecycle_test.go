package sagernet

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	M "github.com/sagernet/sing/common/metadata"
)

var (
	errEndpointTestDial   = errors.New("endpoint received a stream dial")
	errEndpointTestListen = errors.New("endpoint received a packet listen")
)

type recordingEndpoint struct {
	endpoint.Adapter
	starts   []adapter.StartStage
	closes   int
	startErr error
}

func (e *recordingEndpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	e.starts = append(e.starts, stage)
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error {
			e.closes++
			return nil
		})
	}
	if stage == adapter.StartStatePostStart {
		return e.startErr
	}
	return nil
}

func (*recordingEndpoint) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errEndpointTestDial
}

func (*recordingEndpoint) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errEndpointTestListen
}

func testEndpointOutbound(t *testing.T, create endpointFactory) *Outbound {
	t.Helper()
	b := New(Options{})
	t.Cleanup(func() { b.Close() })
	out, err := b.newEndpointOutbound("tunnel", "wireguard", create)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := out.Close(); err != nil {
			t.Error(err)
		}
	})
	return out
}

func TestUnusedEndpointCanCloseWithoutStarting(t *testing.T) {
	var created int
	out := testEndpointOutbound(t, func(context.Context, adapter.Router) (adapter.Endpoint, error) {
		created++
		return new(recordingEndpoint), nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	dest := M.ParseSocksaddr("192.0.2.1:443")
	if _, err := out.out.DialContext(ctx, "tcp", dest); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial returned %v", err)
	}
	if _, err := out.out.ListenPacket(ctx, dest); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled packet listen returned %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := out.out.ListenPacket(t.Context(), dest); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("packet listen after close returned %v", err)
	}
	if created != 0 {
		t.Fatalf("unused outbound constructed %d endpoints", created)
	}
}

func TestEndpointConcurrentFirstUseStartsOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var created atomic.Int32
		ep := new(recordingEndpoint)
		gate := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(gate) })
		defer unblock()
		var block bool
		out := testEndpointOutbound(t, func(context.Context, adapter.Router) (adapter.Endpoint, error) {
			created.Add(1)
			if block {
				<-gate
			}
			return ep, nil
		})
		if created.Load() != 0 {
			t.Fatal("outbound constructed the endpoint before its first use")
		}
		block = true
		dest := M.ParseSocksaddr("192.0.2.1:443")
		stream := make(chan error, 1)
		packet := make(chan error, 1)
		go func() {
			_, err := out.out.DialContext(t.Context(), "tcp", dest)
			stream <- err
		}()
		go func() {
			_, err := out.out.ListenPacket(t.Context(), dest)
			packet <- err
		}()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		synctest.Wait()
		waiter := make(chan error, 1)
		go func() {
			_, err := out.out.ListenPacket(ctx, dest)
			waiter <- err
		}()
		synctest.Wait()
		cancel()
		if err := <-waiter; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled startup waiter returned %v", err)
		}
		unblock()
		if err := <-stream; !errors.Is(err, errEndpointTestDial) {
			t.Fatalf("stream dial returned %v", err)
		}
		if err := <-packet; !errors.Is(err, errEndpointTestListen) {
			t.Fatalf("packet listen returned %v", err)
		}
		if created.Load() != 1 || !slices.Equal(ep.starts, adapter.ListStartStages) {
			t.Fatalf("constructed %d endpoints with startup callbacks %v", created.Load(), ep.starts)
		}
		if ep.closes != 0 {
			t.Fatal("endpoint scope closed after first use")
		}
		for range 2 {
			if err := out.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if ep.closes != 1 {
			t.Fatalf("endpoint cleanup ran %d times", ep.closes)
		}
	})
}

func TestEndpointFailedStartRollsBackAndRetries(t *testing.T) {
	failure := errors.New("unable to start endpoint")
	var attempts []*recordingEndpoint
	out := testEndpointOutbound(t, func(context.Context, adapter.Router) (adapter.Endpoint, error) {
		ep := new(recordingEndpoint)
		if len(attempts) == 0 {
			ep.startErr = failure
		}
		attempts = append(attempts, ep)
		return ep, nil
	})
	dest := M.ParseSocksaddr("192.0.2.1:443")
	if _, err := out.out.ListenPacket(t.Context(), dest); !errors.Is(err, failure) {
		t.Fatalf("startup failure returned %v", err)
	}
	want := []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart, adapter.StartStatePostStart}
	if len(attempts) != 1 || !slices.Equal(attempts[0].starts, want) || attempts[0].closes != 1 {
		t.Fatal("failed endpoint resources were not rolled back before returning")
	}
	if _, err := out.out.DialContext(t.Context(), "tcp", dest); !errors.Is(err, errEndpointTestDial) {
		t.Fatalf("retry returned %v", err)
	}
	if len(attempts) != 2 || !slices.Equal(attempts[1].starts, adapter.ListStartStages) || attempts[1].closes != 0 {
		t.Fatal("retry did not start a fresh endpoint")
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if attempts[0].closes != 1 || attempts[1].closes != 1 {
		t.Fatal("endpoint scope cleanup ran an unexpected number of times")
	}
}
