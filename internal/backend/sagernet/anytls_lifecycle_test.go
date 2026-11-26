package sagernet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"runtime/pprof"
	"testing"
	"time"

	rt "github.com/MimoProxy/reka/internal/runtime"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type anyTLSEchoRouter struct{ adapter.Router }

func (anyTLSEchoRouter) RouteConnectionEx(_ context.Context, conn net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}

func TestHotSwapDrainsAnyTLS(t *testing.T) {
	const password = "test-password"
	const profileLabel = "anytls-test"
	labels := pprof.Labels(profileLabel, t.Name())
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	cert, key, pin := hy2TestCertificate(t)
	in, err := anytls.NewInbound(b.ctx, anyTLSEchoRouter{}, b.componentLogger("inbound", "anytls", "echo"), "echo", option.AnyTLSInboundOptions{
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
			Enabled: true, Certificate: []string{cert}, Key: []string{key},
		}},
		Users: []option.AnyTLSUser{{Name: "test", Password: password}},
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := in.(*anytls.Inbound)
	newOutbound := func(tag string) (*Outbound, <-chan struct{}) {
		t.Helper()
		sessionClosed := make(chan struct{})
		var out *Outbound
		var err error
		pprof.Do(context.Background(), labels, func(context.Context) {
			out, err = b.NewOutbound(tag, ProxySpec{
				Type: "anytls", Server: "127.0.0.1", Port: 443, Password: password,
				TLS: &TLSSpec{ServerName: "proxy.test", CertificatePin: pin},
				// sing-anytls uses 30s for intervals at or below 5s.
				Options: json.RawMessage(`{"idle_session_check_interval":"6s","client_metadata":"reka-test"}`),
				// Feed the real TLS inbound without binding a listener.
				Detour: &DetourSpec{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					client, server := net.Pipe()
					t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
					go func() {
						defer close(sessionClosed)
						defer server.Close()
						peer.NewConnection(ctx, server, adapter.InboundContext{}, nil)
					}()
					return client, nil
				}},
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		return out, sessionClosed
	}
	old, oldSessionClosed := newOutbound("old")
	oldClosed := make(chan error, 1)
	routing := rt.New(map[string]*Outbound{"proxy": old}, rt.Options{
		OnClosed: func(_ string, generation uint64, forced int64, err error) {
			if generation == 1 {
				if forced != 0 {
					t.Errorf("retired outbound force-closed %d leases", forced)
				}
				oldClosed <- err
			}
		},
	})
	t.Cleanup(routing.Close)
	acquire := runtimeRoute(t, routing)
	open := func(want *Outbound) net.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		route := acquire(ctx, Metadata{})
		if route.Release != nil {
			t.Cleanup(route.Release)
		}
		if route.Outbound != want {
			t.Fatalf("route selected %v, want %s", route.Outbound, want.Tag())
		}
		var conn net.Conn
		var err error
		pprof.Do(ctx, labels, func(ctx context.Context) {
			conn, err = route.Outbound.out.DialContext(ctx, "tcp", M.ParseSocksaddr("192.0.2.1:443"))
		})
		if err != nil {
			t.Fatal(err)
		}
		leased := &leasedConn{Conn: conn, release: route.Release}
		t.Cleanup(func() { _ = leased.Close() })
		return leased
	}
	echo := func(conn net.Conn, payload string) {
		t.Helper()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, payload); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != payload {
			t.Fatalf("echo = %q, err = %v, want %q", reply, err, payload)
		}
	}
	workerRunning := func() bool {
		t.Helper()
		var workers bytes.Buffer
		if err := pprof.Lookup("goroutine").WriteTo(&workers, 1); err != nil {
			t.Fatal(err)
		}
		return bytes.Contains(workers.Bytes(), []byte(`"`+profileLabel+`":"`+t.Name()+`"`))
	}

	oldStream := open(old)
	echo(oldStream, "before replacement")
	fresh, freshSessionClosed := newOutbound("fresh")
	if _, err := routing.Commit(map[string]*Outbound{"proxy": fresh}); err != nil {
		_ = fresh.Close()
		t.Fatal(err)
	}
	freshStream := open(fresh)
	echo(freshStream, "new session")
	if !old.Lease().Retired() || old.Active() != 1 || fresh.Active() != 1 {
		t.Fatalf("retired = %v, old leases = %d, fresh leases = %d", old.Lease().Retired(), old.Active(), fresh.Active())
	}
	select {
	case <-oldClosed:
		t.Fatal("outbound closed while its lease was active")
	default:
	}
	echo(oldStream, "during drain")
	if !workerRunning() {
		t.Fatal("AnyTLS goroutines did not inherit the test label")
	}
	if err := oldStream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-oldClosed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retired outbound stayed open after draining")
	}
	select {
	case <-oldSessionClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("retired outbound retained its TLS session")
	}
	echo(freshStream, "after retired session closed")
	if err := freshStream.Close(); err != nil {
		t.Fatal(err)
	}
	routing.Close()
	select {
	case <-freshSessionClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("replacement outbound retained its TLS session")
	}
	// The upstream idle reaper observes cancellation on its next check.
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(8 * time.Second)
	for workerRunning() {
		select {
		case <-ticker.C:
		case <-timeout:
			t.Fatal("AnyTLS goroutines remained after both outbounds closed")
		}
	}
}
