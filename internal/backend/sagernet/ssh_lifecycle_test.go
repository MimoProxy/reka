package sagernet

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rt "github.com/MimoProxy/reka/internal/runtime"
	C "github.com/sagernet/sing-box/constant"
)

func TestHotSwapDrainsSSH(t *testing.T) {
	config, host := sshTestConfig(t)
	peer := newSSHTestServer(t, config, false)
	options := map[string]any{"host_key": sshTestPin(host)}
	old := peer.outbound(t, "password", options)
	drained := make(chan error, 1)
	routing := rt.New(map[string]*Outbound{"proxy": old}, rt.Options{
		OnClosed: func(_ string, generation uint64, forced int64, err error) {
			if generation == 1 {
				if forced != 0 {
					t.Errorf("retired SSH outbound force-closed %d leases", forced)
				}
				drained <- err
			}
		},
	})
	t.Cleanup(routing.Close)
	oldStream := peer.open(t, routing.Current().Resources["proxy"])
	oldSession := sshTestReceive(t, peer.sessions)
	sshTestEcho(t, oldStream, "before replacement")

	fresh := peer.outbound(t, "password", options)
	if _, err := routing.Commit(map[string]*Outbound{"proxy": fresh}); err != nil {
		t.Fatal(err)
	}
	newStream := peer.open(t, routing.Current().Resources["proxy"])
	newSession := sshTestReceive(t, peer.sessions)
	sshTestEcho(t, newStream, "after replacement")
	sshTestEcho(t, oldStream, "during drain")
	if !old.Lease().Retired() || old.Active() != 1 || fresh.Active() != 1 {
		t.Fatalf("retired = %v, old leases = %d, replacement leases = %d", old.Lease().Retired(), old.Active(), fresh.Active())
	}
	if err := oldStream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sshTestReceive(t, drained); err != nil {
		t.Fatal(err)
	}
	sshTestReceive(t, oldSession.done)
	sshTestEcho(t, newStream, "after retired session closed")
	if err := newStream.Close(); err != nil {
		t.Fatal(err)
	}
	routing.Close()
	sshTestReceive(t, newSession.done)
}

func TestSSHHandshakeWaiters(t *testing.T) {
	for _, stage := range []string{"dial", "handshake"} {
		t.Run(stage, func(t *testing.T) {
			b := New(Options{Logger: testLogger(t)})
			defer b.Close()
			var attempts atomic.Int32
			dialStarted := make(chan struct{})
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			out, err := b.NewOutbound("ssh", ProxySpec{
				Type: "ssh", Server: "127.0.0.1", Port: 22, Username: "alice", Password: "password",
				Options: json.RawMessage(`{"reka_insecure_skip_host_key":true}`),
				Detour: &DetourSpec{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					if attempts.Add(1) > 1 {
						return nil, errors.New("unexpected concurrent SSH handshake")
					}
					close(dialStarted)
					if stage == "dial" {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					return client, nil
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = out.Close() })
			dial := func(ctx context.Context) <-chan error {
				result := make(chan error, 1)
				go func() {
					conn, err := out.Dial(ctx, "tcp", "echo.test:1234")
					if conn != nil {
						_ = conn.Close()
					}
					result <- err
				}()
				return result
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			first := dial(ctx)
			sshTestReceive(t, dialStarted)
			if stage == "handshake" {
				if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				// Reading the client's version confirms the physical dial has finished.
				if _, err := bufio.NewReader(peer).ReadString('\n'); err != nil {
					t.Fatal(err)
				}
			}
			waitCtx, stopWaiting := context.WithTimeout(ctx, 30*time.Millisecond)
			defer stopWaiting()
			if err := sshTestReceive(t, dial(waitCtx)); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("waiting dial error = %v, want deadline exceeded", err)
			}
			select {
			case err := <-first:
				t.Fatalf("waiting dial interrupted the original handshake: %v", err)
			default:
			}
			closed := make(chan error, 1)
			go func() { closed <- out.Close() }()
			if err := sshTestReceive(t, closed); err != nil {
				t.Fatal(err)
			}
			if err := sshTestReceive(t, first); err == nil {
				t.Fatal("unfinished SSH handshake succeeded after close")
			}
			if stage == "handshake" {
				if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("SSH transport after close = %v, want EOF", err)
				}
			}
		})
	}
}

func TestSSHHandshakeTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := New(Options{Logger: testLogger(t)})
		defer b.Close()
		client, silentPeer := net.Pipe()
		defer silentPeer.Close()
		out, err := b.NewOutbound("ssh", ProxySpec{
			Type: "ssh", Server: "127.0.0.1", Port: 22, Password: "password",
			Options: json.RawMessage(`{"reka_insecure_skip_host_key":true}`),
			Detour:  &DetourSpec{Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		start := time.Now()
		_, err = out.Dial(context.Background(), "tcp", "echo.test:80")
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != C.TCPTimeout {
			t.Fatalf("silent SSH peer returned %v after %s", err, time.Since(start))
		}
		if _, err := silentPeer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("handshake timeout did not close the transport: %v", err)
		}
	})
}
