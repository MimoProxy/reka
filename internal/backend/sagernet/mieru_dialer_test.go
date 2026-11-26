package sagernet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
)

func TestMieruServerDialer(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	const server = "mieru.test"
	for _, transport := range []string{"TCP", "UDP"} {
		t.Run(transport, func(t *testing.T) {
			var network, address string
			end := errors.New("detour received physical connection")
			detour := &DetourSpec{
				Dial: func(_ context.Context, n, a string) (net.Conn, error) {
					network, address = n, a
					return nil, end
				},
				Packet: func(_ context.Context, a string) (net.PacketConn, error) {
					network, address = "udp", a
					return nil, end
				},
			}
			opts, err := json.Marshal(map[string]string{"transport": transport, "domain_strategy": "prefer_ipv6"})
			if err != nil {
				t.Fatal(err)
			}
			o, err := b.NewOutbound("example", ProxySpec{Type: "mieru", Server: server, Port: 443,
				Username: "test", Password: "test-password", Options: opts, Detour: detour})
			if err != nil {
				t.Fatal(err)
			}
			defer o.Close()
			if _, err := o.Dial(t.Context(), "udp", "echo.test:53"); err == nil || o.out.(*mieruOutbound).client.IsRunning() {
				t.Fatal("disabled UDP should reject the dial before starting the client")
			}
			lookups := 0
			ctx := WithLookup(t.Context(), func(_ context.Context, host string) ([]netip.Addr, error) {
				lookups++
				if host != server {
					t.Fatalf("looked up %q", host)
				}
				return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, nil
			})
			if _, err := o.Dial(ctx, "tcp", "echo.test:80"); err == nil || !strings.Contains(err.Error(), end.Error()) {
				t.Fatalf("expected detour error, got %v", err)
			}
			wantAddress, wantLookups := server+":443", 0
			if transport == "UDP" {
				wantAddress, wantLookups = "[2001:db8::1]:443", 1
			}
			if network != strings.ToLower(transport) || address != wantAddress || lookups != wantLookups {
				t.Errorf("detour received %s %s after %d DNS lookups", network, address, lookups)
			}
		})
	}
}

func TestMieruCloseCancelsPhysicalDial(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	entered := make(chan struct{})
	o, err := b.NewOutbound("cancel", ProxySpec{
		Type: "mieru", Server: "192.0.2.1", Port: 443, Username: "test", Password: "test-password",
		Options: json.RawMessage(`{"transport":"TCP"}`),
		Detour: &DetourSpec{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := o.Dial(ctx, "tcp", "echo.test:80")
		finished <- err
	}()
	select {
	case <-entered:
	case err := <-finished:
		t.Fatalf("connection failed before reaching detour: %v", err)
	case <-ctx.Done():
		t.Fatal("dial did not reach detour")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; !errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
		t.Fatalf("closing outbound should interrupt detour before caller timeout, got %v", err)
	}
	if o.out.(*mieruOutbound).client.IsRunning() {
		t.Fatal("Mieru client is still running after close")
	}
}

func TestMieruCloseWakesSilentHandshake(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	client, peer := net.Pipe()
	defer peer.Close()
	o, err := b.NewOutbound("silent", ProxySpec{
		Type: "mieru", Server: "192.0.2.1", Port: 443, Username: "test", Password: "test-password",
		Options: json.RawMessage(`{"transport":"TCP","handshake_mode":"HANDSHAKE_STANDARD"}`),
		Detour: &DetourSpec{Dial: func(context.Context, string, string) (net.Conn, error) {
			return client, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := o.Dial(t.Context(), "tcp", "echo.test:80")
		finished <- err
	}()
	// Observe the handshake on the wire and leave the peer silent.
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Read(make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- o.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forced close left a Mieru handshake blocked")
	}
	if err := <-finished; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("handshake after close returned %v", err)
	}
}

func TestMieruPacketBoundaries(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	frames := &mieruPacketFrames{PacketConn: apicommon.NewPacketOverStreamTunnel(reader)}
	c := &mieruPacketConn{PacketConn: apicommon.NewUDPAssociateWrapper(frames)}
	server := apicommon.NewUDPAssociateWrapper(apicommon.NewPacketOverStreamTunnel(writer))
	dst := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:53"))
	go func() {
		defer server.Close()
		for _, p := range [][]byte{bytes.Repeat([]byte{42}, 2048), {}, []byte("next")} {
			if _, err := server.WriteTo(p, dst); err != nil {
				return
			}
		}
	}()
	for _, want := range [][]byte{bytes.Repeat([]byte{42}, 8), {}, []byte("next")} {
		p := make([]byte, 8)
		n, from, err := c.ReadFrom(p)
		if err != nil || !bytes.Equal(p[:n], want) || from.String() != dst.String() {
			t.Fatalf("read %x from %v, err=%v", p[:n], from, err)
		}
	}
	if _, _, err := c.ReadFrom(make([]byte, 8)); err != io.EOF {
		t.Errorf("expected transport EOF, got %v", err)
	}
}
