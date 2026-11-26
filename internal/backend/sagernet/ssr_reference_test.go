package sagernet

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/testnet"
	"github.com/sagernet/sing-shadowsocks/shadowstream"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

func TestSSRAgainstShadowsocksInbound(t *testing.T) {
	var server *Server
	endpoint := testnet.RetryAddr(t, func(address netip.AddrPort) (err error) {
		server, err = StartShadowsocksServer(address, "none", "test-password", testLogger(t))
		return err
	})
	t.Cleanup(func() { _ = server.Close() })
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	out, err := b.NewOutbound("ssr", ProxySpec{
		Type: "ssr", Server: endpoint.Addr().String(), Port: endpoint.Port(), Method: "none", Password: "test-password",
		Options: json.RawMessage(`{"protocol":"origin","obfs":"plain","udp":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	t.Run("TCP", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		conn, err := out.out.DialContext(ctx, "tcp", M.SocksaddrFromNetIP(echoServer(t)))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ssrStreamEcho(t, conn, "stream payload")
	})
	t.Run("UDP", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		target, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer target.Close()
		destination := M.SocksaddrFromNet(target.LocalAddr()).Unwrap()
		conn, err := out.out.ListenPacket(ctx, destination)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		deadline, _ := ctx.Deadline()
		if err := target.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		const request, reply = "request payload", "reply payload"
		if n, err := conn.WriteTo([]byte(request), target.LocalAddr()); err != nil || n != len(request) {
			t.Fatalf("SSR datagram write = %d, err = %v", n, err)
		}
		buf := make([]byte, 1024)
		n, sender, err := target.ReadFrom(buf)
		if err != nil || string(buf[:n]) != request {
			t.Fatalf("Shadowsocks datagram = %q, err = %v", buf[:n], err)
		}
		if _, err = target.WriteTo([]byte(reply), sender); err != nil {
			t.Fatal(err)
		}
		n, from, err := conn.ReadFrom(buf)
		if err != nil || M.SocksaddrFromNet(from).Unwrap() != destination || string(buf[:n]) != reply {
			t.Fatalf("SSR datagram = %q from %v, err = %v", buf[:n], from, err)
		}
	})
}

// The detour carries connected datagrams over a pipe and checks the outer
// destination independently of the SOCKS address inside the ciphertext.
type ssrDetourPacketConn struct{ packetFlowEchoPacketConn }

func (c ssrDetourPacketConn) WriteTo(p []byte, to net.Addr) (int, error) {
	if M.SocksaddrFromNet(to) != M.SocksaddrFromNet(c.source) {
		return 0, fmt.Errorf("SSR sent datagram to %v, want %v", to, c.source)
	}
	return c.Write(p)
}

func TestSSRUDPDetour(t *testing.T) {
	const method, password = "aes-256-cfb", "test-password"
	reference, err := shadowstream.New(method, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	server := M.ParseSocksaddr("proxy.test:8388")
	for _, entry := range []string{"DialContext", "ListenPacket"} {
		t.Run(entry, func(t *testing.T) {
			clientPipe, peerPipe := connectionEventPipe(t)
			deadline := time.Now().Add(3 * time.Second)
			if err := clientPipe.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := peerPipe.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			b := New(Options{Logger: testLogger(t)})
			defer b.Close()
			out, err := b.NewOutbound("ssr", ProxySpec{
				Type: "ssr", Server: server.Fqdn, Port: server.Port, Method: method, Password: password,
				Options: json.RawMessage(`{"udp":true,"obfs":"http_post","protocol":"origin"}`),
				Detour: &DetourSpec{Packet: func(_ context.Context, addr string) (net.PacketConn, error) {
					if addr != server.String() {
						return nil, fmt.Errorf("SSR packet detour opened for %s, want %s", addr, server)
					}
					return ssrDetourPacketConn{packetFlowEchoPacketConn{clientPipe, server}}, nil
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			target := M.ParseSocksaddr("[2001:db8::1]:53")
			replyFrom := target
			var client net.PacketConn
			if entry == "DialContext" {
				conn, err := out.out.DialContext(t.Context(), "udp", target)
				if err != nil {
					t.Fatal(err)
				}
				// Drive the connected socket through net.Conn.Read and Write.
				client = bufio.NewUnbindPacketConn(conn)
			} else {
				client, err = out.out.ListenPacket(t.Context(), target)
				if err != nil {
					t.Fatal(err)
				}
				target = M.ParseSocksaddr("destination.test:443")
				replyFrom = M.ParseSocksaddr("reply.test:8443")
			}
			defer client.Close()
			const request, reply = "detoured request", "detoured reply"
			peer := reference.DialPacketConn(peerPipe)
			done := make(chan error, 1)
			go func() {
				defer peer.Close()
				buf := make([]byte, 512)
				n, to, err := peer.ReadFrom(buf)
				if err == nil && (string(buf[:n]) != request || M.SocksaddrFromNet(to).Unwrap() != target) {
					err = fmt.Errorf("Shadowsocks decoded %q for %v, want %q for %v", buf[:n], to, request, target)
				}
				if err == nil {
					_, err = peer.WriteTo([]byte(reply), replyFrom)
				}
				done <- err
			}()
			if n, err := client.WriteTo([]byte(request), target); err != nil || n != len(request) {
				t.Fatalf("SSR datagram write = %d, err = %v", n, err)
			}
			buf := make([]byte, 512)
			n, from, err := client.ReadFrom(buf)
			if peerErr := <-done; peerErr != nil {
				t.Fatal(peerErr)
			}
			if err != nil || string(buf[:n]) != reply || M.SocksaddrFromNet(from).Unwrap() != replyFrom {
				t.Fatalf("SSR decoded %q from %v, want %q from %v, err = %v", buf[:n], from, reply, replyFrom, err)
			}
		})
	}
}
