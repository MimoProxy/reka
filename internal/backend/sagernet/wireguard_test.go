//go:build with_gvisor

package sagernet

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/testnet"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func wireGuardKeys(t *testing.T) (privateKey, publicKey string) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func wireGuardClientSpec(t *testing.T, server netip.AddrPort, privateKey, peerKey, sharedKey string) ProxySpec {
	t.Helper()
	options := option.WireGuardEndpointOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")}, PrivateKey: privateKey,
		Peers: []option.WireGuardPeer{{
			PublicKey: peerKey, PreSharedKey: sharedKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.8.0.1/32")},
		}},
	}
	raw, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	return ProxySpec{Type: "wireguard", Server: server.Addr().String(), Port: server.Port(), Options: raw}
}

// The peer serves TCP and UDP echoes directly in its tunnel.
type wireGuardEchoRouter struct{ adapter.Router }

func (r wireGuardEchoRouter) RouteConnectionEx(_ context.Context, c net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer c.Close()
	_, err := io.Copy(c, c)
	if onClose != nil {
		onClose(err)
	}
}

func (r wireGuardEchoRouter) RoutePacketConnectionEx(_ context.Context, c N.PacketConn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer c.Close()
	packet := buf.NewPacket()
	dst, err := c.ReadPacket(packet)
	if err == nil {
		err = c.WritePacket(packet, dst)
	} else {
		packet.Release()
	}
	if onClose != nil {
		onClose(err)
	}
}

func TestWireGuardPeer(t *testing.T) {
	clientPrivate, clientPublic := wireGuardKeys(t)
	serverPrivate, serverPublic := wireGuardKeys(t)
	sharedKey, _ := wireGuardKeys(t)
	server := New(Options{Logger: testLogger(t)})
	defer server.Close()
	var peer adapter.Endpoint
	var scope *adapter.Scope
	address := testnet.RetryAddr(t, func(listen netip.AddrPort) error {
		var err error
		peer, err = wireguard.NewEndpoint(server.ctx, wireGuardEchoRouter{server.router}, server.logger, "peer", option.WireGuardEndpointOptions{
			ListenPort: listen.Port(), PrivateKey: serverPrivate,
			Address: []netip.Prefix{netip.MustParsePrefix("10.8.0.1/32")},
			Peers: []option.WireGuardPeer{{
				PublicKey: clientPublic, PreSharedKey: sharedKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")},
			}},
		})
		if err == nil {
			scope, err = server.start("peer", peer, server.logger)
		}
		return err
	})
	defer scope.Close()

	var protected, routed atomic.Int32
	client := New(Options{Logger: testLogger(t), Protect: func(network, _ string, _ syscall.RawConn) error {
		if network == "udp4" || network == "udp6" {
			protected.Add(1)
		}
		return nil
	}})
	defer client.Close()
	client.SetRoute(func(context.Context, Metadata) Route { routed.Add(1); return Route{} })
	spec := wireGuardClientSpec(t, address, clientPrivate, serverPublic, sharedKey)
	spec.Server = "peer.example"
	spec.PeerLookup = func(_ context.Context, name string) ([]netip.Addr, error) {
		if name != spec.Server {
			return nil, errors.New("unexpected domain in peer resolver")
		}
		return []netip.Addr{address.Addr()}, nil
	}
	out, err := client.NewOutbound("tunnel", spec)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	target := M.ParseSocksaddr("10.8.0.1:7070")
	ctx = WithLookup(ctx, func(_ context.Context, name string) ([]netip.Addr, error) {
		if name != "service.example" {
			return nil, errors.New("unexpected domain in destination resolver")
		}
		return []netip.Addr{target.Addr}, nil
	})
	conn, err := out.Dial(ctx, "tcp", "service.example:7070")
	if err != nil {
		t.Fatal("tunnel TCP dial:", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(conn, "tcp echo"); err != nil {
		t.Fatal(err)
	}
	var reply [8]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "tcp echo" {
		t.Fatalf("tunnel TCP echo %q, %v", reply, err)
	}

	packet, err := out.out.ListenPacket(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	packet.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = packet.WriteTo([]byte("udp echo"), target.UDPAddr()); err != nil {
		t.Fatal(err)
	}
	n, from, err := packet.ReadFrom(reply[:])
	if err != nil || string(reply[:n]) != "udp echo" || from.String() != target.String() {
		t.Fatalf("tunnel UDP echo %q from %v, %v", reply[:n], from, err)
	}
	if protected.Load() == 0 {
		t.Fatal("WireGuard exchanged data without protecting its UDP socket")
	}

	clientAddr := M.ParseSocksaddr("10.8.0.2:7070")
	reverse, err := peer.DialContext(ctx, "tcp", clientAddr)
	if err == nil {
		reverse.Close()
		t.Fatal("peer-initiated TCP connection accepted")
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("expected a TCP rejection, got %v", err)
	}
	reverse, err = peer.DialContext(ctx, "udp", clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer reverse.Close()
	reverse.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err = reverse.Write([]byte("peer UDP")); err != nil {
		t.Fatal(err)
	}
	if _, err = reverse.Read(reply[:]); err == nil {
		t.Fatal("peer-initiated UDP received a response")
	}
	if n := routed.Load(); n != 0 {
		t.Fatalf("%d peer-initiated connections reached Reka routing", n)
	}
}

func TestWireGuardCloseReleasesResources(t *testing.T) {
	var protected atomic.Int32
	b := New(Options{Logger: testLogger(t), ProtectFD: func(int) error { protected.Add(1); return nil }})
	defer b.Close()
	private, _ := wireGuardKeys(t)
	_, peer := wireGuardKeys(t)
	spec := wireGuardClientSpec(t, loopback(51820), private, peer, "")
	baseline := runtime.NumGoroutine()
	for range 8 {
		out, err := b.NewOutbound("tunnel", spec)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := out.out.ListenPacket(t.Context(), M.ParseSocksaddr("10.8.0.1:53"))
		if err != nil {
			t.Fatal(err)
		}
		packet.Close()
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
	}
	before := protected.Load()
	if err := b.ReprotectEndpointSockets(); err != nil || before != protected.Load() {
		t.Fatal("closed endpoint retained UDP sockets", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > baseline+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline+2 {
		t.Fatalf("goroutines after closing WireGuard endpoints: got %d, started with %d", n, baseline)
	}
}
