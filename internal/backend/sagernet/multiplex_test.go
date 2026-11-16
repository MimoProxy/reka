package sagernet

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/sagernet/smux"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	MX "github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The reference parser can wrap every proxy. QUIC/Snell/HTTP/SOCKS peers do
// not have an inline sing-box mux option, so give these real test nodes the
// same protocol-independent mux dispatcher at their routing boundary.
type multiplexTestRouter struct {
	adapter.Router
	mux      adapter.ConnectionRouterEx
	onPacket func()
}

func (r *multiplexTestRouter) RouteConnection(ctx context.Context, c net.Conn, md adapter.InboundContext) error {
	return r.mux.RouteConnection(ctx, c, md)
}
func (r *multiplexTestRouter) RoutePacketConnection(ctx context.Context, c N.PacketConn, md adapter.InboundContext) error {
	if r.onPacket != nil {
		r.onPacket()
	}
	return r.mux.RoutePacketConnection(ctx, c, md)
}
func (r *multiplexTestRouter) RouteConnectionEx(ctx context.Context, c net.Conn, md adapter.InboundContext, close N.CloseHandlerFunc) {
	r.mux.RouteConnectionEx(ctx, c, md, close)
}
func (r *multiplexTestRouter) RoutePacketConnectionEx(ctx context.Context, c N.PacketConn, md adapter.InboundContext, close N.CloseHandlerFunc) {
	if r.onPacket != nil {
		r.onPacket()
	}
	r.mux.RoutePacketConnectionEx(ctx, c, md, close)
}

func TestMultiplexOnlyTCPPreservesNativeUDPProtectAndNetworkReset(t *testing.T) {
	for _, protocol := range []string{"h2mux", "smux", "yamux"} {
		for _, onlyTCP := range []bool{false, true} {
			t.Run(protocol+"/"+map[bool]string{false: "multiplex-udp", true: "native-udp"}[onlyTCP], func(t *testing.T) {
				var nativePackets, protected atomic.Int32
				port := freePort(t)
				server, err := startNode(testLogger(t), func(b *Backend) (adapter.Inbound, string, error) {
					logger := b.componentLogger("inbound", "ss", "mux")
					mux, err := MX.NewRouterWithOptions(b.router, logger, option.InboundMultiplexOptions{Enabled: true})
					if err != nil {
						return nil, "shadowsocks", err
					}
					route := &multiplexTestRouter{Router: b.router, mux: mux, onPacket: func() { nativePackets.Add(1) }}
					in, err := shadowsocks.NewInbound(b.ctx, route, logger, "mux", option.ShadowsocksInboundOptions{ListenOptions: listenOpts(loopback(port)), Method: "aes-128-gcm", Password: "test"})
					return in, "shadowsocks", err
				})
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				b := New(Options{Logger: testLogger(t), ProtectFD: func(int) error { protected.Add(1); return nil }})
				defer b.Close()
				options, _ := json.Marshal(map[string]any{"multiplex": map[string]any{"enabled": true, "protocol": protocol, "padding": true, "only_tcp": onlyTCP, "max_connections": 1}})
				out, err := b.NewOutbound("mux", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: port, Method: "aes-128-gcm", Password: "test", Options: options})
				if err != nil {
					t.Fatal(err)
				}
				defer out.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				target := echoServer(t).String()
				roundTrip := func() {
					t.Helper()
					c, err := out.Dial(ctx, "tcp", target)
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(time.Second))
					c.Write([]byte("mux"))
					reply := make([]byte, 3)
					if _, err = io.ReadFull(c, reply); err != nil || string(reply) != "mux" {
						t.Fatal(err)
					}
				}
				roundTrip()
				udp, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				go func() {
					buffer := make([]byte, 1024)
					for {
						n, addr, err := udp.ReadFrom(buffer)
						if err != nil {
							return
						}
						udp.WriteTo(buffer[:n], addr)
					}
				}()
				destination := M.ParseSocksaddr(udp.LocalAddr().String())
				packet, err := out.out.ListenPacket(ctx, destination)
				if err != nil {
					t.Fatal(err)
				}
				packet.SetDeadline(time.Now().Add(time.Second))
				packet.WriteTo([]byte("udp"), destination)
				reply := make([]byte, 1024)
				n, _, err := packet.ReadFrom(reply)
				packet.Close()
				if err != nil || string(reply[:n]) != "udp" {
					t.Fatal(err)
				}
				wantPackets, wantProtect := int32(0), int32(1)
				if onlyTCP {
					wantPackets, wantProtect = 1, 2
				}
				if nativePackets.Load() != wantPackets || protected.Load() != wantProtect {
					t.Fatal("UDP path or socket protection changed", nativePackets.Load(), protected.Load())
				}
				out.out.(adapter.InterfaceUpdateListener).InterfaceUpdated(ctx)
				roundTrip()
				if protected.Load() != wantProtect+1 {
					t.Fatal("network reset did not open a fresh protected carrier", protected.Load())
				}
				// Negotiation with a server that lacks Brutal must fail, never silently
				// create an ordinary stream that ignores the configured requirement.
				brutalOptions, _ := json.Marshal(map[string]any{"multiplex": map[string]any{"enabled": true, "protocol": protocol, "brutal": map[string]any{"enabled": true, "up_bps": 1250000, "down_bps": 2000000}}})
				brutal, err := b.NewOutbound("brutal", ProxySpec{Type: "shadowsocks", Server: "127.0.0.1", Port: port, Method: "aes-128-gcm", Password: "test", Options: brutalOptions})
				if err != nil {
					t.Fatal(err)
				}
				defer brutal.Close()
				unexpected, err := brutal.Dial(ctx, "tcp", target)
				if err == nil {
					unexpected.Close()
					t.Fatal("server without Brutal accepted the requirement")
				}

			})
		}
	}
}

// Deliberately hold the physical write after smux accepts a frame. A stream
// deadline must let callers reuse their input without mutating queued bytes.
type blockedMuxCarrier struct {
	net.Conn
	entered  chan struct{}
	release  chan struct{}
	observed chan []byte
	once     sync.Once
}

func (c *blockedMuxCarrier) Write(p []byte) (int, error) {
	if len(p) >= 8 && p[1] == 2 {
		c.once.Do(func() { close(c.entered) })
		<-c.release
		c.observed <- bytes.Clone(p[8:])
	}
	return len(p), nil
}
func TestSmuxDeadlineOwnsQueuedPayload(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	carrier := &blockedMuxCarrier{Conn: left, entered: make(chan struct{}), release: make(chan struct{}), observed: make(chan []byte, 1)}
	config := smux.DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := smux.Client(carrier, config)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("original")
	stream.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	finished := make(chan error, 1)
	go func() { _, err := stream.Write(payload); finished <- err }()
	select {
	case <-carrier.entered:
	case <-time.After(time.Second):
		t.Fatal("carrier did not receive frame")
	}
	select {
	case err = <-finished:
		if err == nil {
			t.Fatal("deadline did not fail")
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not return")
	}
	copy(payload, []byte("modified"))
	close(carrier.release)
	select {
	case got := <-carrier.observed:
		if string(got) != "original" {
			t.Fatalf("queued payload mutated: %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("carrier did not complete")
	}
}
