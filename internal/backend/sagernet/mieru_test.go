package sagernet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	rt "github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/testnet"
	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	apimodel "github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/server"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing/common/bufio"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

type mieruTestListeners struct {
	stream net.Listener
	packet net.PacketConn
}

func (l mieruTestListeners) Listen(context.Context, string, string) (net.Listener, error) {
	return l.stream, nil
}

func (l mieruTestListeners) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return l.packet, nil
}

const mieruTestPassword = "echo-password"

func startMieruTestServer(t *testing.T, port uint16, transport pb.TransportProtocol, listeners mieruTestListeners, handle func(net.Conn, *apimodel.Request)) {
	t.Helper()
	srv := server.NewServer()
	err := srv.Store(&server.ServerConfig{
		Config: &pb.ServerConfig{
			ListenIPAddress: proto.String("127.0.0.1"),
			PortBindings:    []*pb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: transport.Enum()}},
			Users:           []*pb.User{{Name: proto.String("echo-user"), Password: proto.String(mieruTestPassword)}},
		},
		StreamListenerFactory: listeners,
		PacketListenerFactory: listeners,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	go func() {
		for {
			conn, req, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				resp := apimodel.Response{Reply: constant.Socks5ReplySuccess, BindAddr: apimodel.AddrSpec{IP: net.IPv4zero}}
				if resp.WriteToSocks5(conn) == nil {
					handle(conn, req)
				}
			}()
		}
	}()
}

func newMieruTestOutbound(t *testing.T, b *Backend, tag string, port uint16, transport pb.TransportProtocol, mux pb.MultiplexingLevel, password string, detour *DetourSpec) *Outbound {
	t.Helper()
	options, err := json.Marshal(map[string]any{"transport": transport.String(), "multiplexing": mux.String(), "handshake_mode": "HANDSHAKE_STANDARD", "udp": true})
	if err != nil {
		t.Fatal(err)
	}
	out, err := b.NewOutbound(tag, ProxySpec{Type: "mieru", Server: "127.0.0.1", Port: port, Username: "echo-user", Password: password, Options: options, Detour: detour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	return out
}

func mieruRoundTrip(t *testing.T, conn net.Conn, data []byte, datagram bool) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(data); err != nil || n != len(data) {
		t.Fatalf("write %d bytes: n=%d, err=%v", len(data), n, err)
	}
	reply := make([]byte, len(data))
	var n int
	var err error
	if datagram {
		n, err = conn.Read(reply)
	} else {
		n, err = io.ReadFull(conn, reply)
	}
	if err != nil || !bytes.Equal(data, reply[:n]) {
		t.Fatalf("echo mismatch: wrote %d bytes, read %d, err=%v", len(data), n, err)
	}
}

func TestMieruInteroperability(t *testing.T) {
	tcpEcho := echoServer(t).String()
	udpEcho, err := mieruTestUDPSocket()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpEcho.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := udpEcho.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := udpEcho.WriteTo(buf[:n], from); err != nil {
				return
			}
		}
	}()
	for _, transport := range []pb.TransportProtocol{pb.TransportProtocol_TCP, pb.TransportProtocol_UDP} {
		t.Run(transport.String(), func(t *testing.T) {
			ln, pc := testnet.ListenTCPUDP(t)
			port := ln.Addr().(*net.TCPAddr).AddrPort().Port()
			startMieruTestServer(t, port, transport, mieruTestListeners{ln, pc}, func(conn net.Conn, req *apimodel.Request) {
				switch req.Command {
				case constant.Socks5ConnectCmd:
					if req.DstAddr.String() != tcpEcho {
						return
					}
					dst, err := net.Dial("tcp", req.DstAddr.String())
					if err != nil {
						return
					}
					defer dst.Close()
					go func() { _, _ = io.Copy(dst, conn); _ = dst.Close() }()
					_, _ = io.Copy(conn, dst)
				case constant.Socks5UDPAssociateCmd:
					relayMieruTestPackets(conn, udpEcho.LocalAddr())
				}
			})
			b := New(Options{Logger: testLogger(t)})
			t.Cleanup(func() { _ = b.Close() })
			for _, mux := range []pb.MultiplexingLevel{pb.MultiplexingLevel_MULTIPLEXING_OFF, pb.MultiplexingLevel_MULTIPLEXING_HIGH} {
				t.Run(mux.String(), func(t *testing.T) {
					out := newMieruTestOutbound(t, b, "echo", port, transport, mux, mieruTestPassword, nil)
					ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
					defer cancel()
					tcp, err := out.Dial(ctx, "tcp", tcpEcho)
					if err != nil {
						t.Fatal(err)
					}
					defer tcp.Close()
					udp, err := out.Dial(ctx, "udp", udpEcho.LocalAddr().String())
					if err != nil {
						t.Fatal(err)
					}
					defer udp.Close()
					mieruRoundTrip(t, tcp, bytes.Repeat([]byte("TCP echo"), 12*1024), false)
					// A single datagram crosses the library's 32 KiB stream PDU boundary.
					mieruRoundTrip(t, udp, bytes.Repeat([]byte("UDP echo"), 5*1024), true)
					mieruRoundTrip(t, udp, []byte("next datagram"), true)
				})
			}
		})
	}
}

func TestMieruWrongPassword(t *testing.T) {
	for _, transport := range []pb.TransportProtocol{pb.TransportProtocol_TCP, pb.TransportProtocol_UDP} {
		t.Run(transport.String(), func(t *testing.T) {
			t.Parallel()
			var listeners mieruTestListeners
			var detour DetourSpec
			switch transport {
			case pb.TransportProtocol_TCP:
				ln := bufconn.Listen(64 * 1024)
				listeners.stream = ln
				t.Cleanup(func() { _ = ln.Close() })
				detour.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) { return ln.DialContext(ctx) }
			case pb.TransportProtocol_UDP:
				client, peer := hysteriaPacketPipe(t)
				listeners.packet = peer
				detour.Packet = func(context.Context, string) (net.PacketConn, error) {
					return bufio.NewUnbindPacketConn(client), nil
				}
			}
			startMieruTestServer(t, 443, transport, listeners, func(net.Conn, *apimodel.Request) {
				t.Error("server accepted an unauthenticated request")
			})
			b := New(Options{Logger: testLogger(t)})
			t.Cleanup(func() { _ = b.Close() })
			out := newMieruTestOutbound(t, b, "wrong", 443, transport, pb.MultiplexingLevel_MULTIPLEXING_OFF, "wrong-password", &detour)
			// Allow the library's ten-second SOCKS handshake to report the failure.
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			conn, err := out.Dial(ctx, "tcp", "echo.test:9000")
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil || ctx.Err() != nil || !strings.Contains(err.Error(), "socks5") {
				t.Fatalf("expected Mieru handshake rejection, got %v", err)
			}
		})
	}
}

// Darwin's default UDP send buffer is smaller than the multi-segment echo.
func mieruTestUDPSocket() (*net.UDPConn, error) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	if err := socket.SetWriteBuffer(128 * 1024); err != nil {
		_ = socket.Close()
		return nil, err
	}
	return socket, nil
}

// The address in each UDP ASSOCIATE frame selects the echo destination.
func relayMieruTestPackets(conn net.Conn, echo net.Addr) {
	tunnel := apicommon.NewUDPAssociateWrapper(apicommon.NewPacketOverStreamTunnel(conn))
	socket, err := mieruTestUDPSocket()
	if err != nil {
		return
	}
	defer socket.Close()
	buf := make([]byte, 65535)
	for {
		n, dst, err := tunnel.ReadFrom(buf)
		if err != nil || dst.String() != echo.String() {
			return
		}
		if _, err := socket.WriteTo(buf[:n], dst); err != nil {
			return
		}
		_ = socket.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := socket.ReadFrom(buf)
		if err != nil {
			return
		}
		if _, err := tunnel.WriteTo(buf[:n], from); err != nil {
			return
		}
	}
}

func TestHotSwapDrainsMieru(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	ln := bufconn.Listen(64 * 1024)
	t.Cleanup(func() { _ = ln.Close() })
	const port = 443
	const target = "echo.test:9000"
	startMieruTestServer(t, port, pb.TransportProtocol_TCP, mieruTestListeners{stream: ln}, func(c net.Conn, req *apimodel.Request) {
		if req.Command == constant.Socks5ConnectCmd && req.DstAddr.String() == target {
			_, _ = io.Copy(c, c)
		}
	})
	newOutbound := func(tag string) *Outbound {
		t.Helper()
		out := newMieruTestOutbound(t, b, tag, port, pb.TransportProtocol_TCP, pb.MultiplexingLevel_MULTIPLEXING_HIGH, mieruTestPassword,
			&DetourSpec{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) { return ln.DialContext(ctx) }})
		if out.out.(*mieruOutbound).client.IsRunning() {
			t.Fatal("Mieru started before its first connection")
		}
		return out
	}
	old := newOutbound("old")
	drained := make(chan error, 1)
	routing := rt.New(map[string]*Outbound{"proxy": old}, rt.Options{OnClosed: func(_ string, generation uint64, forced int64, err error) {
		if generation == 1 {
			if forced != 0 {
				t.Errorf("retired Mieru outbound force-closed %d leases", forced)
			}
			drained <- err
		}
	}})
	t.Cleanup(routing.Close)
	openCurrent := func() net.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		c, err := routing.Current().Resources["proxy"].Dial(ctx, "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	oldConn := openCurrent()
	mieruRoundTrip(t, oldConn, bytes.Repeat([]byte("before replacement"), 8192), false)
	fresh := newOutbound("fresh")
	if _, err := routing.Commit(map[string]*Outbound{"proxy": fresh}); err != nil {
		t.Fatal(err)
	}
	freshConn := openCurrent()
	mieruRoundTrip(t, freshConn, []byte("after replacement"), false)
	if !old.Lease().Retired() || old.Active() != 1 || fresh.Active() != 1 || !old.out.(*mieruOutbound).client.IsRunning() {
		t.Fatal("expected a running, retired Mieru client and one lease on each generation")
	}
	mieruRoundTrip(t, oldConn, []byte("during drain"), false)
	if err := oldConn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-drained:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("old generation did not drain")
	}
	waitMieruStopped(t, old)
	if !fresh.out.(*mieruOutbound).client.IsRunning() {
		t.Fatal("expected only the replacement Mieru client to be running after drain")
	}
	mieruRoundTrip(t, freshConn, []byte("after old client stopped"), false)
}

// A packet detour supplies the physical UDP socket. One Mieru association
// must preserve the address and boundary of each application datagram.
func TestMieruPacketDetour(t *testing.T) {
	client, peer := hysteriaPacketPipe(t)
	startMieruTestServer(t, 443, pb.TransportProtocol_UDP, mieruTestListeners{packet: peer}, func(conn net.Conn, req *apimodel.Request) {
		if req.Command != constant.Socks5UDPAssociateCmd {
			return
		}
		packets := apicommon.NewUDPAssociateWrapper(apicommon.NewPacketOverStreamTunnel(conn))
		data := make([]byte, 65535)
		for {
			n, dst, err := packets.ReadFrom(data)
			if err != nil {
				return
			}
			if _, err := packets.WriteTo(data[:n], dst); err != nil {
				return
			}
		}
	})
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	out, err := b.NewOutbound("range", ProxySpec{
		Type: "mieru", Server: "127.0.0.1", Username: "echo-user", Password: mieruTestPassword,
		Options: json.RawMessage(`{"transport":"UDP","server_ports":["443-443"],"handshake_mode":"HANDSHAKE_NO_WAIT","udp":true}`),
		Detour: &DetourSpec{Packet: func(_ context.Context, remote string) (net.PacketConn, error) {
			if remote != "127.0.0.1:443" {
				t.Errorf("packet detour selected %s", remote)
			}
			return bufio.NewUnbindPacketConn(client), nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	pin, err := out.Pin()
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	packet, err := pin.ListenPacket(ctx, "192.0.2.1:8001")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	for _, dst := range []string{"192.0.2.1:8001", "[2001:db8::1]:8002"} {
		payload := bytes.Repeat([]byte(dst), 2500)
		_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := packet.WriteTo(payload, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(dst))); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(payload))
		n, from, err := packet.ReadFrom(reply)
		if err != nil || !bytes.Equal(reply[:n], payload) || from == nil || from.String() != dst {
			t.Fatalf("reply from %v, read %d of %d bytes, err=%v", from, n, len(payload), err)
		}
	}
}
