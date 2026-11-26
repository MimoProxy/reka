package sagernet

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/testnet"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	ST "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria"
	wire "github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

type hysteriaEchoRouter struct{ adapter.Router }

func (hysteriaEchoRouter) RouteConnectionEx(ctx context.Context, c net.Conn, md adapter.InboundContext, close N.CloseHandlerFunc) {
	hy2EchoHandler{}.NewConnectionEx(ctx, c, md.Source, md.Destination, close)
}

func (hysteriaEchoRouter) RoutePacketConnectionEx(ctx context.Context, c N.PacketConn, md adapter.InboundContext, close N.CloseHandlerFunc) {
	hy2EchoHandler{}.NewPacketConnectionEx(ctx, c, md.Source, md.Destination, close)
}

func hysteriaTestInbound(t *testing.T, users []option.HysteriaUser, obfs ...string) ProxySpec {
	t.Helper()
	cert, key, pin := hy2TestCertificate(t)
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	addr := testnet.RetryAddr(t, func(addr netip.AddrPort) error {
		in, err := hysteria.NewInbound(b.ctx, hysteriaEchoRouter{}, b.logger, "echo", option.HysteriaInboundOptions{
			ListenOptions: listenOpts(addr), UpMbps: 100, DownMbps: 100, Users: users, Obfs: strings.Join(obfs, ""),
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
				Enabled: true, Certificate: []string{cert}, Key: []string{key},
			}},
		})
		if err != nil {
			return err
		}
		scope, err := b.start("echo", in, b.logger)
		if err == nil {
			t.Cleanup(func() { _ = scope.Close() })
		}
		return err
	})
	return ProxySpec{Type: "hysteria", Server: addr.Addr().String(), Port: addr.Port(), TLS: &TLSSpec{ServerName: "proxy.test", CertificatePin: pin}}
}

func hysteriaTestOutbound(t *testing.T, b *Backend, tag string, spec ProxySpec, options option.HysteriaOutboundOptions) *Outbound {
	t.Helper()
	options.UpMbps, options.DownMbps = 80, 100
	raw, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	spec.Options = raw
	out, err := b.NewOutbound(tag, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	return out
}

func hysteriaTestDial(t *testing.T, ctx context.Context, out *Outbound, network string) net.Conn {
	t.Helper()
	c, err := out.Dial(ctx, network, "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func hysteriaCheckEcho(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	// The sing-quic UDP connection supports a read deadline.
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != payload {
		t.Fatalf("echo = %q, err = %v, want %q", got, err, payload)
	}
}

func TestHysteriaV1Interoperability(t *testing.T) {
	rawAuth := []byte{0xfe, 0x00, 0xab}
	spec := hysteriaTestInbound(t, []option.HysteriaUser{
		{Name: "text", AuthString: "echo-password"}, {Name: "binary", Auth: rawAuth},
	})
	for _, tc := range []struct {
		name, password string
		auth           []byte
	}{
		{name: "text", password: "echo-password"},
		{name: "binary", auth: rawAuth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := New(Options{Logger: testLogger(t)})
			t.Cleanup(func() { _ = b.Close() })
			client := spec
			client.Password = tc.password
			out := hysteriaTestOutbound(t, b, "echo", client, option.HysteriaOutboundOptions{Auth: tc.auth})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			for _, network := range []string{"tcp", "udp"} {
				hysteriaCheckEcho(t, hysteriaTestDial(t, ctx, out, network), tc.name+" "+network)
			}
		})
	}
}

func TestHysteriaV1XPlusInboundTCPUDPAndWrongPassword(t *testing.T) {
	spec := hysteriaTestInbound(t, []option.HysteriaUser{{AuthString: "echo-password"}}, "xplus-secret")
	spec.Password = "echo-password"
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	correct := hysteriaTestOutbound(t, b, "correct", spec, option.HysteriaOutboundOptions{Obfs: "xplus-secret"})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, network := range []string{"tcp", "udp"} {
		hysteriaCheckEcho(t, hysteriaTestDial(t, ctx, correct, network), "inbound xplus "+network)
	}
	wrong := hysteriaTestOutbound(t, b, "wrong", spec, option.HysteriaOutboundOptions{Obfs: "wrong-password"})
	ctx, cancelWrong := context.WithTimeout(t.Context(), time.Second)
	defer cancelWrong()
	if c, err := wrong.Dial(ctx, "tcp", "192.0.2.1:443"); err == nil {
		_ = c.Close()
		t.Fatal("wrong XPlus password established a session with the Hysteria inbound")
	}
}

func TestHysteriaV1XPlusTCPUDPAndWrongPassword(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	auth := []byte{0x00, 0xff, 0x01}
	spec, _ := hysteriaTestPipeService(t, b, string(auth), "xplus-secret")
	spec.Password = ""
	bandwidth := uint64(wire.MbpsToBps)
	spec.UpBPS, spec.DownBPS = &bandwidth, &bandwidth
	correct := hysteriaTestOutbound(t, b, "correct", spec, option.HysteriaOutboundOptions{Auth: auth, Obfs: "xplus-secret"})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, network := range []string{"tcp", "udp"} {
		hysteriaCheckEcho(t, hysteriaTestDial(t, ctx, correct, network), "xplus "+network)
	}
	wrongSpec, _ := hysteriaTestPipeService(t, b, string(auth), "xplus-secret")
	wrongSpec.Password = ""
	wrong := hysteriaTestOutbound(t, b, "wrong", wrongSpec, option.HysteriaOutboundOptions{Auth: auth, Obfs: "wrong-password"})
	ctx, cancelWrong := context.WithTimeout(t.Context(), time.Second)
	defer cancelWrong()
	if c, err := wrong.Dial(ctx, "tcp", "192.0.2.1:443"); err == nil {
		_ = c.Close()
		t.Fatal("wrong XPlus password established a Hysteria session")
	}
}

func TestHysteriaV1XPlusDatagramReadBuffers(t *testing.T) {
	raw, packet := hysteriaPacketPipe(t)
	key := []byte("xplus-secret")
	client := wire.NewXPlusClientConn(raw, key)
	server := bufio.NewBindPacketConn(wire.NewXPlusPacketConn(packet, key), raw.LocalAddr())
	for _, direction := range []struct {
		name             string
		sender, receiver net.Conn
	}{
		{"client-to-server", client, server},
		{"server-to-client", server, client},
	} {
		t.Run(direction.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte("data"), 360)
			for _, tc := range []struct {
				name    string
				payload []byte
				size    int
			}{
				{"exact", payload, len(payload)},
				{"short", payload, 7},
				{"empty", nil, 0},
			} {
				t.Run(tc.name, func(t *testing.T) {
					deadline := time.Now().Add(3 * time.Second)
					if err := direction.sender.SetWriteDeadline(deadline); err != nil {
						t.Fatal(err)
					}
					if err := direction.receiver.SetReadDeadline(deadline); err != nil {
						t.Fatal(err)
					}
					written := make(chan error, 1)
					go func() {
						_, err := direction.sender.Write(bytes.Clone(tc.payload))
						written <- err
					}()
					reply := make([]byte, tc.size)
					n, err := direction.receiver.Read(reply)
					if err != nil {
						t.Fatal(err)
					}
					if writeErr := <-written; writeErr != nil {
						t.Fatal(writeErr)
					}
					if n != len(reply) || !bytes.Equal(reply, tc.payload[:tc.size]) {
						t.Fatalf("decoded %d bytes, want first %d bytes of datagram", n, tc.size)
					}
				})
			}
		})
	}
}

func TestHysteriaV1PortHoppingRealTCPUDP(t *testing.T) {
	spec := hysteriaTestInbound(t, []option.HysteriaUser{{AuthString: "echo-password"}})
	front := newHoppingFront(t, &net.UDPAddr{IP: net.ParseIP(spec.Server), Port: int(spec.Port)})
	var ports []string
	for _, socket := range front.sockets {
		port := socket.LocalAddr().(*net.UDPAddr).Port
		ports = append(ports, fmt.Sprintf("%d:%d", port, port))
	}
	spec.Port, spec.Password = 0, "echo-password"
	var protected atomic.Int32
	b := New(Options{Logger: testLogger(t), ProtectFD: func(int) error {
		protected.Add(1)
		return nil
	}})
	t.Cleanup(func() { _ = b.Close() })
	out := hysteriaTestOutbound(t, b, "hop", spec, option.HysteriaOutboundOptions{
		ServerPorts: ports, HopInterval: badoption.Duration(5 * time.Second),
	})
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	tcp := hysteriaTestDial(t, ctx, out, "tcp")
	udp := hysteriaTestDial(t, ctx, out, "udp")

	// Keep both flows open across a change of the actual destination port.
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for i := 0; ; i++ {
		front.mu.Lock()
		hopped := len(front.seen) >= 2
		front.mu.Unlock()
		hysteriaCheckEcho(t, tcp, fmt.Sprintf("tcp %d", i))
		hysteriaCheckEcho(t, udp, fmt.Sprintf("udp %d", i))
		if hopped {
			if protected.Load() < 2 {
				t.Fatalf("observed %d protected sockets across two hopping ports", protected.Load())
			}
			return
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("no traffic reached a second hopping port")
		}
	}
}

type hysteriaPipeConn struct {
	net.Conn
	local, remote *net.UDPAddr
}

// Read consumes a complete net.Pipe write before truncating an oversized datagram like UDP.
func (c hysteriaPipeConn) Read(p []byte) (int, error) {
	packet := buf.NewPacket()
	defer packet.Release()
	_, err := packet.ReadOnceFrom(c.Conn)
	return copy(p, packet.Bytes()), err
}

func (c hysteriaPipeConn) LocalAddr() net.Addr  { return c.local }
func (c hysteriaPipeConn) RemoteAddr() net.Addr { return c.remote }

func hysteriaPacketPipe(t *testing.T) (net.Conn, net.PacketConn) {
	t.Helper()
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	return hysteriaPipeConn{left, client, server}, bufio.NewUnbindPacketConn(hysteriaPipeConn{right, server, client})
}

func hysteriaTestPipeService(t *testing.T, b *Backend, password, obfs string) (ProxySpec, net.Conn) {
	t.Helper()
	cert, key, pin := hy2TestCertificate(t)
	client, packet := hysteriaPacketPipe(t)
	serverTLS, err := ST.NewServer(b.ctx, b.logger, option.InboundTLSOptions{
		Enabled: true, Certificate: []string{cert}, Key: []string{key},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverTLS.Close() })
	service, err := wire.NewService[int](wire.ServiceOptions{
		Context: b.ctx, Logger: b.logger, TLSConfig: serverTLS, Handler: hy2EchoHandler{},
		XPlusPassword: obfs, UDPTimeout: time.Minute,
		SendBPS: 100 * wire.MbpsToBps, ReceiveBPS: 100 * wire.MbpsToBps,
	})
	if err != nil {
		t.Fatal(err)
	}
	service.UpdateUsers([]int{1}, []string{password})
	if err := service.Start(packet); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return ProxySpec{
		Type: "hysteria", Server: "127.0.0.1", Port: 443, Password: password,
		TLS:    &TLSSpec{ServerName: "proxy.test", CertificatePin: pin},
		Detour: &DetourSpec{Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }},
	}, client
}

func TestHysteriaV1ExactBandwidthAndDefaultALPN(t *testing.T) {
	cert, key, pin := hy2TestCertificate(t)
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	client, packet := hysteriaPacketPipe(t)
	// Accept both ALPNs so that the negotiated value exposes an accidental HTTP/3 default.
	listener, err := quic.Listen(packet, &tls.Config{
		Certificates: []tls.Certificate{pair}, NextProtos: []string{"h3", wire.DefaultALPN},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	up, down := uint64(62501), uint64(93751)
	out := hysteriaTestOutbound(t, b, "exact", ProxySpec{
		Type: "hysteria", Server: "127.0.0.1", Port: 443, UpBPS: &up, DownBPS: &down,
		TLS:    &TLSSpec{ServerName: "proxy.test", CertificatePin: pin},
		Detour: &DetourSpec{Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }},
	}, option.HysteriaOutboundOptions{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := out.Dial(ctx, "tcp", "192.0.2.1:443")
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	session, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.CloseWithError(0, "")
	if alpn := session.ConnectionState().TLS.NegotiatedProtocol; alpn != wire.DefaultALPN {
		t.Fatalf("negotiated ALPN = %q, want %q", alpn, wire.DefaultALPN)
	}
	control, err := session.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	if err := control.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	hello, err := wire.ReadClientHello(control)
	if err != nil {
		t.Fatal(err)
	}
	if hello.SendBPS != up || hello.RecvBPS != down {
		t.Fatalf("advertised upload/download = %d/%d bytes/s, want %d/%d", hello.SendBPS, hello.RecvBPS, up, down)
	}
	if err := wire.WriteServerHello(control, wire.ServerHello{OK: true, SendBPS: down, RecvBPS: up}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
