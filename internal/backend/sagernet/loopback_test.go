package sagernet

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common/json/badoption"
	"golang.org/x/net/proxy"
)

// testLogger shows upstream errors when tests run with -v; set
// REKA_TEST_LOG=debug for everything.
func testLogger(t *testing.T) *slog.Logger {
	level := slog.LevelWarn
	if os.Getenv("REKA_TEST_LOG") == "debug" {
		level = levelTrace
	}
	w := &testWriter{t: t}
	t.Cleanup(func() { w.mu.Lock(); w.done = true; w.mu.Unlock() })
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

// testWriter drops output once the test has finished: relay goroutines may
// still log while connections wind down, and t.Log panics after completion.
type testWriter struct {
	t    *testing.T
	mu   sync.Mutex
	done bool
}

func (w *testWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return len(p), nil
	}
	w.t.Helper()
	w.t.Log(string(bytes.TrimRight(p, "\n")))
	return len(p), nil
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	// These fixtures often listen on TCP and UDP at the same port. Starting
	// from UDP detects both Windows exclusion tables. Random explicit ports
	// avoid walking an entire reserved TCP range with consecutive ephemeral
	// allocations. Production listeners still report bind failures.
	for attempt := 0; attempt < 64; attempt++ {
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(1024+mrand.IntN(65536-1024)))
		packet, err := net.ListenPacket("udp", address)
		if err != nil {
			continue
		}
		listener, err := net.Listen("tcp", packet.LocalAddr().String())
		port := packet.LocalAddr().(*net.UDPAddr).Port
		packet.Close()
		if err == nil {
			listener.Close()
			return uint16(port)
		}
	}
	t.Fatal("no common TCP/UDP fixture port")
	return 0
}

func loopback(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

// echoServer echoes every TCP connection until the client half-closes.
func echoServer(t *testing.T) netip.AddrPort {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).AddrPort()
}

// tlsEchoServer is an echo server behind TLS, so Vision sees inner TLS
// records and takes its splice path.
func tlsEchoServer(t *testing.T) netip.AddrPort {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS() // only for the generated certificate
	cert := srv.TLS.Certificates
	srv.Close()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).AddrPort()
}

// startClient starts a Reka backend with a mixed inbound whose only rule
// sends everything to the outbound built from spec.
func startClient(t *testing.T, spec any) (socks netip.AddrPort, out *Outbound) {
	t.Helper()
	b := New(Options{Logger: testLogger(t), HalfCloseTimeout: testHalfClose})
	t.Cleanup(func() { b.Close() })
	out, err := b.NewOutbound("proxy", spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	b.SetRoute(Fixed(out))
	socks = loopback(freePort(t))
	in, err := b.NewMixedInbound("mixed-in", socks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	return socks, out
}

// startServer starts a second backend that plays the remote node: inbound
// built by newInbound, routed to a direct outbound.
func startServer(t *testing.T, typ string, newInbound func(b *Backend, listen netip.AddrPort) error) netip.AddrPort {
	t.Helper()
	b := New(Options{Logger: testLogger(t), HalfCloseTimeout: testHalfClose})
	t.Cleanup(func() { b.Close() })
	direct, err := b.NewOutbound("direct", DirectSpec{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { direct.Close() })
	b.SetRoute(Fixed(direct))
	listen := loopback(freePort(t))
	if err := newInbound(b, listen); err != nil {
		t.Fatalf("start %s server: %v", typ, err)
	}
	return listen
}

func listenOptions(listen netip.AddrPort) option.ListenOptions {
	addr := badoption.Addr(listen.Addr())
	return option.ListenOptions{Listen: &addr, ListenPort: listen.Port()}
}

func adopt(t *testing.T, b *Backend, tag, typ string, build func() (adapter.Inbound, error)) error {
	in, err := build()
	if err != nil {
		return err
	}
	adopted, err := b.adoptInbound(tag, typ, in, b.componentLogger("inbound", typ, tag))
	if err != nil {
		return err
	}
	t.Cleanup(func() { adopted.Close() })
	return nil
}

// roundTrip sends payload through the SOCKS5 proxy to target and checks the
// echo byte for byte.
func roundTrip(t *testing.T, socks, target netip.AddrPort, useTLS bool, size int) {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", socks.String(), nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.(proxy.ContextDialer).DialContext(context.Background(), "tcp", target.String())
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	var rw net.Conn = conn
	if useTLS {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "echo.test"})
		if err := tc.Handshake(); err != nil {
			t.Fatalf("inner TLS handshake: %v", err)
		}
		rw = tc
	}
	payload := make([]byte, size)
	rand.Read(payload)
	want := sha256.Sum256(payload)
	errc := make(chan error, 1)
	go func() {
		_, err := rw.Write(payload)
		errc <- err
	}()
	got := sha256.New()
	if _, err := io.CopyN(got, rw, int64(size)); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got.Sum(nil), want[:]) {
		t.Fatal("echo mismatch")
	}
}

const payloadSize = 8 << 20

func TestLoopbackDirect(t *testing.T) {
	socks, out := startClient(t, DirectSpec{})
	roundTrip(t, socks, echoServer(t), false, payloadSize)
	waitIdle(t, out)
}

// TestLoopbackShadowsocks uses a domain server address, so the outbound goes
// through the backend's DNS router.
func TestLoopbackShadowsocks(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)
	password := base64.StdEncoding.EncodeToString(key)
	const method = "2022-blake3-aes-128-gcm"
	server := startServer(t, "shadowsocks", func(b *Backend, listen netip.AddrPort) error {
		return adopt(t, b, "ss-in", "shadowsocks", func() (adapter.Inbound, error) {
			return shadowsocks.NewInbound(b.ctx, b.router, b.componentLogger("inbound", "shadowsocks", "ss-in"), "ss-in", option.ShadowsocksInboundOptions{
				ListenOptions: listenOptions(listen),
				Method:        method,
				Password:      password,
			})
		})
	})
	socks, out := startClient(t, ShadowsocksSpec{Server: "localhost", Port: server.Port(), Method: method, Password: password})
	roundTrip(t, socks, echoServer(t), false, payloadSize)
	waitIdle(t, out)
}

// realityServer starts a VLESS + REALITY node (with Vision when flow is set). The REALITY
// handshake target is a local TLS server standing in for a real website.
func realityServer(t *testing.T, uuid, flow string) (listen netip.AddrPort, publicKey, shortID string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey = base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	sid := make([]byte, 4)
	rand.Read(sid)
	shortID = hex.EncodeToString(sid)

	target := httptest.NewUnstartedServer(http.NotFoundHandler())
	target.StartTLS()
	t.Cleanup(target.Close)
	targetAddr := target.Listener.Addr().(*net.TCPAddr).AddrPort()

	listen = startServer(t, "vless", func(b *Backend, listen netip.AddrPort) error {
		return adopt(t, b, "vless-in", "vless", func() (adapter.Inbound, error) {
			return vless.NewInbound(b.ctx, b.router, b.componentLogger("inbound", "vless", "vless-in"), "vless-in", option.VLESSInboundOptions{
				ListenOptions: listenOptions(listen),
				Users:         []option.VLESSUser{{Name: "test", UUID: uuid, Flow: flow}},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
					Enabled:    true,
					ServerName: "reality.test",
					Reality: &option.InboundRealityOptions{
						Enabled: true,
						Handshake: option.InboundRealityHandshakeOptions{
							ServerOptions: option.ServerOptions{Server: targetAddr.Addr().String(), ServerPort: targetAddr.Port()},
						},
						PrivateKey: base64.RawURLEncoding.EncodeToString(priv.Bytes()),
						ShortID:    badoption.Listable[string]{shortID},
					},
				}},
			})
		})
	})
	return listen, publicKey, shortID
}

func realitySpec(server netip.AddrPort, uuid, flow, pub, sid string) VLESSSpec {
	return VLESSSpec{
		Server: "127.0.0.1",
		Port:   server.Port(),
		UUID:   uuid,
		Flow:   flow,
		TLS: &TLSSpec{
			ServerName:  "reality.test",
			Fingerprint: "chrome",
			Reality:     &RealitySpec{PublicKey: pub, ShortID: sid},
		},
	}
}

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func TestLoopbackVLESSReality(t *testing.T) {
	for _, mlkem := range []bool{false, true} {
		name := "x25519"
		if mlkem {
			name = "x25519mlkem768"
		}
		t.Run(name, func(t *testing.T) {
			server, pub, sid := realityServer(t, testUUID, "")
			spec := realitySpec(server, testUUID, "", pub, sid)
			spec.TLS.Reality.X25519MLKEM768 = mlkem
			socks, out := startClient(t, spec)
			roundTrip(t, socks, echoServer(t), false, payloadSize)
			waitIdle(t, out)
		})
	}
}

// TestRealityWrongKey checks that a client with the wrong public key is not
// let through: the server falls back to the real site and the client gives up.
func TestRealityWrongKey(t *testing.T) {
	server, _, sid := realityServer(t, testUUID, "")
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong := base64.RawURLEncoding.EncodeToString(other.PublicKey().Bytes())
	socks, out := startClient(t, realitySpec(server, testUUID, "", wrong, sid))
	dialer, _ := proxy.SOCKS5("tcp", socks.String(), nil, &net.Dialer{Timeout: 5 * time.Second})
	if c, err := dialer.Dial("tcp", echoServer(t).String()); err == nil {
		c.Close()
		t.Fatal("connected with the wrong REALITY public key")
	}
	waitIdle(t, out)
}

func TestLoopbackVLESSRealityVision(t *testing.T) {
	const flow = "xtls-rprx-vision"
	server, pub, sid := realityServer(t, testUUID, flow)
	socks, out := startClient(t, realitySpec(server, testUUID, flow, pub, sid))
	t.Run("plain", func(t *testing.T) {
		roundTrip(t, socks, echoServer(t), false, payloadSize)
	})
	t.Run("inner-tls", func(t *testing.T) {
		roundTrip(t, socks, tlsEchoServer(t), true, payloadSize)
	})
	waitIdle(t, out)
}

// waitIdle checks that relays release the outbound once both sides close.
func waitIdle(t *testing.T, out *Outbound) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for out.Active() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("outbound/%s still has %d active connections", out.Tag(), out.Active())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestLoopbackHTTPConnect covers the HTTP side of the mixed inbound.
func TestLoopbackHTTPConnect(t *testing.T) {
	socks, out := startClient(t, DirectSpec{})
	conn, err := net.DialTimeout("tcp", socks.String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	target := echoServer(t)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT "+target.String()+" HTTP/1.1\r\nHost: "+target.String()+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status %d", resp.StatusCode)
	}
	const msg = "hello through http connect"
	io.WriteString(conn, msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Fatalf("got %q", got)
	}
	conn.Close()
	waitIdle(t, out)
}

// TestRouteReject checks that a nil route closes the client connection.
func TestRouteReject(t *testing.T) {
	b := New(Options{Logger: testLogger(t), HalfCloseTimeout: testHalfClose})
	t.Cleanup(func() { b.Close() })
	b.SetRoute(Fixed(nil))
	listen := loopback(freePort(t))
	in, err := b.NewMixedInbound("mixed-in", listen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	dialer, _ := proxy.SOCKS5("tcp", listen.String(), nil, &net.Dialer{Timeout: 5 * time.Second})
	if c, err := dialer.Dial("tcp", echoServer(t).String()); err == nil {
		c.Close()
		t.Fatal("rejected route still connected")
	}
}

// testHalfClose keeps the half-close grace period short in tests.
const testHalfClose = 300 * time.Millisecond
