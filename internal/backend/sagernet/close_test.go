package sagernet

// Close-semantics experiment: while a long-lived connection is relaying
// through outbound instance A, a new instance B of the same protocol takes
// over routing, then A is closed. The questions are whether A's borrowed
// connection survives A.Close, whether new connections land on B, and
// whether closing A disturbs B.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
)

// stream keeps a connection busy in both directions. The writer sends a
// seeded pseudo-random byte stream until stopped; the reader regenerates
// the same stream and checks every echoed byte.
type stream struct {
	conn     net.Conn
	rw       io.ReadWriter
	sent     atomic.Int64
	received atomic.Int64
	stop     chan struct{}
	writeErr chan error
	readErr  chan error
}

func streamBytes(seed uint64) *rand.ChaCha8 {
	var s [32]byte
	for i := range 8 {
		s[i] = byte(seed >> (8 * i))
	}
	return rand.NewChaCha8(s)
}

// socks5Connect is a minimal SOCKS5 CONNECT client. Unlike x/net/proxy it
// returns the raw *net.TCPConn, so the test can half-close it.
func socks5Connect(socks, target netip.AddrPort) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", socks.String(), 5*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		return fail(fmt.Errorf("socks5 auth: %v %v", reply, err))
	}
	ip := target.Addr().As4()
	req := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(target.Port() >> 8), byte(target.Port())}
	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}
	head := make([]byte, 10) // IPv4 bound address in the reply
	if _, err := io.ReadFull(conn, head); err != nil {
		return fail(err)
	}
	if head[1] != 0 {
		return fail(fmt.Errorf("socks5 connect: reply %d", head[1]))
	}
	return conn, nil
}

func openStream(t *testing.T, socks, target netip.AddrPort, useTLS bool) *stream {
	t.Helper()
	conn, err := socks5Connect(socks, target)
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	s := &stream{conn: conn, rw: conn, stop: make(chan struct{}), writeErr: make(chan error, 1), readErr: make(chan error, 1)}
	if useTLS {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "echo.test"})
		if err := tc.Handshake(); err != nil {
			conn.Close()
			t.Fatalf("inner TLS handshake: %v", err)
		}
		s.rw = tc
	}
	seed := rand.Uint64()
	go s.write(seed)
	go s.read(seed)
	return s
}

func (s *stream) write(seed uint64) {
	src := streamBytes(seed)
	chunk := make([]byte, 32<<10)
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			s.writeErr <- closeWrite(s.rw)
			return
		case <-tick.C:
		}
		src.Read(chunk)
		n, err := s.rw.Write(chunk)
		s.sent.Add(int64(n))
		if err != nil {
			s.writeErr <- err
			return
		}
	}
}

func (s *stream) read(seed uint64) {
	want := streamBytes(seed)
	got := make([]byte, 32<<10)
	exp := make([]byte, 32<<10)
	for {
		n, err := s.rw.Read(got)
		if n > 0 {
			want.Read(exp[:n])
			for i := range n {
				if got[i] != exp[i] {
					s.readErr <- fmt.Errorf("byte %d differs", s.received.Load()+int64(i))
					return
				}
			}
			s.received.Add(int64(n))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			s.readErr <- err
			return
		}
	}
}

func closeWrite(w io.ReadWriter) error {
	if cw, ok := w.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// finish stops writing and waits for the echo of everything sent. It
// returns nil only if every byte came back intact.
func (s *stream) finish() error {
	defer s.conn.Close()
	close(s.stop)
	s.conn.SetDeadline(time.Now().Add(10 * time.Second))
	werr := <-s.writeErr
	rerr := <-s.readErr
	switch {
	case werr != nil:
		return fmt.Errorf("write after %d bytes: %w", s.sent.Load(), werr)
	case rerr != nil:
		return fmt.Errorf("read after %d of %d bytes: %w", s.received.Load(), s.sent.Load(), rerr)
	case s.received.Load() != s.sent.Load():
		return fmt.Errorf("echoed %d of %d bytes", s.received.Load(), s.sent.Load())
	}
	return nil
}

type closeCase struct {
	name   string
	useTLS bool
	// newOutbound builds one instance; it is called twice (A and B).
	newOutbound func(t *testing.T, b *Backend, tag string) *Outbound
}

type closeResult struct {
	oldStream  error // stream on A, which was closed mid-transfer
	newStream  error // stream on B, open while A was closed
	afterClose error // fresh connection after A.Close
	aActive    int64 // A's relays still counted after its streams ended
}

func runReplaceAndClose(t *testing.T, c closeCase) closeResult {
	t.Helper()
	b := New(Options{Logger: testLogger(t), HalfCloseTimeout: testHalfClose})
	t.Cleanup(func() { b.Close() })
	a := c.newOutbound(t, b, "A")
	var current atomic.Pointer[Outbound]
	current.Store(a)
	b.SetRoute(func(ctx context.Context, md Metadata) Route { return Fixed(current.Load())(ctx, md) })
	socks := loopback(freePort(t))
	in, err := b.NewMixedInbound("mixed-in", socks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	target := echoServer(t)
	if c.useTLS {
		target = tlsEchoServer(t)
	}

	old := openStream(t, socks, target, c.useTLS)
	time.Sleep(300 * time.Millisecond)
	if got := a.Active(); got != 1 {
		t.Fatalf("A has %d active relays before replacement, want 1", got)
	}

	bOut := c.newOutbound(t, b, "B")
	t.Cleanup(func() { bOut.Close() })
	current.Store(bOut)
	fresh := openStream(t, socks, target, c.useTLS)
	time.Sleep(200 * time.Millisecond)
	if a.Active() != 1 || bOut.Active() != 1 {
		t.Fatalf("after replacement A=%d B=%d active relays, want 1 and 1", a.Active(), bOut.Active())
	}
	t.Logf("before A.Close: old stream %d bytes, new stream %d bytes", old.received.Load(), fresh.received.Load())

	if err := a.Close(); err != nil {
		t.Logf("A.Close: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	var r closeResult
	r.oldStream = old.finish()
	r.newStream = fresh.finish()
	after := openStream(t, socks, target, c.useTLS)
	time.Sleep(100 * time.Millisecond)
	r.afterClose = after.finish()
	deadline := time.Now().Add(5 * time.Second)
	for (a.Active() != 0 || bOut.Active() != 0) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	r.aActive = a.Active()
	t.Logf("old stream: %v (%d bytes); new stream: %v (%d bytes); after close: %v",
		errOrOK(r.oldStream), old.received.Load(), errOrOK(r.newStream), fresh.received.Load(), errOrOK(r.afterClose))
	return r
}

func errOrOK(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func ssServer(t *testing.T, method, password string, mux bool) netip.AddrPort {
	t.Helper()
	return startServer(t, "shadowsocks", func(b *Backend, listen netip.AddrPort) error {
		return adopt(t, b, "ss-in", "shadowsocks", func() (adapter.Inbound, error) {
			opts := option.ShadowsocksInboundOptions{
				ListenOptions: listenOptions(listen),
				Method:        method,
				Password:      password,
			}
			if mux {
				opts.Multiplex = &option.InboundMultiplexOptions{Enabled: true}
			}
			return shadowsocks.NewInbound(b.ctx, b.router, b.componentLogger("inbound", "shadowsocks", "ss-in"), "ss-in", opts)
		})
	})
}

func newSSPassword() string {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(rand.Uint32())
	}
	return base64.StdEncoding.EncodeToString(key)
}

func specOutbound(spec any) func(*testing.T, *Backend, string) *Outbound {
	return func(t *testing.T, b *Backend, tag string) *Outbound {
		t.Helper()
		out, err := b.NewOutbound(tag, spec)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
}

const ssMethod = "2022-blake3-aes-128-gcm"

// TestCloseSemantics: for outbounds without multiplexing, closing an
// instance must not touch connections it already handed out.
func TestCloseSemantics(t *testing.T) {
	ssPass := newSSPassword()
	ss := ssServer(t, ssMethod, ssPass, false)
	reality, pub, sid := realityServer(t, testUUID, "")
	vision, vpub, vsid := realityServer(t, testUUID, "xtls-rprx-vision")

	cases := []closeCase{
		{name: "direct", newOutbound: specOutbound(DirectSpec{})},
		{name: "shadowsocks", newOutbound: specOutbound(ShadowsocksSpec{Server: "127.0.0.1", Port: ss.Port(), Method: ssMethod, Password: ssPass})},
		{name: "vless-reality", newOutbound: specOutbound(realitySpec(reality, testUUID, "", pub, sid))},
	}
	if !raceEnabled {
		cases = append(cases, closeCase{
			name:        "vless-reality-vision-inner-tls",
			useTLS:      true,
			newOutbound: specOutbound(realitySpec(vision, testUUID, "xtls-rprx-vision", vpub, vsid)),
		})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runReplaceAndClose(t, c)
			if r.oldStream != nil {
				t.Errorf("connection borrowed from closed instance broke: %v", r.oldStream)
			}
			if r.newStream != nil {
				t.Errorf("connection on the new instance broke when the old one closed: %v", r.newStream)
			}
			if r.afterClose != nil {
				t.Errorf("new connection after close failed: %v", r.afterClose)
			}
			if r.aActive != 0 {
				t.Errorf("closed instance still counts %d relays", r.aActive)
			}
		})
	}
}

// TestCloseSemanticsMultiplex documents the opposite behaviour: a
// multiplexed outbound owns its sessions, so Close tears down every stream
// it carries. Reka must drain such an instance (wait for its relays to
// finish) before closing it.
func TestCloseSemanticsMultiplex(t *testing.T) {
	ssPass := newSSPassword()
	server := ssServer(t, ssMethod, ssPass, true)
	newMux := func(t *testing.T, b *Backend, tag string) *Outbound {
		t.Helper()
		out, err := shadowsocks.NewOutbound(b.ctx, b.router, b.componentLogger("outbound", "shadowsocks", tag), tag, option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: server.Port()},
			Method:        ssMethod,
			Password:      ssPass,
			Multiplex:     &option.OutboundMultiplexOptions{Enabled: true, Protocol: "smux"},
		})
		if err != nil {
			t.Fatal(err)
		}
		adopted, err := b.adoptOutbound(tag, "shadowsocks", out)
		if err != nil {
			t.Fatal(err)
		}
		return adopted
	}
	r := runReplaceAndClose(t, closeCase{name: "shadowsocks-smux", newOutbound: newMux})
	if r.oldStream == nil {
		t.Error("stream survived closing its multiplexed outbound; the drain requirement may be unnecessary")
	}
	if r.newStream != nil {
		t.Errorf("closing A broke B's multiplexed stream: %v", r.newStream)
	}
	if r.afterClose != nil {
		t.Errorf("new connection after close failed: %v", r.afterClose)
	}
	if r.aActive != 0 {
		t.Errorf("closed instance still counts %d relays", r.aActive)
	}
}
