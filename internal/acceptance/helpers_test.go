package acceptance

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/secret"
)

func logger(t *testing.T) *slog.Logger {
	if os.Getenv("REKA_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func freePort(t *testing.T) int {
	t.Helper()
	// These fixtures often listen on TCP and UDP at the same port. Starting
	// from UDP detects both Windows exclusion tables. Random explicit ports
	// avoid walking an entire reserved TCP range with consecutive ephemeral
	// allocations. Production listeners still report bind failures.
	for attempt := 0; attempt < 64; attempt++ {
		packet, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", 1024+mrand.IntN(65536-1024)))
		if err != nil {
			continue
		}
		listener, err := net.Listen("tcp", packet.LocalAddr().String())
		port := packet.LocalAddr().(*net.UDPAddr).Port
		packet.Close()
		if err == nil {
			listener.Close()
			return port
		}
	}
	t.Fatal("no common TCP/UDP fixture port")
	return 0
}

// harness is one kernel on a temporary state root with a mixed listener.
type harness struct {
	t    *testing.T
	root string
	port int
	sec  secret.Store
	svc  *service.Service
	fail func(string) error
}

func newHarness(t *testing.T, profile string) *harness {
	t.Helper()
	root, err := os.MkdirTemp("", "rka")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	sec, _ := secret.NewFileStore(filepath.Join(root, "secrets", "secrets.json"), nil)
	h := &harness{t: t, root: root, port: freePort(t), sec: sec}
	h.open(profile)
	t.Cleanup(func() { h.svc.Close() })
	return h
}

func (h *harness) local() string {
	return fmt.Sprintf("listeners:\n  - {id: mixed, type: mixed, listen: \"127.0.0.1:%d\"}\n", h.port)
}

func (h *harness) open(profile string) {
	h.t.Helper()
	eng := generation.NewEngine(generation.EngineOptions{
		Backend:      sagernet.Options{Logger: logger(h.t), HalfCloseTimeout: 300 * time.Millisecond, UDPTimeout: 2 * time.Second},
		DrainTimeout: 2 * time.Minute,
	})
	svc, err := service.Open(service.Options{StateRoot: h.root, Secrets: h.sec, Engine: eng, Logger: logger(h.t),
		InitialProfile: []byte(profile), InitialLocal: []byte(h.local()), FailPoint: func(p string) error {
			if h.fail != nil {
				return h.fail(p)
			}
			return nil
		}})
	if err != nil {
		eng.Close()
		h.t.Fatal(err)
	}
	h.svc = svc
}

func (h *harness) engine() *generation.Engine { return h.svc.Engine() }

func (h *harness) commit(req service.CommitRequest) service.Result {
	h.t.Helper()
	if req.BaseRevision == 0 {
		req.BaseRevision = h.svc.ActiveRevision()
	}
	res, err := h.svc.Commit(context.Background(), req)
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}

func (h *harness) mustCommit(req service.CommitRequest) service.Result {
	h.t.Helper()
	res := h.commit(req)
	if res.State != "committed" {
		h.t.Fatalf("commit: %s %+v %v", res.State, res.Error, res.Diagnostics)
	}
	return res
}

func patch(ops ...string) service.CommitRequest {
	var req service.CommitRequest
	for i := 0; i+1 < len(ops); i += 2 {
		req.Patch = append(req.Patch, model.Op{Op: "set", Path: ops[i], Value: []byte(ops[i+1])})
	}
	return req
}

func (h *harness) proxy() netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(h.port))
}

// socks5Connect opens a CONNECT tunnel through the proxy.
func socks5Connect(proxy, target netip.AddrPort) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxy.String(), 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	defer c.SetDeadline(time.Time{})
	fail := func(err error) (net.Conn, error) { c.Close(); return nil, err }
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	var b [2]byte
	if _, err := io.ReadFull(c, b[:]); err != nil || b[1] != 0 {
		return fail(fmt.Errorf("socks5 auth: %v", err))
	}
	req := []byte{5, 1, 0, 1}
	req = append(req, target.Addr().AsSlice()...)
	req = binary.BigEndian.AppendUint16(req, target.Port())
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	head := make([]byte, 10)
	if _, err := io.ReadFull(c, head); err != nil {
		return fail(fmt.Errorf("socks5 reply: %w", err))
	}
	if head[1] != 0 {
		return fail(fmt.Errorf("socks5 connect: reply %d", head[1]))
	}
	return c, nil
}

// echoServer echoes TCP until the client half-closes.
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
				if tc, ok := c.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).AddrPort()
}

// stream is a long-lived echo connection that checks every byte.
type stream struct {
	conn              net.Conn
	sent, received    atomic.Int64
	stop              chan struct{}
	writeErr, readErr chan error
}

func openStream(t *testing.T, proxy, target netip.AddrPort) *stream {
	t.Helper()
	c, err := socks5Connect(proxy, target)
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	s := &stream{conn: c, stop: make(chan struct{}), writeErr: make(chan error, 1), readErr: make(chan error, 1)}
	seed := mrand.Uint64()
	go s.write(seed)
	go s.read(seed)
	return s
}

func bytesFrom(seed uint64) *mrand.ChaCha8 {
	var k [32]byte
	binary.LittleEndian.PutUint64(k[:], seed)
	return mrand.NewChaCha8(k)
}

func (s *stream) write(seed uint64) {
	src := bytesFrom(seed)
	chunk := make([]byte, 16<<10)
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			s.writeErr <- s.conn.(*net.TCPConn).CloseWrite()
			return
		case <-tick.C:
		}
		src.Read(chunk)
		n, err := s.conn.Write(chunk)
		s.sent.Add(int64(n))
		if err != nil {
			s.writeErr <- err
			return
		}
	}
}

func (s *stream) read(seed uint64) {
	want := bytesFrom(seed)
	got := make([]byte, 16<<10)
	exp := make([]byte, 16<<10)
	for {
		n, err := s.conn.Read(got)
		if n > 0 {
			want.Read(exp[:n])
			if !bytes.Equal(got[:n], exp[:n]) {
				s.readErr <- fmt.Errorf("byte mismatch near offset %d", s.received.Load())
				return
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

// finish half-closes and waits for the complete echo.
func (s *stream) finish() error {
	defer s.conn.Close()
	close(s.stop)
	if err := <-s.writeErr; err != nil {
		return fmt.Errorf("write: %w", err)
	}
	select {
	case err := <-s.readErr:
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
	case <-time.After(15 * time.Second):
		return errors.New("echo did not finish")
	}
	if s.received.Load() != s.sent.Load() {
		return fmt.Errorf("received %d of %d bytes", s.received.Load(), s.sent.Load())
	}
	return nil
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func connsByDest(h *harness, dest string) []generation.Connection {
	var out []generation.Connection
	for _, c := range h.engine().Connections() {
		if c.Destination == dest {
			out = append(out, c)
		}
	}
	return out
}

func newSSKey() string {
	k := make([]byte, 16)
	rand.Read(k)
	return base64.StdEncoding.EncodeToString(k)
}

const ssMethod = "2022-blake3-aes-128-gcm"

func ssServer(t *testing.T, password string) netip.AddrPort {
	t.Helper()
	listen := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(freePort(t)))
	s, err := sagernet.StartShadowsocksServer(listen, ssMethod, password, logger(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return listen
}

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// realityServer returns a node and the outbound YAML fields for it.
func realityServer(t *testing.T, multiplex ...bool) (listen netip.AddrPort, outboundYAML string) {
	t.Helper()
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sid := make([]byte, 4)
	rand.Read(sid)
	target := httptest.NewUnstartedServer(http.NotFoundHandler())
	target.TLS = &tls.Config{}
	target.StartTLS()
	t.Cleanup(target.Close)
	listen = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(freePort(t)))
	s, err := sagernet.StartRealityServer(sagernet.RealityServerOptions{
		Listen: listen, UUID: testUUID, ServerName: "reality.test", Multiplex: len(multiplex) > 0 && multiplex[0],
		Target: target.Listener.Addr().(*net.TCPAddr).AddrPort(), PrivateKey: priv.Bytes(), ShortID: hex.EncodeToString(sid),
	}, logger(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	outboundYAML = fmt.Sprintf(`  - id: reality
    type: vless
    server: 127.0.0.1
    port: %d
    uuid: %s
    tls:
      server-name: reality.test
      fingerprint: chrome
      reality: {public-key: %q, short-id: %q}
`, listen.Port(), testUUID, base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), hex.EncodeToString(sid))
	return listen, outboundYAML
}

// fdCount counts open descriptors where the platform exposes them.
func fdCount() (int, bool) {
	dir := "/dev/fd"
	if goruntime.GOOS == "linux" {
		dir = "/proc/self/fd"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, false
	}
	return len(entries), true
}
