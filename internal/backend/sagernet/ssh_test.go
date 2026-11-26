package sagernet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/test/bufconn"
)

type sshTestSession struct {
	conn *ssh.ServerConn
	done chan struct{}
}

type sshTestServer struct {
	backend  *Backend
	port     uint16
	detour   *DetourSpec
	target   string
	loopback bool
	accepts  atomic.Int32
	sessions chan sshTestSession
	// Delayed channel confirmations and keepalive replies can be controlled independently.
	pending chan ssh.NewChannel
	probes  chan *ssh.Request
}

func sshTestReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SSH peer")
		var zero T
		return zero
	}
}

func sshTestConfig(t *testing.T) (*ssh.ServerConfig, ssh.Signer) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	c := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() == "alice" && string(password) == "password" {
			return &ssh.Permissions{Extensions: map[string]string{"auth": "password"}}, nil
		}
		return nil, errors.New("invalid SSH credentials")
	}}
	c.AddHostKey(key)
	return c, key
}

func newSSHTestServer(t *testing.T, config *ssh.ServerConfig, loopback bool) *sshTestServer {
	t.Helper()
	s := &sshTestServer{
		backend: New(Options{Logger: testLogger(t)}), port: 22, target: "echo.test:1234", loopback: loopback,
		sessions: make(chan sshTestSession, 16), pending: make(chan ssh.NewChannel, 16), probes: make(chan *ssh.Request, 16),
	}
	t.Cleanup(func() { _ = s.backend.Close() })
	var listener net.Listener
	if loopback {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listener = ln
		s.port = ln.Addr().(*net.TCPAddr).AddrPort().Port()
		s.target = echoServer(t).String()
	} else {
		// Both SSH peers write their version before reading, so the pipe needs buffering.
		ln := bufconn.Listen(64 * 1024)
		listener = ln
		s.detour = &DetourSpec{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) { return ln.DialContext(ctx) }}
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.accepts.Add(1)
			go s.serve(conn, config)
		}
	}()
	return s
}

func (s *sshTestServer) serve(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	server, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	session := sshTestSession{conn: server, done: make(chan struct{})}
	defer close(session.done)
	s.sessions <- session
	go func() {
		for req := range requests {
			if req.Type == "keepalive@openssh.com" && req.WantReply {
				s.probes <- req
			} else {
				_ = req.Reply(false, nil)
			}
		}
	}()
	for ch := range channels {
		var target struct {
			Host       string
			Port       uint32
			Origin     string
			OriginPort uint32
		}
		if ch.ChannelType() != "direct-tcpip" || ssh.Unmarshal(ch.ExtraData(), &target) != nil {
			_ = ch.Reject(ssh.UnknownChannelType, "expected direct-tcpip")
			continue
		}
		if target.Host == "pending.test" {
			s.pending <- ch
			continue
		}
		addr := net.JoinHostPort(target.Host, strconv.FormatUint(uint64(target.Port), 10))
		if addr != s.target {
			_ = ch.Reject(ssh.Prohibited, "unknown target")
			continue
		}
		go s.forward(ch)
	}
}

func (s *sshTestServer) forward(ch ssh.NewChannel) {
	var echo net.Conn
	if s.loopback {
		var err error
		echo, err = net.DialTimeout("tcp", s.target, time.Second)
		if err != nil {
			_ = ch.Reject(ssh.ConnectionFailed, "echo server unavailable")
			return
		}
		defer echo.Close()
	}
	stream, requests, err := ch.Accept()
	if err != nil {
		return
	}
	defer stream.Close()
	go ssh.DiscardRequests(requests)
	if echo == nil {
		_, _ = io.Copy(stream, stream)
		return
	}
	go func() {
		_, _ = io.Copy(echo, stream)
		_ = echo.(*net.TCPConn).CloseWrite()
	}()
	_, _ = io.Copy(stream, echo)
}

func (s *sshTestServer) outbound(t *testing.T, password string, options map[string]any) *Outbound {
	t.Helper()
	raw, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.backend.NewOutbound("ssh-test", ProxySpec{
		Type: "ssh", Server: "127.0.0.1", Port: s.port, Username: "alice", Password: password, Options: raw, Detour: s.detour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	return out
}

func (s *sshTestServer) open(t *testing.T, out *Outbound) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := out.Dial(ctx, "tcp", s.target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func sshTestPin(key ssh.Signer) []string {
	return []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey())))}
}

func sshTestEcho(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != payload {
		t.Fatalf("SSH echo = %q, err = %v, want %q", reply, err, payload)
	}
}

func TestSSHInteroperability(t *testing.T) {
	testSSHInteroperability(t, false)
}

// The protocol interoperability suite runs these cases over loopback TCP as well.
func testSSHInteroperability(t *testing.T, loopback bool) {
	t.Run("authentication and forwarding", func(t *testing.T) { testSSHForwarding(t, loopback) })
	t.Run("handshake failures", func(t *testing.T) { testSSHHandshakeFailures(t, loopback) })
	t.Run("shared session", func(t *testing.T) { testSSHSharedSession(t, loopback) })
	t.Run("reconnect", func(t *testing.T) { testSSHReconnectAfterDisconnect(t, loopback) })
}

func testSSHForwarding(t *testing.T, loopback bool) {
	_, id, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ssh.NewSignerFromKey(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, explicitAlgo                                    string
		userKey, encrypted, password, skip, rsaHost, hostCert bool
	}{
		{name: "password", password: true},
		{name: "public key", userKey: true},
		{name: "encrypted key before password", userKey: true, encrypted: true, password: true},
		{name: "explicit skip", password: true, skip: true},
		{name: "pin second server key by RSA type", password: true, rsaHost: true},
		{name: "pin RSA host certificate", password: true, rsaHost: true, hostCert: true},
		{name: "explicit RSA algorithm", password: true, rsaHost: true, explicitAlgo: ssh.KeyAlgoRSASHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, host := sshTestConfig(t)
			if tc.rsaHost {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				host, err = ssh.NewSignerFromKey(key)
				if err != nil {
					t.Fatal(err)
				}
				if tc.hostCert {
					cert := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, ValidBefore: ssh.CertTimeInfinity}
					if err := cert.SignCert(rand.Reader, clientKey); err != nil {
						t.Fatal(err)
					}
					host, err = ssh.NewCertSigner(cert, host)
					if err != nil {
						t.Fatal(err)
					}
				}
				config.AddHostKey(host)
			}
			options := map[string]any{"host_key": sshTestPin(host)}
			if tc.explicitAlgo != "" {
				options["host_key_algorithms"] = []string{tc.explicitAlgo}
				options["client_version"] = "SSH-2.0-reka-test"
			}
			if tc.skip {
				options = map[string]any{"reka_insecure_skip_host_key": true, "host_key_algorithms": []string{}}
			}
			wantAuth := "password"
			if tc.userKey {
				wantAuth = "publickey"
				config.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					if meta.User() == "alice" && bytes.Equal(key.Marshal(), clientKey.PublicKey().Marshal()) {
						return &ssh.Permissions{Extensions: map[string]string{"auth": "publickey"}}, nil
					}
					return nil, errors.New("unknown SSH identity")
				}
				var block *pem.Block
				var err error
				if tc.encrypted {
					options["private_key_passphrase"] = "phrase"
					block, err = ssh.MarshalPrivateKeyWithPassphrase(id, "", []byte("phrase"))
				} else {
					block, err = ssh.MarshalPrivateKey(id, "")
				}
				if err != nil {
					t.Fatal(err)
				}
				options["private_key"] = string(pem.EncodeToMemory(block))
			}
			password := ""
			if tc.password {
				password = "password"
			}
			s := newSSHTestServer(t, config, loopback)
			out := s.outbound(t, password, options)
			sshTestEcho(t, s.open(t, out), tc.name)
			peer := sshTestReceive(t, s.sessions).conn
			if got := peer.Permissions.Extensions["auth"]; got != wantAuth {
				t.Fatalf("used authentication %q, want %q", got, wantAuth)
			}
			if tc.rsaHost {
				wantAlgo := ssh.KeyAlgoRSASHA512
				if tc.hostCert {
					wantAlgo = ssh.CertAlgoRSASHA512v01
				}
				if tc.explicitAlgo != "" {
					wantAlgo = tc.explicitAlgo
					if string(peer.ClientVersion()) != "SSH-2.0-reka-test" {
						t.Fatal("configured SSH client version did not reach peer")
					}
				}
				if got := peer.Conn.(ssh.AlgorithmsConnMetadata).Algorithms().HostKey; got != wantAlgo {
					t.Fatalf("negotiated host key algorithm %q, want %q", got, wantAlgo)
				}
			}
		})
	}
}

func TestSSHRequiresHostKeyPolicy(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	_, host := sshTestConfig(t)
	for _, options := range []map[string]any{
		{}, {"reka_insecure_skip_host_key": false}, {"host_key": sshTestPin(host), "reka_insecure_skip_host_key": true},
	} {
		raw, err := json.Marshal(options)
		if err != nil {
			t.Fatal(err)
		}
		out, err := b.NewOutbound("ssh", ProxySpec{Type: "ssh", Server: "127.0.0.1", Port: 22, Password: "password", Options: raw})
		if err == nil {
			out.Close()
			t.Fatal("SSH outbound accepted an invalid host key policy")
		}
		if !strings.Contains(err.Error(), "host-key") {
			t.Fatalf("unexpected host key validation error: %v", err)
		}
	}
}

func testSSHHandshakeFailures(t *testing.T, loopback bool) {
	config, host := sshTestConfig(t)
	_, other := sshTestConfig(t)
	s := newSSHTestServer(t, config, loopback)
	for _, tc := range []struct {
		name, password, errContains string
		pin                         ssh.Signer
	}{
		{"mismatch", "password", "mismatch", other}, {"bad password", "wrong", "authenticate", host},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := s.outbound(t, tc.password, map[string]any{"host_key": sshTestPin(tc.pin)})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := out.Dial(ctx, "tcp", s.target)
			if err == nil {
				conn.Close()
				t.Fatal("unexpected SSH handshake success")
			}
			if !strings.Contains(err.Error(), tc.errContains) || ctx.Err() != nil {
				t.Fatalf("unexpected SSH handshake result: %v", err)
			}
			if tc.name == "mismatch" && !strings.Contains(err.Error(), sshTestPin(host)[0]) {
				t.Errorf("host key mismatch did not report the received key: %v", err)
			}
		})
	}
}

func testSSHSharedSession(t *testing.T, loopback bool) {
	config, host := sshTestConfig(t)
	s := newSSHTestServer(t, config, loopback)
	out := s.outbound(t, "password", map[string]any{"host_key": sshTestPin(host)})
	if s.accepts.Load() != 0 || !slices.Equal(out.out.Network(), []string{"tcp"}) {
		t.Fatal("SSH outbound must be lazy and advertise only TCP")
	}
	target := M.ParseSocksaddr(s.target)
	if _, err := out.out.ListenPacket(t.Context(), target); err == nil {
		t.Fatal("SSH accepted a packet listener")
	}
	if _, err := out.out.DialContext(t.Context(), "udp", target); err == nil || s.accepts.Load() != 0 {
		t.Fatal("UDP dial should fail before connecting to SSH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := make(chan struct{})
	var streams [12]net.Conn
	var wg sync.WaitGroup
	for i := range streams {
		wg.Go(func() {
			<-start
			c, err := out.Dial(ctx, "tcp", s.target)
			if err != nil {
				t.Errorf("concurrent SSH dial: %v", err)
				return
			}
			streams[i] = c
		})
	}
	close(start)
	wg.Wait()
	session := sshTestReceive(t, s.sessions)
	if got := s.accepts.Load(); got != 1 {
		t.Fatalf("opened %d SSH connections for concurrent dials", got)
	}
	keeper := out.out.(adapter.IdleConnectionKeeper)
	keeper.SetKeepIdleConnections(false)
	keeper.CloseIdleConnections()
	for i, stream := range streams {
		if stream == nil {
			t.Fatal("stream missing")
		}
		sshTestEcho(t, stream, fmt.Sprint(i))
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		if err := stream.Close(); err != nil {
			t.Fatalf("repeated stream close: %v", err)
		}
	}
	sshTestReceive(t, session.done)
	keeper.SetKeepIdleConnections(true)
	active := s.open(t, out)
	sshTestEcho(t, active, "new session")
	session = sshTestReceive(t, s.sessions)
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	sshTestReceive(t, session.done)
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if conn, err := out.out.DialContext(t.Context(), "tcp", target); err == nil {
		conn.Close()
		t.Fatal("closed SSH outbound reconnected")
	}
}

func testSSHReconnectAfterDisconnect(t *testing.T, loopback bool) {
	config, host := sshTestConfig(t)
	s := newSSHTestServer(t, config, loopback)
	out := s.outbound(t, "password", map[string]any{"host_key": sshTestPin(host)})
	old := s.open(t, out)
	session := sshTestReceive(t, s.sessions)
	if err := session.conn.Close(); err != nil {
		t.Fatal(err)
	}
	sshTestReceive(t, session.done)
	if _, err := old.Read(make([]byte, 1)); err == nil {
		t.Fatal("read on disconnected SSH session succeeded")
	}
	sshTestEcho(t, s.open(t, out), "reconnected")
	if got := s.accepts.Load(); got != 2 {
		t.Fatalf("got %d SSH connections, want 2", got)
	}
}

func TestSSHStreamDeadlines(t *testing.T) {
	config, host := sshTestConfig(t)
	s := newSSHTestServer(t, config, false)
	out := s.outbound(t, "password", map[string]any{"host_key": sshTestPin(host)})
	stream := s.open(t, out)
	if err := stream.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("blocked read returned %v", err)
	}
	if err := stream.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := stream.Write([]byte("expired")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired write returned %d, %v", n, err)
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	sshTestEcho(t, stream, "same stream after read deadline")
}

func TestSSHProbeAfterStreamTimeout(t *testing.T) {
	for _, mode := range []string{"responsive", "silent", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			config, host := sshTestConfig(t)
			s := newSSHTestServer(t, config, false)
			out := s.outbound(t, "password", map[string]any{"host_key": sshTestPin(host)})
			existing := s.open(t, out)
			session := sshTestReceive(t, s.sessions)
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				conn, err := out.Dial(ctx, "tcp", "pending.test:80")
				if conn != nil {
					conn.Close()
				}
				result <- err
			}()
			delayed := sshTestReceive(t, s.pending)
			wantErr := context.DeadlineExceeded
			if mode == "canceled" {
				cancel()
				wantErr = context.Canceled
			}
			if err := sshTestReceive(t, result); !errors.Is(err, wantErr) {
				t.Fatalf("pending stream dial returned %v, want %v", err, wantErr)
			}
			if mode == "canceled" {
				_ = delayed.Reject(ssh.ConnectionFailed, "canceled")
				sshTestEcho(t, existing, "healthy after cancellation")
				select {
				case <-s.probes:
					t.Fatal("caller cancellation triggered a keepalive probe")
				case <-time.After(50 * time.Millisecond):
				}
				return
			}
			probe := sshTestReceive(t, s.probes)
			if mode == "responsive" {
				// An SSH peer can reject the request and still prove it is alive.
				if err := probe.Reply(false, nil); err != nil {
					t.Fatal(err)
				}
				_ = delayed.Reject(ssh.ConnectionFailed, "destination timed out")
				sshTestEcho(t, existing, "healthy after timeout")
				return
			}
			select {
			case <-session.done:
			case <-time.After(8 * time.Second):
				t.Fatal("unresponsive SSH session survived the keepalive deadline")
			}
			sshTestEcho(t, s.open(t, out), "new session after timeout")
		})
	}
}

func TestSSHCloseWrite(t *testing.T) {
	config, host := sshTestConfig(t)
	server := newSSHTestServer(t, config, false)
	out := server.outbound(t, "password", map[string]any{"host_key": sshTestPin(host)})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	// relayTCP dials the adapter directly and uses CloseWrite at inbound EOF.
	conn, err := out.out.DialContext(ctx, "tcp", M.ParseSocksaddr(server.target))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	const payload = "reply after request EOF"
	if _, err = io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || string(reply) != payload {
		t.Fatalf("reply after SSH half-close = %q, error = %v", reply, err)
	}
}
