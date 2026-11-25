package generation

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/internal/testnet"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

const mitmWireHost = "origin.test"

func TestMITMGenerationLoopback(t *testing.T) {
	upstream := mitmWireOrigin(t, mitmWireHost, "original")
	rewritten := mitmWireOrigin(t, "rewritten.test", "rewritten")
	mitmCA := mitmWireAuthority(t, "Interception test CA")
	store := mitmWireStore(t)
	if err := ca.Save(store, mitmCA); err != nil {
		t.Fatal(err)
	}
	roots := mitmWireRoots(t, mitmCA)
	originRoots := mitmWireRoots(t, upstream.authority)
	target := upstream.address
	redirectPort := rewritten.address.Port()

	t.Run("reload and hostname reroute", func(t *testing.T) {
		routes := make(chan RouteObservation, 32)
		engine := NewEngine(EngineOptions{ObserveRoute: func(observation RouteObservation) {
			if observation.Domain == "rewritten.test" {
				routes <- observation
			}
		}})
		t.Cleanup(engine.Close)
		profile := func(skipVerify bool, mark string) string {
			return fmt.Sprintf(`schema-version: 1
sniff: {enabled: true, protocols: [tls]}
mitm: {hostnames: ['%s:0'], client-source-address: ['127.0.0.0/8'], skip-server-cert-verify: %t}
dns:
  nameserver: ['127.0.0.1:9']
  use-hosts: true
  hosts: [{id: rewritten.test, addresses: [127.0.0.1]}]
outbounds: [{id: original, type: direct}, {id: rewritten, type: direct}]
rules:
  - {match: {domain: rewritten.test}, outbound: rewritten}
  - {match: {all: true}, outbound: original}
http-rewrites:
  - {id: switch-host, match: '^https://origin[.]test:[0-9]+/switch$', action: header, target: 'https://rewritten.test:%d/forward'}
map-local:
  - {id: generation-mark, match: '^https://origin[.]test:[0-9]+/generation$', data-type: text, data: %q}
`, mitmWireHost, skipVerify, redirectPort, mark)
		}
		listen := testnet.RetryAddr(t, func(listen netip.AddrPort) error {
			return mitmWireApply(t, engine, store, listen, profile(false, "old generation"), true, 1)
		})
		open := func() *mitmWireClient {
			t.Helper()
			client, err := mitmWireConnect(t, listen, target, roots)
			if err != nil {
				t.Fatal(err)
			}
			state := client.conn.ConnectionState()
			if state.NegotiatedProtocol != "http/1.1" || bytes.Equal(state.PeerCertificates[0].Raw, upstream.cert) {
				t.Fatalf("unexpected MITM TLS state: ALPN %q", state.NegotiatedProtocol)
			}
			return client
		}
		old := open()
		old.check(t, "/generation", http.StatusOK, "old generation")
		old.check(t, "/verify", http.StatusBadGateway, "")
		if err := mitmWireApply(t, engine, store, listen, profile(true, "new generation"), true, 2); err != nil {
			t.Fatal(err)
		}
		current := open()
		current.check(t, "/generation", http.StatusOK, "new generation")
		header := current.check(t, "/verify", http.StatusOK, "original")
		if got := header.Get("X-Upstream-SNI"); got != mitmWireHost {
			t.Fatalf("origin SNI = %q", got)
		}
		header = current.check(t, "/switch", http.StatusOK, "rewritten")
		if got := header.Get("X-Upstream-SNI"); got != "rewritten.test" {
			t.Fatalf("rewritten SNI = %q", got)
		}
		select {
		case route := <-routes:
			if route.Decision.Outbound != "rewritten" {
				t.Fatalf("new hostname routed to %q", route.Decision.Outbound)
			}
		default:
			t.Fatal("hostname change did not run routing")
		}
		old.check(t, "/generation", http.StatusOK, "old generation")
		old.check(t, "/verify", http.StatusBadGateway, "")
	})

	t.Run("h2", func(t *testing.T) {
		engine := NewEngine(EngineOptions{})
		t.Cleanup(engine.Close)
		profile := `schema-version: 1
sniff: {enabled: true, protocols: [tls]}
mitm: {hostnames: ['` + mitmWireHost + `:0'], h2: true, skip-server-cert-verify: true}
rules: [{match: {all: true}, outbound: direct}]
map-local:
  - {id: h2-mark, match: '^https://origin[.]test:[0-9]+/h2$', data-type: text, data: 'over h2'}
`
		listen := testnet.RetryAddr(t, func(listen netip.AddrPort) error {
			return mitmWireApply(t, engine, store, listen, profile, true, 1)
		})
		client, err := mitmWireConnect(t, listen, target, roots)
		if err != nil {
			t.Fatal(err)
		}
		if got := client.conn.ConnectionState().NegotiatedProtocol; got != "h2" {
			t.Fatalf("MITM ALPN = %q", got)
		}
		h2, err := (&http2.Transport{}).NewClientConn(client.conn)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/h2", "/verify"} {
			req, err := http.NewRequest(http.MethodGet, "https://"+client.host+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := h2.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			want := map[string]string{"/h2": "over h2", "/verify": "original"}[path]
			if res.StatusCode != http.StatusOK || res.ProtoMajor != 2 || string(body) != want {
				t.Fatalf("%s over h2 = %d %s %q", path, res.StatusCode, res.Proto, body)
			}
		}
		if status := engine.MITMStatus(); status.H2 != "enabled" {
			t.Fatalf("MITM h2 status = %q", status.H2)
		}
	})

	t.Run("pass through", func(t *testing.T) {
		engine := NewEngine(EngineOptions{})
		t.Cleanup(engine.Close)
		profile := func(host, source string) string {
			return fmt.Sprintf(`schema-version: 1
sniff: {enabled: true, protocols: [tls]}
mitm: {hostnames: [%q], client-source-address: %s, skip-server-cert-verify: true}
rules: [{match: {all: true}, outbound: direct}]
`, host+":0", source)
		}
		empty := mitmWireStore(t)
		listen := testnet.RetryAddr(t, func(listen netip.AddrPort) error {
			return mitmWireApply(t, engine, store, listen, profile(mitmWireHost, "[]"), false, 1)
		})
		for i, test := range []struct {
			name, host, source string
			enabled            bool
			store              secret.Store
		}{
			{name: "disabled", host: mitmWireHost, source: "[]", store: store},
			{name: "missing CA", host: mitmWireHost, source: "[]", enabled: true, store: empty},
			{name: "hostname mismatch", host: "different.test", source: "[]", enabled: true, store: store},
			{name: "source mismatch", host: mitmWireHost, source: "['192.0.2.0/24']", enabled: true, store: store},
			{name: "excluded source", host: mitmWireHost, source: "['127.0.0.0/8', '-127.0.0.1']", enabled: true, store: store},
		} {
			t.Run(test.name, func(t *testing.T) {
				if err := mitmWireApply(t, engine, test.store, listen, profile(test.host, test.source), test.enabled, uint64(i+2)); err != nil {
					t.Fatal(err)
				}
				client, err := mitmWireConnect(t, listen, target, originRoots)
				if err != nil {
					t.Fatal(err)
				}
				client.check(t, "/direct", http.StatusOK, "original")
				if got := client.conn.ConnectionState().PeerCertificates[0]; !bytes.Equal(got.Raw, upstream.cert) {
					t.Fatal("pass-through did not present the origin certificate")
				}
			})
		}
	})

	t.Run("certificate rejection bypass", func(t *testing.T) {
		start := time.Now()
		var elapsed atomic.Int64
		engine := NewEngine(EngineOptions{mitmNow: func() time.Time { return start.Add(time.Duration(elapsed.Load())) }})
		t.Cleanup(engine.Close)
		const profile = `schema-version: 1
sniff: {enabled: true, protocols: [tls]}
mitm: {hostnames: ['origin.test:0'], skip-server-cert-verify: true}
rules: [{match: {all: true}, outbound: direct}]
`
		listen := testnet.RetryAddr(t, func(listen netip.AddrPort) error {
			return mitmWireApply(t, engine, store, listen, profile, true, 1)
		})
		var unknownAuthority x509.UnknownAuthorityError
		if _, err := mitmWireConnect(t, listen, target, originRoots); !errors.As(err, &unknownAuthority) {
			t.Fatalf("client rejection = %v, want unknown CA", err)
		}
		mitmWireWaitBypass(t, engine)
		if err := mitmWireApply(t, engine, store, listen, profile, true, 2); err != nil {
			t.Fatal(err)
		}
		bypassed, err := mitmWireConnect(t, listen, target, originRoots)
		if err != nil {
			t.Fatal(err)
		}
		if got := bypassed.conn.ConnectionState().PeerCertificates[0]; !bytes.Equal(got.Raw, upstream.cert) {
			t.Fatal("bypass did not present the origin certificate")
		}
		bypassed.check(t, "/bypassed", http.StatusOK, "original")

		elapsed.Store(int64(10*time.Minute + time.Second))
		restored, err := mitmWireConnect(t, listen, target, roots)
		if err != nil {
			t.Fatal(err)
		}
		if got := restored.conn.ConnectionState().PeerCertificates[0]; bytes.Equal(got.Raw, upstream.cert) {
			t.Fatal("interception did not resume after bypass expired")
		}
		restored.check(t, "/restored", http.StatusOK, "original")
	})
}

func mitmWireApply(t *testing.T, engine *Engine, store secret.Store, listen netip.AddrPort, profile string, enabled bool, revision uint64) error {
	t.Helper()
	local := fmt.Appendf(nil, "listeners: [{id: mixed, type: mixed, listen: %q}]\nmitm: {enabled: %t, ca: secret://mitm/ca}\n", listen, enabled)
	eff, ds := compile.Compile([]byte(profile), local, compile.Options{Secrets: store})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	prepared, err := engine.Prepare(eff)
	if err != nil {
		return err
	}
	_, err = engine.Activate(prepared, revision)
	return err
}

type mitmWireUpstream struct {
	address   netip.AddrPort
	cert      []byte
	authority *ca.Authority
}

func mitmWireOrigin(t *testing.T, host, name string) mitmWireUpstream {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	root := mitmWireAuthority(t, name+" test CA")
	issuer := ca.NewIssuer(root, ca.IssuerOptions{})
	t.Cleanup(issuer.Close)
	cert, err := issuer.Certificate(host)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-SNI", r.TLS.ServerName)
		_, _ = io.WriteString(w, name)
	})}
	t.Cleanup(func() { _ = server.Close() })
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}}
	go func() { _ = server.Serve(tls.NewListener(listener, tlsConfig)) }()
	return mitmWireUpstream{address: listener.Addr().(*net.TCPAddr).AddrPort(), cert: cert.Certificate[0], authority: root}
}

func mitmWireAuthority(t *testing.T, name string) *ca.Authority {
	t.Helper()
	authority, err := ca.Generate(ca.GenerateOptions{CommonName: name})
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func mitmWireStore(t *testing.T) *secret.FileStore {
	t.Helper()
	store, err := secret.NewFileStore(filepath.Join(t.TempDir(), "secrets.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func mitmWireRoots(t *testing.T, authority *ca.Authority) *x509.CertPool {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.CertificatePEM()) {
		t.Fatal("could not load test root")
	}
	return roots
}

type mitmWireClient struct {
	conn   *tls.Conn
	reader *bufio.Reader
	host   string
}

func mitmWireConnect(t *testing.T, listen, target netip.AddrPort, roots *x509.CertPool) (*mitmWireClient, error) {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", listen.String(), nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dialer.(proxy.ContextDialer).DialContext(t.Context(), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := tls.Client(raw, &tls.Config{ServerName: mitmWireHost, RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}})
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return &mitmWireClient{conn: conn, reader: bufio.NewReader(conn), host: net.JoinHostPort(mitmWireHost, fmt.Sprint(target.Port()))}, nil
}

func (client *mitmWireClient) check(t *testing.T, path string, status int, want string) http.Header {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+client.host+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(client.conn); err != nil {
		t.Fatal(err)
	}
	reply, err := http.ReadResponse(client.reader, req)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Body.Close()
	body, err := io.ReadAll(reply.Body)
	if err != nil || reply.StatusCode != status || status != http.StatusBadGateway && string(body) != want {
		t.Fatalf("%s: response code %d, body %q, error %v", path, reply.StatusCode, body, err)
	}
	return reply.Header
}

func mitmWireWaitBypass(t *testing.T, engine *Engine) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		bypasses := engine.MITMStatus().PinningBypasses
		if len(bypasses) == 1 {
			if got := bypasses[0]; got.Hostname != mitmWireHost || got.Reason == "" ||
				!got.ExpiresAt.Equal(engine.opts.mitmNow().Add(10*time.Minute)) {
				t.Fatalf("unexpected certificate bypass: %+v", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("certificate bypasses = %v", bypasses)
		}
		time.Sleep(time.Millisecond)
	}
}
