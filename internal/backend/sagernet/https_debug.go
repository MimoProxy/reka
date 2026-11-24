package sagernet

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	debugLifetime = time.Hour
	debugTimeout  = 30 * time.Second
	debugInbound  = "https-debug"
	debugUsername = "reka"
)

type httpsDebug struct {
	backend       *Backend
	status        api.HTTPSDebugStatus
	ctx           context.Context
	cancel        context.CancelFunc
	closeOnce     sync.Once
	server        *http.Server
	listener      net.Listener
	certificates  map[debugAuthority]tls.Certificate
	upstreamRoots *x509.CertPool
	profileID     string
	auth          string
	allowHTTP     bool
	previewSlots  chan struct{}
	slots         chan struct{}

	mu      sync.Mutex
	tunnels map[*singleConnListener]struct{}
}

func (b *Backend) StartHTTPSDebug(request api.HTTPSDebugRequest) (api.HTTPSDebugStatus, error) {
	return b.startHTTPSDebug(request, nil)
}

func (b *Backend) startHTTPSDebug(request api.HTTPSDebugRequest, roots *x509.CertPool) (api.HTTPSDebugStatus, error) {
	b.debugMu.Lock()
	defer b.debugMu.Unlock()
	if b.httpsDebug != nil && b.httpsDebug.ctx.Err() == nil {
		return api.HTTPSDebugStatus{}, errors.New("stop the existing HTTPS debug session first")
	}
	if b.ctx.Err() != nil {
		return api.HTTPSDebugStatus{}, b.ctx.Err()
	}
	expires := time.Now().Add(debugLifetime)
	publicCA, certificates, err := newDebugCertificates(request.Targets, expires)
	if err != nil {
		return api.HTTPSDebugStatus{}, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return api.HTTPSDebugStatus{}, err
	}
	targets := make([]string, 0, len(certificates))
	for target := range certificates {
		targets = append(targets, target.String())
	}
	sort.Strings(targets)
	var passwordBytes [24]byte
	rand.Read(passwordBytes[:])
	password := hex.EncodeToString(passwordBytes[:])
	ctx, cancel := context.WithDeadline(b.ctx, expires)
	maxClients := request.MaxClients
	if maxClients <= 0 || maxClients > 16 {
		maxClients = 16
	}
	debug := &httpsDebug{
		backend: b, certificates: certificates, ctx: ctx, cancel: cancel, upstreamRoots: roots, listener: listener,
		auth: base64.StdEncoding.EncodeToString([]byte(debugUsername + ":" + password)), allowHTTP: request.AllowHTTP,
		tunnels: make(map[*singleConnListener]struct{}), previewSlots: make(chan struct{}, 16),
		slots: make(chan struct{}, maxClients),
		status: api.HTTPSDebugStatus{
			Running: true, Address: listener.Addr().String(), Targets: targets,
			Username: debugUsername, Password: password, Certificate: publicCA,
			ExpiresAt: &expires, CaptureBody: request.CaptureBody,
		},
	}
	if b.historyScope != nil {
		debug.profileID = b.historyScope().ProfileID
	}
	debug.server = &http.Server{
		Handler: http.HandlerFunc(debug.connect), ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes: 16 << 10, IdleTimeout: 5 * time.Second, WriteTimeout: debugTimeout,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	b.httpsDebug = debug
	context.AfterFunc(ctx, func() {
		debug.close()
		b.debugMu.Lock()
		if b.httpsDebug == debug {
			b.httpsDebug = nil
		}
		b.debugMu.Unlock()
	})
	go func() {
		_ = debug.server.Serve(&debugListener{Listener: listener, slots: debug.slots})
		debug.close()
	}()
	return debug.status, nil
}

func (b *Backend) HTTPSDebugStatus() api.HTTPSDebugStatus {
	b.debugMu.Lock()
	defer b.debugMu.Unlock()
	if b.httpsDebug != nil && b.httpsDebug.ctx.Err() == nil {
		return b.httpsDebug.status
	}
	return api.HTTPSDebugStatus{}
}

func (b *Backend) StopHTTPSDebug() {
	b.debugMu.Lock()
	debug := b.httpsDebug
	b.httpsDebug = nil
	b.debugMu.Unlock()
	if debug != nil {
		debug.close()
	}
}

func (s *httpsDebug) close() {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.listener.Close()
		_ = s.server.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		for tunnel := range s.tunnels {
			_ = tunnel.Close()
		}
	})
}

func (s *httpsDebug) connect(w http.ResponseWriter, r *http.Request) {
	kind, auth, _ := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !strings.EqualFold(kind, "Basic") || subtle.ConstantTimeCompare([]byte(auth), []byte(s.auth)) != 1 {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Reka HTTPS Debug"`)
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	if r.Method != http.MethodConnect || r.URL.Path != "" {
		if s.allowHTTP && r.Method != http.MethodConnect && r.URL.Scheme == "http" &&
			r.URL.User == nil && r.URL.Host != "" {
			authority := r.URL.Host
			if r.URL.Port() == "" {
				authority = net.JoinHostPort(r.URL.Hostname(), "80")
			}
			target, err := parseDebugAuthority(authority)
			if _, allowed := s.certificates[target]; err == nil && allowed {
				s.forward(w, r, target, s.listener.Addr().String(), "http")
			} else {
				http.Error(w, "Target is outside the debug session", http.StatusForbidden)
			}
			return
		}
		http.Error(w, "Use CONNECT to an authorized HTTPS target", http.StatusMethodNotAllowed)
		return
	}
	authority, err := parseDebugAuthority(r.URL.Host)
	certificate, allowed := s.certificates[authority]
	if err != nil || !allowed {
		http.Error(w, "Target is outside the HTTPS debug session", http.StatusForbidden)
		return
	}
	hijack, supported := w.(http.Hijacker)
	if !supported {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	conn, buffered, err := hijack.Hijack()
	if err != nil {
		s.mu.Unlock()
		return
	}
	tunnel := newSingleConnListener(&bufferedHTTPConn{Conn: conn, reader: buffered.Reader})
	s.tunnels[tunnel] = struct{}{}
	s.mu.Unlock()
	defer func() {
		_ = tunnel.Close()
		s.mu.Lock()
		delete(s.tunnels, tunnel)
		s.mu.Unlock()
	}()

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	server := &http.Server{
		BaseContext: func(net.Listener) context.Context { return s.ctx },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.forward(w, r, authority, conn.LocalAddr().String(), "https")
		}),
		ReadHeaderTimeout: 5 * time.Second, WriteTimeout: debugTimeout, IdleTimeout: 20 * time.Second,
		MaxHeaderBytes: 32 << 10, HTTP2: &http.HTTP2Config{MaxConcurrentStreams: cap(s.slots)},
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				if !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), authority.host) {
					return nil, errors.New("TLS server name does not match the authorized target")
				}
				return nil, nil
			},
		},
	}
	_ = server.ServeTLS(tunnel, "", "")
	_ = server.Close()
}

func (s *httpsDebug) forward(w http.ResponseWriter, r *http.Request, target debugAuthority, local, scheme string) {
	if scheme == "https" {
		host, err := parseDebugAuthority(r.Host)
		if err != nil || host != target || r.URL.IsAbs() {
			http.Error(w, "Request authority does not match the debug tunnel", http.StatusMisdirectedRequest)
			return
		}
	}
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), debugTimeout)
	defer cancel()
	if s.ctx.Err() != nil || s.backend.historyScope != nil && s.backend.historyScope().ProfileID != s.profileID {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	request := r.Clone(ctx)
	request.URL.Scheme = scheme
	request.URL.Host = target.String()
	if scheme == "http" {
		request.Host = target.String()
	}
	request.RequestURI = ""
	stripHTTPHopHeaders(request.Header)
	ctx, observation := s.backend.beginRequest(ctx, request, debugInbound, r.RemoteAddr)
	var bodyLimit int
	if s.status.CaptureBody {
		select {
		case s.previewSlots <- struct{}{}:
			defer func() { <-s.previewSlots }()
			bodyLimit = 8 << 10
		default:
		}
	}
	observation.enableDetail(request.Header, bodyLimit, s.status.CaptureBody && bodyLimit == 0)

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: s.upstreamRoots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true, DisableKeepAlives: true, DisableCompression: true, TLSHandshakeTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: relayHTTPMaxHeaderBytes,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != target.String() || s.ctx.Err() != nil {
				return nil, errors.New("invalid HTTPS debug upstream")
			}
			return s.dial(ctx, target, r.RemoteAddr, local)
		},
	}
	defer transport.CloseIdleConnections()
	res, err := transport.RoundTrip(request.WithContext(ctx))
	if err != nil {
		if s.ctx.Err() == nil {
			observation.finish(http.StatusBadGateway, err)
		}
		http.Error(w, "Debug upstream request failed", http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	observation.response(res)
	stripHTTPHopHeaders(res.Header)
	for key, values := range res.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(res.StatusCode)
	_, err = io.Copy(w, res.Body)
	if s.ctx.Err() == nil {
		observation.finish(0, err)
	}
}

func (s *httpsDebug) dial(ctx context.Context, target debugAuthority, source, local string) (net.Conn, error) {
	client, relay := net.Pipe()
	bridge := &debugBridge{Conn: relay, local: M.ParseSocksaddr(local), ready: make(chan error, 1)}
	metadata := adapter.InboundContext{
		Inbound: debugInbound, InboundType: "http",
		Source: M.ParseSocksaddr(source), Destination: M.ParseSocksaddr(target.String()),
		OriginDestination: bridge.local, Domain: target.host, Protocol: "tls",
	}
	go s.backend.router.RouteConnectionEx(ctx, bridge, metadata, func(err error) {
		if err == nil {
			err = io.EOF
		}
		bridge.signal(err)
		_ = bridge.Close()
	})
	var err error
	select {
	case err = <-bridge.ready:
	case <-ctx.Done():
		err = ctx.Err()
	case <-s.ctx.Done():
		err = s.ctx.Err()
	}
	if err != nil {
		_ = client.Close()
		_ = bridge.Close()
		return nil, err
	}
	return client, nil
}

type debugBridge struct {
	net.Conn
	local M.Socksaddr
	ready chan error
	once  sync.Once
}

func (b *debugBridge) LocalAddr() net.Addr { return b.local }
func (b *debugBridge) signal(err error)    { b.once.Do(func() { b.ready <- err }) }
func (b *debugBridge) HandshakeSuccess() error {
	b.signal(nil)
	return nil
}

type debugListener struct {
	net.Listener
	slots chan struct{}
}

func (l *debugListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &debugClientConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}

type debugClientConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *debugClientConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

type bufferedHTTPConn struct {
	net.Conn
	reader *bufio.Reader
}

func (t *bufferedHTTPConn) Read(p []byte) (int, error) { return t.reader.Read(p) }
