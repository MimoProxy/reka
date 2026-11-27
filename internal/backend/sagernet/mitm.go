package sagernet

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/script"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// MITMScriptRequest is the request a MITM script ran for.
type MITMScriptRequest struct {
	Method, URL  string
	RequestID    uint64
	ConnectionID uint64
	Started      time.Time
	// Capture is what the script saw and returned, when CaptureScripts asked for it.
	Capture *api.ScriptCapture
}

// MITMRoute contains the HTTP processing settings pinned by Route.Release, with an
// independent routing callback for requests rewritten to another origin.
type MITMRoute struct {
	PlainHTTP            bool
	Host                 string
	Issuer               *ca.Issuer
	Rewrite              *httprewrite.Set
	MaxBodySize          int
	H2                   bool
	SkipServerCertVerify bool
	// Reroute routes a request whose rewritten URL or script names another
	// origin. The request is nil unless RouteRequest is set.
	Reroute func(context.Context, Destination, *HTTPRequestInfo) Route
	// RouteRequest routes each request by its URL and headers when the
	// connection's route depended on them. changed is false when the
	// request keeps the connection's route, and route is then empty.
	RouteRequest func(context.Context, HTTPRequestInfo) (route Route, changed bool)
	OnPinFailure func(host, reason string)
	OnConnection func()
	OnRequest    func()
	MatchScript  func(kind script.Kind, rawURL string) *MITMScript
	OnScript     func(run api.MITMScriptRun, executed bool, request MITMScriptRequest)
	// CaptureScripts reports whether OnScript should receive each script's
	// input and output. Copying bodies costs memory, so it is off unless asked.
	CaptureScripts func() bool
}

func (b *Backend) relayHTTPEngine(ctx context.Context, rt Route, conn net.Conn, metadata adapter.InboundContext, originalDestination string, onClose N.CloseHandlerFunc, attempt *connectionAttempt) {
	ctx, cancel := context.WithCancel(ctx)
	var closeOnce sync.Once
	closeRaw := func() { closeOnce.Do(func() { _ = conn.Close() }) }
	stopContext := context.AfterFunc(ctx, closeRaw)
	stopBackend := context.AfterFunc(b.ctx, cancel)

	mitm := rt.MITM
	attempt.mu.Lock()
	attempt.MITM = true
	attempt.MITMPlainHTTP = mitm.PlainHTTP
	attempt.mu.Unlock()
	if mitm.OnConnection != nil {
		mitm.OnConnection()
	}

	var manual atomic.Bool
	processTraffic, finishProcess := b.beginProcessTraffic(rt.Owner)
	untrack := b.conns.add(&tracked{
		attempt: attempt, id: attempt.ID, start: time.Now(), md: toMetadata(metadata), out: rt.Outbound,
		originalDestination: originalDestination, info: rt.Info,
		close: func() {
			manual.Store(true)
			cancel()
			closeRaw()
		},
	})
	var err error
	stage := "handshake"
	defer func() {
		stopBackend()
		stopContext()
		closeRaw()
		cancel()
		reason := connectionReason(err, "eof")
		if manual.Load() {
			reason, stage = "manual", ""
		} else if err == nil {
			stage = ""
		}
		attempt.complete(reason, stage)
		untrack()
		finishProcess()
		rt.Release()
		if onClose != nil {
			onClose(err)
		}
	}()

	// SOCKS may be waiting for its success reply before sending application data.
	_ = conn.SetDeadline(time.Now().Add(mitmTLSHandshakeTimeout))
	if err = N.ReportConnHandshakeSuccess(conn, conn); err != nil {
		return
	}
	clientWire := &mitmClientConn{
		Conn: conn, attempt: attempt,
		upload: &b.trafficUpload, download: &b.trafficDownload,
		processUpload: &processTraffic.upload, processDownload: &processTraffic.download,
	}
	host := mitm.Host
	listener := newSingleConnListener(clientWire)
	var clientProtocol string
	if !mitm.PlainHTTP {
		host, clientProtocol, err = handshakeMITM(ctx, listener, clientWire, mitm)
		if err != nil {
			return
		}
	}
	_ = conn.SetDeadline(time.Time{})
	stage = "relay"

	attempt.mu.Lock()
	ready := time.Now().UTC()
	attempt.ReadyAt = &ready
	attempt.MITMClientProtocol = clientProtocol
	attempt.mu.Unlock()

	h2 := mitm.H2 && !mitm.PlainHTTP
	upstream := newMITMUpstream(ctx, rt, metadata, host, mitm.SkipServerCertVerify, h2, attempt)
	handler := &mitmHTTPHandler{
		backend: b, route: mitm, attempt: attempt, metadata: metadata,
		upstream: upstream, host: host, closeWire: closeRaw,
	}
	defer func() {
		cancel()
		upstream.close()
		// The HTTP/2 connection may close while its handlers still unwind.
		// Finish request diagnostics before releasing the pinned route.
		handler.waitForRequests()
	}()
	server := &http.Server{
		Handler: handler, Protocols: mitmHTTPProtocols(h2), MaxHeaderBytes: relayHTTPMaxHeaderBytes,
		ReadHeaderTimeout: C.TCPTimeout, IdleTimeout: mitmHTTPIdleTimeout,
		DisableGeneralOptionsHandler: true,
		BaseContext:                  func(net.Listener) context.Context { return ctx },
	}
	if h2 {
		server.HTTP2 = mitmHTTP2Config()
	}
	_ = server.Serve(listener)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
}

func handshakeMITM(ctx context.Context, listener *singleConnListener, clientWire *mitmClientConn, mitm *MITMRoute) (string, string, error) {
	host := mitm.Host
	clientTLS := tls.Server(listener.conn, &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: mitmTLSNextProtos(mitm.H2), SessionTicketsDisabled: true,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				hello.ServerName = host
			}
			cert, err := mitm.Issuer.GetCertificate(hello)
			if err == nil {
				host = strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
				clientWire.certSelected = true
			}
			return cert, err
		},
	})
	// Keep the close notification below TLS so Serve sees the negotiated ALPN
	// on the concrete *tls.Conn and can dispatch it to its HTTP/2 server.
	listener.conn = clientTLS
	if err := clientTLS.HandshakeContext(ctx); err != nil {
		if ctx.Err() == nil && mitm.OnPinFailure != nil {
			if reason := mitmPinFailure(err, clientWire.certSent); reason != "" {
				mitm.OnPinFailure(host, reason)
			}
		}
		return "", "", err
	}
	clientWire.certSelected = false
	return host, clientTLS.ConnectionState().NegotiatedProtocol, nil
}

type mitmClientConn struct {
	net.Conn
	attempt                        *connectionAttempt
	upload, download               *atomic.Uint64
	processUpload, processDownload *atomic.Uint64
	certSelected, certSent         bool
}

func (c *mitmClientConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.attempt.up.Add(int64(n))
		c.upload.Add(uint64(n))
		c.processUpload.Add(uint64(n))
	}
	return n, err
}

func (c *mitmClientConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.attempt.down.Add(int64(n))
		c.download.Add(uint64(n))
		c.processDownload.Add(uint64(n))
	}
	// Go TLS buffers the server's certificate flight before writing it.
	if c.certSelected && n == len(p) && err == nil {
		c.certSent = true
	}
	return n, err
}

func mitmPinFailure(err error, certSent bool) string {
	var remote *net.OpError
	if errors.As(err, &remote) && remote.Op == "remote error" && remote.Err != nil {
		// The Go TLS TCP implementation wraps its private alert type in
		// net.OpError. Match certificate alerts from that remote error only.
		switch remote.Err.Error() {
		case "tls: bad certificate":
			return "bad_certificate"
		case "tls: unsupported certificate":
			return "unsupported_certificate"
		case "tls: revoked certificate":
			return "certificate_revoked"
		case "tls: expired certificate":
			return "certificate_expired"
		case "tls: unknown certificate":
			return "certificate_unknown"
		case "tls: unknown certificate authority":
			return "unknown_ca"
		}
	}
	if certSent {
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			return "eof_after_certificate"
		case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
			return "reset_after_certificate"
		}
	}
	return ""
}
