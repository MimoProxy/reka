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

// MITMRoute contains the HTTPS settings pinned by Route.Release, with an
// independent routing callback for requests rewritten to another origin.
type MITMRoute struct {
	Host                 string
	Issuer               *ca.Issuer
	Rewrite              *httprewrite.Set
	MaxBodySize          int
	SkipServerCertVerify bool
	Reroute              func(context.Context, Destination) Route
	OnPinFailure         func(host, reason string)
	OnConnection         func()
	OnRequest            func()
	MatchScript          func(kind script.Kind, rawURL string) *MITMScript
	OnScript             func(run api.MITMScriptRun, executed bool)
}

func (b *Backend) relayMITM(ctx context.Context, rt Route, conn net.Conn, metadata adapter.InboundContext, originalDestination string, onClose N.CloseHandlerFunc, attempt *connectionAttempt) {
	ctx, cancel := context.WithCancel(ctx)
	var closeOnce sync.Once
	closeRaw := func() { closeOnce.Do(func() { _ = conn.Close() }) }
	stopContext := context.AfterFunc(ctx, closeRaw)
	stopBackend := context.AfterFunc(b.ctx, cancel)

	mitm := rt.MITM
	attempt.mu.Lock()
	attempt.MITM = true
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

	// SOCKS may be waiting for its success reply before sending ClientHello.
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
	// Sniffing wraps the original socket in sniffReplayConn, so the consumed
	// ClientHello bytes remain readable here. HTTP/2 support is deferred.
	clientTLS := tls.Server(clientWire, &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true,
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
	if err = clientTLS.HandshakeContext(ctx); err != nil {
		if ctx.Err() == nil && mitm.OnPinFailure != nil {
			if reason := mitmPinFailure(err, clientWire.certSent); reason != "" {
				mitm.OnPinFailure(host, reason)
			}
		}
		return
	}
	_ = conn.SetDeadline(time.Time{})
	clientWire.certSelected = false
	stage = "relay"

	attempt.mu.Lock()
	ready := time.Now().UTC()
	attempt.ReadyAt = &ready
	attempt.mu.Unlock()

	upstream := newMITMUpstream(ctx, rt, metadata, host, mitm.SkipServerCertVerify, attempt)
	defer upstream.close()
	handler := &mitmHTTPHandler{
		backend: b, route: mitm, attempt: attempt, metadata: metadata,
		upstream: upstream, host: host, closeWire: closeRaw,
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	server := &http.Server{
		Handler: handler, Protocols: protocols, MaxHeaderBytes: relayHTTPMaxHeaderBytes,
		ReadHeaderTimeout: C.TCPTimeout, IdleTimeout: mitmHTTPIdleTimeout,
		DisableGeneralOptionsHandler: true,
		BaseContext:                  func(net.Listener) context.Context { return ctx },
	}
	_ = server.Serve(newSingleConnListener(clientTLS))
	if ctx.Err() != nil {
		err = ctx.Err()
	}
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
