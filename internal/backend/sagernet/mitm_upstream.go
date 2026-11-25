package sagernet

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const (
	// Match the HTTP transport defaults in mihomo's component/http.
	mitmHTTPIdleTimeout       = 30 * time.Second
	mitmTLSHandshakeTimeout   = 10 * time.Second
	mitmExpectContinueTimeout = time.Second
	// sing-box's common/networkquality HTTP transport keeps one idle
	// connection per host for sequential requests.
	mitmIdleUpstreams = 1
)

// mitmUpstream owns a transport's sockets until the client connection ends.
// A rewritten authority gets a separate transport that lives for that request.
type mitmUpstream struct {
	transport *http.Transport
	route     Route
	cancel    context.CancelFunc

	mu     sync.Mutex
	closed bool
	dials  sync.WaitGroup
	conns  map[*mitmUpstreamConn]struct{}
}

func newMITMUpstream(ctx context.Context, route Route, metadata adapter.InboundContext, host string, skipVerify, h2 bool, attempt *connectionAttempt) *mitmUpstream {
	owner, cancel := context.WithCancel(ctx)
	upstream := &mitmUpstream{route: route, cancel: cancel}
	tlsConfig := &tls.Config{
		ServerName: host, InsecureSkipVerify: skipVerify, MinVersion: tls.VersionTLS12, NextProtos: mitmTLSNextProtos(h2),
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return upstream.dial(ctx, owner, metadata, attempt)
	}
	upstream.transport = &http.Transport{
		Protocols:              mitmHTTPProtocols(h2),
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    mitmTLSHandshakeTimeout,
		ExpectContinueTimeout:  mitmExpectContinueTimeout,
		IdleConnTimeout:        mitmHTTPIdleTimeout,
		MaxIdleConns:           mitmIdleUpstreams,
		MaxIdleConnsPerHost:    mitmIdleUpstreams,
		MaxResponseHeaderBytes: relayHTTPMaxHeaderBytes,
		DisableCompression:     true,
		DialContext:            dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, tlsConfig.Clone())
			// net/http leaves the handshake timeout to a custom TLS dialer.
			handshakeCtx, cancelHandshake := context.WithTimeout(ctx, mitmTLSHandshakeTimeout)
			defer cancelHandshake()
			started := time.Now()
			err = tlsConn.HandshakeContext(handshakeCtx)
			observeMITMUpstreamTLS(ctx, time.Since(started))
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
				return &mitmH2ClientConn{Conn: tlsConn}, nil
			}
			return tlsConn, nil
		},
	}
	if h2 {
		upstream.transport.HTTP2 = mitmHTTP2Config()
	}
	return upstream
}

func (u *mitmUpstream) dial(ctx, owner context.Context, metadata adapter.InboundContext, attempt *connectionAttempt) (net.Conn, error) {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil, net.ErrClosed
	}
	u.dials.Add(1)
	u.mu.Unlock()
	defer u.dials.Done()

	// net/http can detach a speculative dial from RoundTrip's
	// cancellation. Tie it to the client or rerouted request too.
	ctx, cancelDial := context.WithCancel(ctx)
	stopCancel := context.AfterFunc(owner, cancelDial)
	releaseDialContext := func() {
		stopCancel()
		cancelDial()
	}
	remote, err := dialTCP(tcpRouteContext(ctx, u.route, metadata), u.route.Outbound, metadata.Destination, attempt)
	if err != nil {
		releaseDialContext()
		return nil, err
	}
	conn := &mitmUpstreamConn{Conn: remote, owner: u, releaseDialContext: releaseDialContext}
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	if u.conns == nil {
		u.conns = make(map[*mitmUpstreamConn]struct{})
	}
	u.conns[conn] = struct{}{}
	u.mu.Unlock()
	return conn, nil
}

func (u *mitmUpstream) close() {
	u.mu.Lock()
	u.closed = true
	conns := make([]*mitmUpstreamConn, 0, len(u.conns))
	for conn := range u.conns {
		conns = append(conns, conn)
	}
	u.mu.Unlock()

	u.cancel()
	// Close tracked sockets even if HTTP/2 streams are still active.
	for _, conn := range conns {
		_ = conn.Close()
	}
	u.transport.CloseIdleConnections()
	u.dials.Wait()
}

type mitmUpstreamConn struct {
	net.Conn
	owner              *mitmUpstream
	releaseDialContext func()
	once               sync.Once
	err                error
}

func (c *mitmUpstreamConn) Close() error {
	c.once.Do(func() {
		c.releaseDialContext()
		c.err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
	})
	return c.err
}
