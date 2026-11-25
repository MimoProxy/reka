package sagernet

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const (
	// Match the HTTP transport defaults in mihomo's component/http.
	mitmHTTPIdleTimeout       = 30 * time.Second
	mitmTLSHandshakeTimeout   = 10 * time.Second
	mitmExpectContinueTimeout = time.Second
	// An HTTP/2 client multiplexes requests that the HTTP/1.1 upstream
	// spreads over connections. sing-box and mihomo have no MITM equivalent;
	// keep as many idle as browsers open per host. Busy connections are not
	// capped, so a long-lived request never blocks others.
	mitmHTTP1Upstreams = 6
	// One HTTP/2 connection carries all gRPC streams, as in sing-box's
	// common/networkquality HTTP transport for sequential requests.
	mitmH2IdleUpstreams = 1
)

// mitmUpstream owns its transports' sockets until the client connection
// ends. A rewritten authority gets a separate upstream that lives for that
// request.
//
// Requests go to the origin over HTTP/1.1, even when the client speaks
// HTTP/2: some CDNs reject an app's requests when net/http's HTTP/2 client
// relays them, since its frames differ from the app's own. Requests that
// need HTTP/2, such as gRPC, use h2Transport when HTTP/2 is enabled.
type mitmUpstream struct {
	transport   *http.Transport
	h2Transport *http.Transport
	route       Route
	cancel      context.CancelFunc

	mu     sync.Mutex
	closed bool
	dials  sync.WaitGroup
	conns  map[*mitmUpstreamConn]struct{}
}

func newMITMUpstream(ctx context.Context, route Route, metadata adapter.InboundContext, host string, skipVerify, h2 bool, attempt *connectionAttempt) *mitmUpstream {
	owner, cancel := context.WithCancel(ctx)
	upstream := &mitmUpstream{route: route, cancel: cancel}
	upstream.transport = upstream.newTransport(owner, metadata, host, skipVerify, false, attempt)
	if h2 {
		upstream.h2Transport = upstream.newTransport(owner, metadata, host, skipVerify, true, attempt)
	}
	return upstream
}

func (u *mitmUpstream) newTransport(owner context.Context, metadata adapter.InboundContext, host string, skipVerify, h2 bool, attempt *connectionAttempt) *http.Transport {
	nextProtos := mitmTLSNextProtos(h2)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return u.dial(ctx, owner, metadata, attempt)
	}
	transport := &http.Transport{
		Protocols: mitmHTTPProtocols(h2),
		TLSClientConfig: &tls.Config{
			ServerName: host, InsecureSkipVerify: skipVerify, MinVersion: tls.VersionTLS12, NextProtos: nextProtos,
		},
		TLSHandshakeTimeout:    mitmTLSHandshakeTimeout,
		ExpectContinueTimeout:  mitmExpectContinueTimeout,
		IdleConnTimeout:        mitmHTTPIdleTimeout,
		MaxIdleConns:           mitmHTTP1Upstreams,
		MaxIdleConnsPerHost:    mitmHTTP1Upstreams,
		MaxResponseHeaderBytes: relayHTTPMaxHeaderBytes,
		DisableCompression:     true,
		DialContext:            dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			// net/http leaves the handshake timeout to a custom TLS dialer.
			handshakeCtx, cancelHandshake := context.WithTimeout(ctx, mitmTLSHandshakeTimeout)
			defer cancelHandshake()
			started := time.Now()
			tlsConn, err := mitmUpstreamTLSHandshake(handshakeCtx, conn, host, skipVerify, nextProtos)
			observeMITMUpstreamTLS(ctx, time.Since(started))
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
				return &mitmH2ClientConn{mitmTLSConn: tlsConn}, nil
			}
			return tlsConn, nil
		},
	}
	if h2 {
		transport.MaxIdleConns = mitmH2IdleUpstreams
		transport.MaxIdleConnsPerHost = mitmH2IdleUpstreams
		transport.HTTP2 = mitmHTTP2Config()
	}
	return transport
}

// roundTripper picks the transport for request: HTTP/2 for gRPC and for
// requests with trailers, which HTTP/1.1 origins rarely accept.
func (u *mitmUpstream) roundTripper(request *http.Request) *http.Transport {
	if u.h2Transport != nil && mitmRequestNeedsH2(request) {
		return u.h2Transport
	}
	return u.transport
}

func mitmRequestNeedsH2(request *http.Request) bool {
	contentType := strings.ToLower(request.Header.Get("Content-Type"))
	return strings.HasPrefix(contentType, "application/grpc") && !strings.HasPrefix(contentType, "application/grpc-web") ||
		len(request.Trailer) != 0
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
	if u.h2Transport != nil {
		u.h2Transport.CloseIdleConnections()
	}
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
