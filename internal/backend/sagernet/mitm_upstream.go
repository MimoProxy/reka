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

func newMITMUpstream(ctx context.Context, route Route, metadata adapter.InboundContext, host string, skipVerify bool, attempt *connectionAttempt) *mitmUpstream {
	owner, cancel := context.WithCancel(ctx)
	upstream := &mitmUpstream{route: route, cancel: cancel}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	upstream.transport = &http.Transport{
		Protocols: protocols,
		TLSClientConfig: &tls.Config{
			ServerName: host, InsecureSkipVerify: skipVerify, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		},
		TLSHandshakeTimeout:    mitmTLSHandshakeTimeout,
		ExpectContinueTimeout:  mitmExpectContinueTimeout,
		IdleConnTimeout:        mitmHTTPIdleTimeout,
		MaxIdleConns:           mitmIdleUpstreams,
		MaxIdleConnsPerHost:    mitmIdleUpstreams,
		MaxResponseHeaderBytes: relayHTTPMaxHeaderBytes,
		DisableCompression:     true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			upstream.mu.Lock()
			if upstream.closed {
				upstream.mu.Unlock()
				return nil, net.ErrClosed
			}
			upstream.dials.Add(1)
			upstream.mu.Unlock()
			defer upstream.dials.Done()

			// net/http can detach a speculative dial from RoundTrip's
			// cancellation. Tie it to the client or rerouted request too.
			ctx, cancelDial := context.WithCancel(ctx)
			stopCancel := context.AfterFunc(owner, cancelDial)
			releaseDialContext := func() {
				stopCancel()
				cancelDial()
			}
			remote, err := dialTCP(tcpRouteContext(ctx, route, metadata), route.Outbound, metadata.Destination, attempt)
			if err != nil {
				releaseDialContext()
				return nil, err
			}
			conn := &mitmUpstreamConn{Conn: remote, owner: upstream, releaseDialContext: releaseDialContext}
			upstream.mu.Lock()
			if upstream.closed {
				upstream.mu.Unlock()
				_ = conn.Close()
				return nil, net.ErrClosed
			}
			if upstream.conns == nil {
				upstream.conns = make(map[*mitmUpstreamConn]struct{})
			}
			upstream.conns[conn] = struct{}{}
			upstream.mu.Unlock()
			return conn, nil
		},
	}
	return upstream
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
