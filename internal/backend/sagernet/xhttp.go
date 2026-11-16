package sagernet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	XC "github.com/MimoProxy/reka/internal/compat/xhttp"
	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"golang.org/x/net/http2"
)

// XHTTPConfig is the protocol configuration shared by native and imported
// options. Each constructed client takes an immutable copy.
type XHTTPConfig = XC.Config

type XHTTPClientOptions struct {
	Config             *XHTTPConfig
	ALPN               []string
	DownloadALPN       []string
	HasReality         bool
	DownloadHasReality bool
	KeepAlivePeriod    time.Duration
}

// XHTTPHooks have no default dialer. TCP must return a stream already protected,
// detoured and wrapped in TLS/REALITY where configured. QUIC must similarly use
// the protected UDP socket and own its closure when the QUIC connection ends.
// download identifies the optional independent download endpoint.
type XHTTPHooks struct {
	DialTCP  func(ctx context.Context, download, h2 bool) (net.Conn, error)
	DialQUIC func(ctx context.Context, download bool, cfg *quic.Config) (*quic.Conn, error)
}

func newXHTTPClient(opts XHTTPClientOptions, hooks XHTTPHooks) (*XC.Client, error) {
	if opts.Config == nil {
		return nil, errors.New("xhttp configuration is missing")
	}
	if err := XC.ValidateConfig(opts.Config); err != nil {
		return nil, err
	}
	cfg := XC.CloneConfig(opts.Config)
	if hooks.DialTCP == nil && hooks.DialQUIC == nil {
		return nil, errors.New("xhttp requires protected dial callbacks")
	}
	makeTransport := func(download bool, alpn []string) (XC.TransportMaker, error) {
		if len(alpn) == 0 {
			alpn = []string{"h2"}
		}
		if len(alpn) != 1 || (alpn[0] != "h2" && alpn[0] != "http/1.1" && alpn[0] != "h3") {
			return nil, fmt.Errorf("xhttp requires one explicit ALPN: h2, http/1.1 or h3")
		}
		protocol := alpn[0]
		keepAlivePeriod := opts.KeepAlivePeriod
		reuse := cfg.ReuseConfig
		if download && cfg.DownloadConfig != nil {
			reuse = cfg.DownloadConfig.ReuseConfig
		}
		if reuse != nil && reuse.HKeepAlivePeriod != "" {
			seconds, err := strconv.ParseInt(reuse.HKeepAlivePeriod, 10, 64)
			if err != nil {
				return nil, err
			}
			keepAlivePeriod = time.Duration(seconds) * time.Second
		}

		if protocol == "h3" {
			if (!download && opts.HasReality) || (download && opts.DownloadHasReality) {
				return nil, errors.New("xhttp HTTP/3 cannot carry REALITY")
			}
			if hooks.DialQUIC == nil {
				return nil, errors.New("xhttp HTTP/3 requires a protected QUIC dial callback")
			}
			return func() http.RoundTripper {
				keepAlive := keepAlivePeriod
				if keepAlive == 0 {
					keepAlive = 10 * time.Second
				}
				if keepAlive < 0 {
					keepAlive = 0
				}
				return &http3.Transport{QUICConfig: &quic.Config{MaxIncomingStreams: -1, KeepAlivePeriod: keepAlive, MaxIdleTimeout: 300 * time.Second}, Dial: func(ctx context.Context, _ string, _ *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
					return hooks.DialQUIC(ctx, download, cfg)
				}}
			}, nil
		}
		if hooks.DialTCP == nil {
			return nil, errors.New("xhttp requires a protected TCP dial callback")
		}
		return func() http.RoundTripper {
			owner := &xhttpOwnedTransport{conns: make(map[net.Conn]struct{})}
			dial := func(ctx context.Context, _ string, _ string) (net.Conn, error) {
				raw, err := hooks.DialTCP(ctx, download, protocol == "h2")
				if err != nil {
					return nil, err
				}
				return owner.track(raw)
			}
			if protocol == "h2" {
				keepAlive := keepAlivePeriod
				if keepAlive == 0 {
					keepAlive = 45 * time.Second
				}
				if keepAlive < 0 {
					keepAlive = 0
				}
				owner.RoundTripper = &http2.Transport{AllowHTTP: true, ReadIdleTimeout: keepAlive, IdleConnTimeout: 300 * time.Second, DialTLSContext: func(ctx context.Context, n, a string, _ *tls.Config) (net.Conn, error) { return dial(ctx, n, a) }}
			} else {
				owner.RoundTripper = &http.Transport{Proxy: nil, DialContext: dial, DialTLSContext: dial, IdleConnTimeout: 300 * time.Second, ForceAttemptHTTP2: false}
			}
			return owner
		}, nil
	}
	upload, err := makeTransport(false, opts.ALPN)
	if err != nil {
		return nil, err
	}
	var download XC.TransportMaker
	if cfg.DownloadConfig != nil {
		alpn := opts.DownloadALPN
		if len(alpn) == 0 {
			alpn = opts.ALPN
		}
		download, err = makeTransport(true, alpn)
		if err != nil {
			return nil, err
		}
	}
	return XC.NewClient(cfg, upload, download, opts.HasReality)
}

// xhttpOwnedTransport closes physical sockets as well as idle pool entries.
// Closing the transport occurs only when its owning stream/pool is released.
type xhttpOwnedTransport struct {
	http.RoundTripper
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func (t *xhttpOwnedTransport) track(raw net.Conn) (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		raw.Close()
		return nil, net.ErrClosed
	}
	c := &xhttpOwnedConn{Conn: raw, owner: t}
	t.conns[c] = struct{}{}
	return c, nil
}
func (t *xhttpOwnedTransport) CloseIdleConnections() {
	if c, ok := t.RoundTripper.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
func (t *xhttpOwnedTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	conns := make([]net.Conn, 0, len(t.conns))
	for c := range t.conns {
		conns = append(conns, c)
	}
	t.mu.Unlock()
	t.CloseIdleConnections()
	var errs []error
	for _, c := range conns {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

type xhttpOwnedConn struct {
	net.Conn
	owner *xhttpOwnedTransport
	once  sync.Once
	err   error
}

func (c *xhttpOwnedConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.owner.mu.Lock(); delete(c.owner.conns, c); c.owner.mu.Unlock() })
	return c.err
}
