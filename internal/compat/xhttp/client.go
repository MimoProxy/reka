// Adapted from MetaCubeX/mihomo v1.19.34; see ORIGIN.md.
package xhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"net/http"
)

// ConnIdleTimeout defines the maximum time an idle TCP session can survive in the tunnel,
// so it should be consistent across HTTP versions and with other transports.
const ConnIdleTimeout = 300 * time.Second

// QuicgoH3KeepAlivePeriod consistent with quic-go
const QuicgoH3KeepAlivePeriod = 10 * time.Second

// ChromeH2KeepAlivePeriod consistent with chrome
const ChromeH2KeepAlivePeriod = 45 * time.Second

type TransportMaker func() http.RoundTripper

type PacketUpWriter struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	cfg                  *Config
	scMaxEachPostBytes   int
	scMinPostsIntervalMs Range
	sessionID            string
	transport            http.RoundTripper
	writeMu              sync.Mutex
	writeCond            sync.Cond
	seq                  uint64
	buf                  []byte
	timer                *time.Timer
	flushErr             error
}

func (c *PacketUpWriter) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.flushErr; err != nil {
		return 0, err
	}

	data := bytes.NewBuffer(b)
	for data.Len() > 0 {
		if c.timer == nil { // start a timer to flush the buffer
			c.timer = time.AfterFunc(time.Duration(c.scMinPostsIntervalMs.Rand())*time.Millisecond, c.flush)
		}

		c.buf = append(c.buf, data.Next(c.scMaxEachPostBytes-len(c.buf))...) // let buffer fill up to scMaxEachPostBytes

		if len(c.buf) >= c.scMaxEachPostBytes { // too much data in buffer, wait the flush complete
			c.writeCond.Wait()
			if err := c.flushErr; err != nil {
				return 0, err
			}
		}
	}
	return len(b), nil
}

func (c *PacketUpWriter) flush() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	defer c.writeCond.Broadcast() // wake up the waited Write() call

	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}

	if c.flushErr != nil {
		return
	}

	if len(c.buf) == 0 {
		return
	}
	_, err := c.write(c.buf)
	c.buf = c.buf[:0] // reset buffer
	if err != nil {
		c.flushErr = err
		return
	}
}

func (c *PacketUpWriter) write(b []byte) (int, error) {
	u := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}

	req, err := http.NewRequestWithContext(c.ctx, c.cfg.GetNormalizedUplinkHTTPMethod(), u.String(), nil)
	if err != nil {
		return 0, err
	}

	seqStr := strconv.FormatUint(c.seq, 10)
	c.seq++

	if err := c.cfg.FillPacketRequest(req, c.sessionID, seqStr, b); err != nil {
		return 0, err
	}
	req.Host = c.cfg.Host

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
	}

	return len(b), nil
}

func (c *PacketUpWriter) Close() error {
	ch := make(chan struct{})
	go func() { // flush in the background
		defer close(ch)
		c.flush()
	}()
	select {
	case <-ch:
	case <-time.After(time.Second):
	}
	c.cancel()
	closeTransport(c.transport)
	return nil
}

type Client struct {
	mu                    sync.Mutex
	closed                bool
	conns                 map[*Conn]struct{}
	ctx                   context.Context
	cancel                context.CancelFunc
	mode                  string
	cfg                   *Config
	scMaxEachPostBytes    Range
	scMinPostsIntervalMs  Range
	generateSessionID     func() string
	makeTransport         TransportMaker
	makeDownloadTransport TransportMaker
	uploadManager         *ReuseManager
	downloadManager       *ReuseManager
}

func NewClient(cfg *Config, makeTransport TransportMaker, makeDownloadTransport TransportMaker, hasReality bool) (*Client, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	cfg = CloneConfig(cfg)
	mode := cfg.EffectiveMode(hasReality)
	switch mode {
	case "stream-one", "stream-up", "packet-up":
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", mode)
	}
	scMaxEachPostBytes, err := cfg.GetNormalizedScMaxEachPostBytes()
	if err != nil {
		return nil, err
	}
	scMinPostsIntervalMs, err := cfg.GetNormalizedScMinPostsIntervalMs()
	if err != nil {
		return nil, err
	}
	generateSessionID, err := cfg.GetGenerateSessionID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		mode:                  mode,
		conns:                 make(map[*Conn]struct{}),
		cfg:                   cfg,
		scMaxEachPostBytes:    scMaxEachPostBytes,
		scMinPostsIntervalMs:  scMinPostsIntervalMs,
		generateSessionID:     generateSessionID,
		makeTransport:         makeTransport,
		makeDownloadTransport: makeDownloadTransport,
		ctx:                   ctx,
		cancel:                cancel,
	}
	if makeTransport == nil {
		return nil, errors.New("xhttp upload transport factory is missing")
	}
	if cfg.DownloadConfig != nil && makeDownloadTransport == nil {
		return nil, errors.New("xhttp download transport factory is missing")
	}
	if cfg.ReuseConfig != nil {
		client.uploadManager, err = NewReuseManager(cfg.ReuseConfig, makeTransport)
		if err != nil {
			cancel()
			return nil, err
		}
		client.makeTransport = client.uploadManager.GetTransport
	}
	if cfg.DownloadConfig != nil && cfg.DownloadConfig.ReuseConfig != nil {
		client.downloadManager, err = NewReuseManager(cfg.DownloadConfig.ReuseConfig, makeDownloadTransport)
		if err != nil {
			cancel()
			return nil, err
		}
		client.makeDownloadTransport = client.downloadManager.GetTransport
	}

	return client, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	conns := make([]*Conn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	c.mu.Unlock()
	c.cancel()
	for _, conn := range conns {
		_ = conn.Close()
	}
	var errs []error
	if c.uploadManager != nil {
		err := c.uploadManager.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if c.downloadManager != nil {
		err := c.downloadManager.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	var raw net.Conn
	var err error
	switch c.mode {
	case "stream-one":
		raw, err = c.DialStreamOne(ctx)
	case "stream-up":
		raw, err = c.DialStreamUp(ctx)
	case "packet-up":
		raw, err = c.DialPacketUp(ctx)
	default:
		return nil, fmt.Errorf("invalid xhttp mode %s", c.mode)
	}
	if err != nil {
		return nil, err
	}
	conn := raw.(*Conn)
	before := conn.onClose
	conn.onClose = func() {
		if before != nil {
			before()
		}
		c.mu.Lock()
		delete(c.conns, conn)
		c.mu.Unlock()
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	c.conns[conn] = struct{}{}
	c.mu.Unlock()
	return conn, nil
}

// onlyRoundTripper is a wrapper that prevents the underlying transport from being closed.
type onlyRoundTripper struct {
	http.RoundTripper
}

func (c *Client) getTransport() (uploadTransport http.RoundTripper, downloadTransport http.RoundTripper, err error) {
	uploadTransport = c.makeTransport()
	downloadTransport = onlyRoundTripper{uploadTransport}
	if c.makeDownloadTransport != nil {
		downloadTransport = c.makeDownloadTransport()
	}
	return
}

func (c *Client) DialStreamOne(ctx context.Context) (net.Conn, error) {
	transport, _, err := c.getTransport()
	if err != nil {
		return nil, err
	}

	requestURL := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()

	conn := &Conn{writer: pw}

	// Use gotConn to detect when TCP connection is established, so we can
	// return the conn immediately without waiting for the HTTP response.
	// This breaks the deadlock where CDN buffers response headers until the
	// server sends body data, but the server waits for our request body,
	// which can't be sent because we haven't returned the conn yet.
	gotConn := make(chan bool, 1)

	reqCtx, reqCancel := c.requestContext(ctx) // preserve scoped DNS and pinned-route values
	stop := context.AfterFunc(ctx, reqCancel)  // temporarily connect ctx with reqCtx when dialing
	defer stop()                               // disconnect ctx with reqCtx after dialing

	streamCtx := newAddrContext(&conn.NetAddr, reqCtx, gotConn)

	req, err := http.NewRequestWithContext(streamCtx, c.cfg.GetNormalizedUplinkHTTPMethod(), requestURL.String(), pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		closeTransport(transport)
		reqCancel()
		return nil, err
	}
	req.Host = c.cfg.Host

	if err = c.cfg.FillStreamRequest(req, ""); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		closeTransport(transport)
		reqCancel()
		return nil, err
	}

	wrc := NewWaitReadCloser()

	go func() {
		resp, err := transport.RoundTrip(req)
		if err != nil {
			wrc.CloseWithError(err)
			select {
			case gotConn <- false:
			default:
			}
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			wrc.CloseWithError(fmt.Errorf("xhttp stream-one bad status: %s", resp.Status))
			return
		}
		wrc.Set(resp.Body)
	}()

	if !<-gotConn {
		// RoundTrip failed before TCP connected (e.g. DNS failure)
		_ = pr.Close()
		_ = pw.Close()
		closeTransport(transport)
		reqCancel()
		var buf [0]byte
		_, err = wrc.Read(buf[:])
		return nil, err
	}

	conn.reader = wrc
	conn.onClose = func() {
		_ = pr.Close()
		closeTransport(transport)
		reqCancel()
	}

	return conn, nil
}

func (c *Client) DialStreamUp(ctx context.Context) (net.Conn, error) {
	uploadTransport, downloadTransport, err := c.getTransport()
	if err != nil {
		return nil, err
	}

	downloadCfg := c.cfg
	if ds := c.cfg.DownloadConfig; ds != nil {
		downloadCfg = ds
	}

	streamURL := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadCfg.Host,
		Path:   downloadCfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()

	conn := &Conn{writer: pw}

	sessionID := c.generateSessionID()

	// Async download: avoid blocking on CDN response header buffering
	gotConn := make(chan bool, 1)

	reqCtx, reqCancel := c.requestContext(ctx) // preserve scoped DNS and pinned-route values
	stop := context.AfterFunc(ctx, reqCancel)  // temporarily connect ctx with reqCtx when dialing
	defer stop()                               // disconnect ctx with reqCtx after dialing

	downloadCtx := newAddrContext(&conn.NetAddr, reqCtx, gotConn)

	downloadReq, err := http.NewRequestWithContext(
		downloadCtx,
		http.MethodGet,
		downloadURL.String(),
		nil,
	)
	if err != nil {
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		reqCancel()
		return nil, err
	}

	if err := downloadCfg.FillDownloadRequest(downloadReq, sessionID); err != nil {
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		reqCancel()
		return nil, err
	}
	downloadReq.Host = downloadCfg.Host

	uploadReq, err := http.NewRequestWithContext(
		reqCtx,
		c.cfg.GetNormalizedUplinkHTTPMethod(),
		streamURL.String(),
		pr,
	)
	if err != nil {
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		reqCancel()
		return nil, err
	}

	if err = c.cfg.FillStreamRequest(uploadReq, sessionID); err != nil {
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		reqCancel()
		return nil, err
	}
	uploadReq.Host = c.cfg.Host

	wrc := NewWaitReadCloser()

	go func() {
		resp, err := downloadTransport.RoundTrip(downloadReq)
		if err != nil {
			wrc.CloseWithError(err)
			select {
			case gotConn <- false:
			default:
			}
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			wrc.CloseWithError(fmt.Errorf("xhttp stream-up download bad status: %s", resp.Status))
			return
		}
		wrc.Set(resp.Body)
	}()

	if !<-gotConn {
		_ = pr.Close()
		_ = pw.Close()
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		reqCancel()
		var buf [0]byte
		_, err = wrc.Read(buf[:])
		return nil, err
	}

	// Start upload after download TCP is connected, so the server has likely
	// already processed the GET and created the session. This preserves the
	// original ordering (download before upload) while still being async.
	go func() {
		resp, err := uploadTransport.RoundTrip(uploadReq)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = pw.CloseWithError(fmt.Errorf("xhttp stream-up upload bad status: %s", resp.Status))
		}
	}()

	conn.reader = wrc
	conn.onClose = func() {
		_ = pr.Close()
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		reqCancel()
	}

	return conn, nil
}

func (c *Client) DialPacketUp(ctx context.Context) (net.Conn, error) {
	uploadTransport, downloadTransport, err := c.getTransport()
	if err != nil {
		return nil, err
	}

	downloadCfg := c.cfg
	if ds := c.cfg.DownloadConfig; ds != nil {
		downloadCfg = ds
	}
	sessionID := c.generateSessionID()

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadCfg.Host,
		Path:   downloadCfg.NormalizedPath(),
	}

	writerCtx, writerCancel := c.requestContext(ctx)
	returned := false
	defer func() {
		if !returned {
			writerCancel()
		}
	}()
	writer := &PacketUpWriter{
		ctx:                  writerCtx,
		cancel:               writerCancel,
		cfg:                  c.cfg,
		scMaxEachPostBytes:   c.scMaxEachPostBytes.Rand(),
		scMinPostsIntervalMs: c.scMinPostsIntervalMs,
		sessionID:            sessionID,
		transport:            uploadTransport,
		seq:                  0,
	}
	writer.writeCond = sync.Cond{L: &writer.writeMu}
	conn := &Conn{writer: writer}

	// Async download: avoid blocking on CDN response header buffering
	gotConn := make(chan bool, 1)

	reqCtx, reqCancel := c.requestContext(ctx) // preserve scoped DNS and pinned-route values
	stop := context.AfterFunc(ctx, reqCancel)  // temporarily connect ctx with reqCtx when dialing
	defer stop()                               // disconnect ctx with reqCtx after dialing

	downloadCtx := newAddrContext(&conn.NetAddr, reqCtx, gotConn)

	downloadReq, err := http.NewRequestWithContext(
		downloadCtx,
		http.MethodGet,
		downloadURL.String(),
		nil,
	)
	if err != nil {
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		reqCancel()
		return nil, err
	}
	if err = downloadCfg.FillDownloadRequest(downloadReq, sessionID); err != nil {
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		reqCancel()
		return nil, err
	}
	downloadReq.Host = downloadCfg.Host

	wrc := NewWaitReadCloser()

	go func() {
		resp, err := downloadTransport.RoundTrip(downloadReq)
		if err != nil {
			wrc.CloseWithError(err)
			select {
			case gotConn <- false:
			default:
			}
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			wrc.CloseWithError(fmt.Errorf("xhttp packet-up download bad status: %s", resp.Status))
			return
		}
		wrc.Set(resp.Body)
	}()

	if !<-gotConn {
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		reqCancel()
		var buf [0]byte
		_, err = wrc.Read(buf[:])
		return nil, err
	}

	conn.reader = wrc
	conn.onClose = func() {
		// uploadTransport already closed by writer
		closeTransport(downloadTransport)
		reqCancel()
	}

	returned = true
	return conn, nil
}

// WaitReadCloser is an io.ReadCloser that blocks on Read() until the underlying
// ReadCloser is provided via Set(). This enables returning a reader immediately
// while the actual HTTP response body is obtained asynchronously in a goroutine,
// breaking the synchronous RoundTrip deadlock with CDN header buffering.
type WaitReadCloser struct {
	wait   chan struct{}
	mu     sync.Mutex
	set    bool
	closed bool
	rc     io.ReadCloser
	err    error
}

func NewWaitReadCloser() *WaitReadCloser           { return &WaitReadCloser{wait: make(chan struct{})} }
func (w *WaitReadCloser) Set(rc io.ReadCloser)     { w.setup(rc, nil) }
func (w *WaitReadCloser) CloseWithError(err error) { w.setup(nil, err) }
func (w *WaitReadCloser) setup(rc io.ReadCloser, err error) {
	w.mu.Lock()
	if w.set || w.closed {
		w.mu.Unlock()
		if rc != nil {
			_ = rc.Close()
		}
		return
	}
	w.set = true
	w.rc = rc
	w.err = err
	close(w.wait)
	w.mu.Unlock()
}
func (w *WaitReadCloser) Read(p []byte) (int, error) {
	<-w.wait
	w.mu.Lock()
	rc, err := w.rc, w.err
	w.mu.Unlock()
	if rc == nil {
		if err == nil {
			err = net.ErrClosed
		}
		return 0, err
	}
	return rc.Read(p)
}
func (w *WaitReadCloser) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	if !w.set {
		w.set = true
		w.err = net.ErrClosed
		close(w.wait)
	}
	rc := w.rc
	w.mu.Unlock()
	if rc != nil {
		return rc.Close()
	}
	return nil
}

// CloseIdleConnections releases idle physical sessions without interrupting
// streams that are still protected by an outbound lease.
func (c *Client) CloseIdleConnections() {
	for _, m := range []*ReuseManager{c.uploadManager, c.downloadManager} {
		if m != nil {
			m.CloseIdleConnections()
		}
	}
}
func (c *Client) Reset() { c.CloseIdleConnections() }
func (c *Client) SetKeepIdleConnections(keep bool) {
	if !keep {
		c.CloseIdleConnections()
	}
}

// Request lifetime is detached from the dial timeout after establishment, but
// DNS/detour metadata stays attached to every later physical HTTP dial. The
// client still owns cancellation when its outbound is finally closed.
func (c *Client) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	request, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(c.ctx, cancel)
	return request, func() { stop(); cancel() }
}
