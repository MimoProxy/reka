package sagernet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	"golang.org/x/net/http2"
)

// REALITY owns the TLS handshake, so its H2 layer uses an already encrypted
// connection. Each physical connection owns and closes its H2 client session.
func newH2Stream(ctx context.Context, raw net.Conn, options option.V2RayHTTPOptions) (net.Conn, error) {
	client, err := (&http2.Transport{}).NewClientConn(raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	reader, writer := io.Pipe()
	requestCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	host := "www.example.com"
	if len(options.Host) > 0 {
		host = options.Host[rand.IntN(len(options.Host))]
	}
	path := options.Path
	if path == "" {
		path = "/"
	}
	request := (&http.Request{Method: "PUT", Host: host, URL: &url.URL{Scheme: "https", Host: host, Path: path}, Header: http.Header{"Accept-Encoding": []string{"identity"}}, Body: reader}).WithContext(requestCtx)
	c := &h2Stream{Conn: raw, client: client, writer: writer, cancel: cancel, ready: make(chan struct{})}
	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	timer := time.AfterFunc(timeout, cancel)
	go func() {
		response, err := client.RoundTrip(request)
		timer.Stop()
		c.mu.Lock()
		defer c.mu.Unlock()
		if err == nil && response.StatusCode != http.StatusOK {
			response.Body.Close()
			err = fmt.Errorf("H2 transport status %d", response.StatusCode)
		}
		if err == nil {
			if c.closed {
				response.Body.Close()
				err = net.ErrClosed
			} else {
				c.body = response.Body
			}
		}
		c.err = err
		close(c.ready)
	}()
	return c, nil
}

type h2Stream struct {
	net.Conn
	client *http2.ClientConn
	writer *io.PipeWriter
	cancel context.CancelFunc
	ready  chan struct{}
	mu     sync.Mutex
	closed bool
	body   io.ReadCloser
	err    error
}

func (c *h2Stream) Read(p []byte) (int, error) {
	<-c.ready
	if c.err != nil {
		return 0, c.err
	}
	return c.body.Read(p)
}
func (c *h2Stream) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *h2Stream) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.cancel()
	var bodyErr error
	if c.body != nil {
		bodyErr = c.body.Close()
	}
	return errors.Join(c.writer.Close(), bodyErr, c.client.Close(), c.Conn.Close())
}
