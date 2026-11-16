package sagernet

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	S "github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type pluginUpgradeTransport struct {
	base       N.Dialer
	dst        M.Socksaddr
	host, path string
	headers    http.Header
	tls        S.Config
	fast       bool
}

func (t *pluginUpgradeTransport) DialContext(ctx context.Context) (net.Conn, error) {
	c, err := t.base.DialContext(ctx, "tcp", t.dst)
	if err != nil {
		return nil, err
	}
	if t.tls != nil {
		secured, err := S.ClientHandshake(ctx, c, t.tls.Clone())
		if err != nil {
			c.Close()
			return nil, err
		}
		c = secured
	}
	path := t.path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	target, err := url.Parse(path)
	if err != nil {
		c.Close()
		return nil, err
	}
	request := &http.Request{Method: "GET", URL: target, Host: t.host, Header: t.headers.Clone()}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	if err = request.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	conn := &pluginUpgradeConn{Conn: c, reader: bufio.NewReader(c), request: request}
	if !t.fast {
		conn.ensureResponse()
		if conn.err != nil {
			c.Close()
			return nil, conn.err
		}
	}
	return conn, nil
}
func (t *pluginUpgradeTransport) Close() error { return nil }

type pluginUpgradeConn struct {
	net.Conn
	reader  *bufio.Reader
	request *http.Request
	once    sync.Once
	err     error
}

func (c *pluginUpgradeConn) ensureResponse() {
	c.once.Do(func() {
		// Fast-open permits the encrypted payload before the upgrade response.
		// Bound the deferred response independently of the completed Dial context.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		stop := context.AfterFunc(ctx, func() { c.Conn.Close() })
		defer stop()
		response, err := http.ReadResponse(c.reader, c.request)
		if err != nil {
			c.err = err
			return
		}
		if response.StatusCode != 101 || !strings.EqualFold(response.Header.Get("Connection"), "upgrade") || !strings.EqualFold(response.Header.Get("Upgrade"), "websocket") {
			c.err = fmt.Errorf("plugin HTTP upgrade rejected: %s", response.Status)
			c.Conn.Close()
			response.Body.Close()
		}
	})
}
func (c *pluginUpgradeConn) Read(p []byte) (int, error) {
	c.ensureResponse()
	if c.err != nil {
		return 0, c.err
	}
	return c.reader.Read(p)
}
