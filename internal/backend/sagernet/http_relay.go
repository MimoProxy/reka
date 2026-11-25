package sagernet

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

// Use the HTTPS debug response budget for both sides of MITM. It leaves
// more room for concurrent flows on Packet Tunnel than sing-box's 1 MiB
// generic HTTP transport header budget.
const relayHTTPMaxHeaderBytes = 64 << 10

// singleConnListener runs an HTTP server on one already accepted connection.
// Serve returns when the connection closes, including after a hijack.
type singleConnListener struct {
	conn     net.Conn
	done     <-chan struct{}
	accepted bool
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	wire := &singleHTTPConn{Conn: conn, done: make(chan struct{})}
	return &singleConnListener{conn: wire, done: wire.done}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error   { return l.conn.Close() }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type singleHTTPConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
	err  error
}

func (c *singleHTTPConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		close(c.done)
	})
	return c.err
}

func stripHTTPHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(token))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authorization",
		"Proxy-Authenticate", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "HTTP2-Settings"} {
		header.Del(name)
	}
}
