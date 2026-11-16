// Adapted from MetaCubeX/mihomo v1.19.34; GPL-3.0-or-later, see ORIGIN.md.
package kcptun

import (
	"net"
	"sync"
	"time"

	"github.com/golang/snappy"
)

// CompStream is a net.Conn wrapper that compresses data using snappy
type CompStream struct {
	conn        net.Conn
	w           *snappy.Writer
	writeAccess sync.Mutex
	r           *snappy.Reader
}

func (c *CompStream) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *CompStream) Write(p []byte) (n int, err error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if _, err := c.w.Write(p); err != nil {
		return 0, err
	}

	if err := c.w.Flush(); err != nil {
		return 0, err
	}
	return len(p), err
}

func (c *CompStream) Close() error {
	return c.conn.Close()
}

func (c *CompStream) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *CompStream) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *CompStream) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *CompStream) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *CompStream) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// NewCompStream creates a new stream that compresses data using snappy
func NewCompStream(conn net.Conn) *CompStream {
	c := new(CompStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}
