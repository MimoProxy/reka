// Adapted from MetaCubeX/mihomo v1.19.34; see ORIGIN.md.
package xhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

// Conn carries a single XHTTP stream. Closing a client is an explicit forced
// close; ordinary outbound replacement keeps the client until its leases drain.
type Conn struct {
	writer  io.WriteCloser
	reader  io.ReadCloser
	onClose func()
	NetAddr
	closeOnce  sync.Once
	closeErr   error
	deadlineMu sync.Mutex
	deadline   *time.Timer
}

func (c *Conn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *Conn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.deadlineMu.Lock()
		if c.deadline != nil {
			c.deadline.Stop()
			c.deadline = nil
		}
		c.deadlineMu.Unlock()
		// Cancel HTTP requests before closing their pipes, so a blocked reader or
		// upload does not retain the outbound after an explicit forced close.
		if c.onClose != nil {
			c.onClose()
		}
		c.closeErr = errors.Join(c.writer.Close(), c.reader.Close())
	})
	return c.closeErr
}
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }
func (c *Conn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.deadline != nil {
		c.deadline.Stop()
		c.deadline = nil
	}
	if !t.IsZero() {
		c.deadline = time.AfterFunc(time.Until(t), func() { _ = c.Close() })
	}
	return nil
}

// NetAddr snapshots physical addresses while HTTP traces can run concurrently.
type NetAddr struct {
	mu            sync.RWMutex
	local, remote net.Addr
}

func (a *NetAddr) LocalAddr() net.Addr {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.local == nil {
		return emptyAddr("xhttp-local")
	}
	return a.local
}
func (a *NetAddr) RemoteAddr() net.Addr {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.remote == nil {
		return emptyAddr("xhttp-remote")
	}
	return a.remote
}

type emptyAddr string

func (a emptyAddr) Network() string { return "xhttp" }
func (a emptyAddr) String() string  { return string(a) }

type initialConnObserverKey struct{}

// WithInitialConnObserver reports the connection selected for the initial
// request before Dial returns. Split modes use their download request here.
func WithInitialConnObserver(ctx context.Context, observe func(httptrace.GotConnInfo)) context.Context {
	return context.WithValue(ctx, initialConnObserverKey{}, observe)
}

func newAddrContext(a *NetAddr, ctx context.Context, ready chan<- bool) context.Context {
	observe, _ := ctx.Value(initialConnObserverKey{}).(func(httptrace.GotConnInfo))
	var once sync.Once
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		a.mu.Lock()
		a.local = info.Conn.LocalAddr()
		a.remote = info.Conn.RemoteAddr()
		a.mu.Unlock()
		once.Do(func() {
			if observe != nil {
				observe(info)
			}
			select {
			case ready <- true:
			default:
			}
		})
	}})
}
func closeTransport(t http.RoundTripper) {
	if c, ok := t.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
	if c, ok := t.(io.Closer); ok {
		_ = c.Close()
	}
}
func newUUID() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	raw[6] = (raw[6] & 15) | 64
	raw[8] = (raw[8] & 63) | 128
	h := hex.EncodeToString(raw[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
