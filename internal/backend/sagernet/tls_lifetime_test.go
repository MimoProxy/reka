package sagernet

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	ST "github.com/sagernet/sing/common/tls"
)

type pausedServerTLS struct {
	ST.ServerConfig
	entered chan struct{}
	release chan struct{}
}

func (*pausedServerTLS) HandshakeTimeout() time.Duration { return 0 }
func (s *pausedServerTLS) ServerHandshake(_ context.Context, c net.Conn) (ST.Conn, error) {
	close(s.entered)
	<-s.release
	return &publishedTLSConn{Conn: c}, nil
}

type publishedTLSConn struct{ net.Conn }

func (c *publishedTLSConn) NetConn() net.Conn                    { return c.Conn }
func (*publishedTLSConn) HandshakeContext(context.Context) error { return nil }
func (*publishedTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{HandshakeComplete: true}
}

func TestLazyTLSCloseDuringHandshakePublication(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	config := &pausedServerTLS{entered: make(chan struct{}), release: make(chan struct{})}
	c := ST.NewLazyConn(raw, config)
	done := make(chan error, 1)
	go func() { done <- c.HandshakeContext(context.Background()) }()
	<-config.entered
	if !c.NeedHandshake() || c.ReaderReplaceable() || c.WriterReplaceable() {
		t.Fatal("published an unfinished handshake")
	}
	if c.Upstream() != raw {
		t.Fatal("lost original socket before handshake")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 1000 {
			c.Close()
			c.LocalAddr()
			c.RemoteAddr()
			c.SetDeadline(time.Time{})
			c.NeedHandshake()
			c.ReaderReplaceable()
			c.WriterReplaceable()
			c.Upstream()
		}
	}()
	close(config.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if c.NeedHandshake() || !c.ReaderReplaceable() || !c.WriterReplaceable() {
		t.Fatal("completed handshake was not published")
	}
	if _, ok := c.Upstream().(*publishedTLSConn); !ok {
		t.Fatal("upstream did not publish TLS connection")
	}
	if _, err := peer.Write([]byte("closed")); err == nil {
		t.Fatal("close did not release physical socket")
	}
}
