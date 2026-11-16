package sagernet

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	SS "github.com/sagernet/sing-shadowsocks2"
	M "github.com/sagernet/sing/common/metadata"
)

type delayedWriteReturn struct {
	net.Conn
	release, entered, closed chan struct{}
	once, closeOnce          sync.Once
}

func (c *delayedWriteReturn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		return n, err
	}
	c.once.Do(func() { close(c.entered) })
	select {
	case <-c.release:
		return n, nil
	case <-c.closed:
		return n, net.ErrClosed
	}
}
func (c *delayedWriteReturn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func TestSS2022SaltPublishedBeforeFirstWriteReturns(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	server := startServer(t, "ss2022", func(b *Backend, listen netip.AddrPort) error {
		s, err := StartShadowsocksServer(listen, "2022-blake3-aes-128-gcm", key, testLogger(t))
		if err == nil {
			t.Cleanup(func() { s.Close() })
		}
		return err
	})
	method, err := SS.CreateMethod(context.Background(), "2022-blake3-aes-128-gcm", SS.MethodOptions{Password: key})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.DialTimeout("tcp", server.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	gate := &delayedWriteReturn{Conn: raw, release: make(chan struct{}), entered: make(chan struct{}), closed: make(chan struct{})}
	defer gate.Close()
	defer close(gate.release)
	c := method.DialEarlyConn(gate, M.ParseSocksaddr(echoServer(t).String()))
	defer c.Close()
	const payload = "salt-publication"
	writeDone := make(chan error, 1)
	go func() { _, err := c.Write([]byte(payload)); writeDone <- err }()
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first write did not reach the wire")
	}
	readDone := make(chan error, 1)
	go func() {
		reply := make([]byte, len(payload))
		_, err := io.ReadFull(c, reply)
		if err == nil && string(reply) != payload {
			err = io.ErrUnexpectedEOF
		}
		readDone <- err
	}()
	select {
	case err = <-readDone:
		if err != nil {
			t.Fatal("response raced request-salt publication", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("response waited for first Write to return")
	}
	// Close unblocks a deliberately delayed writer on all assertion paths.
	gate.Close()
	<-writeDone
}
