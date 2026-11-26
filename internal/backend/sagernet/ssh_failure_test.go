package sagernet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshFailingWriteConn struct {
	net.Conn
	fail   atomic.Bool
	failed chan struct{}
}

func (c *sshFailingWriteConn) Write(p []byte) (int, error) {
	if c.fail.Swap(false) {
		// The transport's read half stays usable until the outbound closes it.
		close(c.failed)
		return 0, errors.New("SSH test transport write failed")
	}
	return c.Conn.Write(p)
}

func TestSSHReconnectAfterTransportWriteError(t *testing.T) {
	config, host := sshTestConfig(t)
	server := newSSHTestServer(t, config, false)
	dial := server.detour.Dial
	transports := make(chan *sshFailingWriteConn, 2)
	server.detour.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		physical := &sshFailingWriteConn{Conn: conn, failed: make(chan struct{})}
		transports <- physical
		return physical, nil
	}
	out := server.outbound(t, "password", map[string]any{"host_key": sshTestPin(host)})
	stream := server.open(t, out)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	refused, err := out.Dial(ctx, "tcp", "denied.test:80")
	if refused != nil {
		_ = refused.Close()
	}
	var channelError *ssh.OpenChannelError
	if !errors.As(err, &channelError) {
		t.Fatalf("expected destination refusal, got %v", err)
	}
	sshTestEcho(t, stream, "before injected write error")
	first := sshTestReceive(t, server.sessions)
	physical := sshTestReceive(t, transports)
	physical.fail.Store(true)
	// x/crypto/ssh caches a packet write error and may return it on a later
	// write. Observe the injected transport error and peer shutdown directly.
	_, _ = stream.Write([]byte("fail this write"))
	sshTestReceive(t, physical.failed)
	sshTestReceive(t, first.done)
	sshTestEcho(t, server.open(t, out), "after transport write error")
	if server.accepts.Load() != 2 {
		t.Fatalf("expected one replacement connection, got %d connections", server.accepts.Load())
	}
}

func TestSSHDeadlineDuringBlockedWrite(t *testing.T) {
	config, host := sshTestConfig(t)
	server := newSSHTestServer(t, config, false)
	out := server.outbound(t, "password", map[string]any{"host_key": sshTestPin(host)})
	sibling := server.open(t, out)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	type dialResult struct {
		conn net.Conn
		err  error
	}
	dialed := make(chan dialResult, 1)
	go func() {
		conn, err := out.Dial(ctx, "tcp", "pending.test:80")
		dialed <- dialResult{conn, err}
	}()
	channel := sshTestReceive(t, server.pending)
	peer, requests, err := channel.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	go ssh.DiscardRequests(requests)
	result := sshTestReceive(t, dialed)
	if result.err != nil {
		t.Fatal(result.err)
	}
	stream := result.conn
	t.Cleanup(func() { _ = stream.Close() })

	// Exceed the peer's SSH channel window. Reading a single byte confirms
	// the write is in flight before its deadline is installed.
	payload := bytes.Repeat([]byte{'x'}, 8<<20)
	type writeResult struct {
		n   int
		err error
	}
	wrote := make(chan writeResult, 1)
	go func() {
		n, err := stream.Write(payload)
		wrote <- writeResult{n, err}
	}()
	received := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(peer, make([]byte, 1))
		received <- err
	}()
	if err := sshTestReceive(t, received); err != nil {
		t.Fatal(err)
	}
	if err := stream.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	partial := sshTestReceive(t, wrote)
	if !errors.Is(partial.err, os.ErrDeadlineExceeded) || partial.n < 1 || partial.n >= len(payload) {
		t.Fatalf("write to stalled SSH channel returned %d bytes, %v", partial.n, partial.err)
	}
	sshTestEcho(t, sibling, "independent stream")

	// Resetting the deadline permits another write. The peer must receive
	// exactly the acknowledged prefix before the marker.
	go func() {
		if _, err := io.CopyN(io.Discard, peer, int64(partial.n-1)); err != nil {
			received <- err
			return
		}
		var marker [1]byte
		_, err := io.ReadFull(peer, marker[:])
		if err == nil && marker[0] != '!' {
			err = errors.New("unexpected byte after the timed out write")
		}
		received <- err
	}()
	if err := stream.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{'!'}); err != nil {
		t.Fatal(err)
	}
	if err := sshTestReceive(t, received); err != nil {
		t.Fatal(err)
	}
	if server.accepts.Load() != 1 {
		t.Fatal("SSH write deadline replaced the shared connection")
	}
}
