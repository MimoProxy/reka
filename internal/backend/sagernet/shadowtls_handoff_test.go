package sagernet

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"io"
	"net"
	"testing"
	"time"

	SH "github.com/sagernet/sing-shadowtls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type shadowHandoffDialer struct {
	N.Dialer
	conn net.Conn
}

func (d shadowHandoffDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

type shadowHandoffHandler struct{ accepted chan struct{} }

func (h shadowHandoffHandler) NewConnectionEx(_ context.Context, c net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	close(h.accepted)
	c.Close()
}

// Hold the final handshake write after the peer has received its bytes. A
// valid authentication can now arrive while the old writer still owns the
// connection; handing it to the next protocol at this point corrupts records.
type shadowPendingWrite struct {
	net.Conn
	release <-chan struct{}
}

func (c shadowPendingWrite) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	<-c.release
	return n, err
}

func TestShadowTLSV2JoinsHandshakeWriterBeforeHandoff(t *testing.T) {
	client, server := net.Pipe()
	decoy, handshake := net.Pipe()
	defer client.Close()
	defer server.Close()
	defer decoy.Close()
	defer handshake.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server.SetDeadline(time.Now().Add(3 * time.Second))
	release := make(chan struct{})
	defer func() {
		if release != nil {
			close(release)
		}
	}()
	accepted := make(chan struct{})
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	service, err := SH.NewService(SH.ServiceConfig{
		Version: 2, Password: "handoff-key", Logger: b.logger,
		Handshake: SH.HandshakeConfig{Server: M.ParseSocksaddr("127.0.0.1:443"), Dialer: shadowHandoffDialer{N.SystemDialer, handshake}},
		Handler:   shadowHandoffHandler{accepted},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	blocked := shadowPendingWrite{server, release}
	go func() {
		done <- service.NewConnection(context.Background(), blocked, M.Socksaddr{}, M.Socksaddr{}, nil)
	}()
	hello := []byte{22, 3, 3, 0, 1, 0}
	flight := []byte{22, 3, 3, 0, 1, 1}
	go func() {
		data := make([]byte, len(hello))
		if _, err := io.ReadFull(decoy, data); err == nil {
			decoy.Write(flight)
		}
	}()
	if _, err = client.Write(hello); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(client, make([]byte, len(flight))); err != nil {
		t.Fatal(err)
	}
	hash := hmac.New(sha1.New, []byte("handoff-key"))
	hash.Write(flight)
	request := append([]byte{23, 3, 3, 0, 8}, hash.Sum(nil)[:8]...)
	if _, err = client.Write(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
		t.Fatal("business handler started before the handshake writer exited")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	release = nil
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handoff did not finish after handshake writer exited")
	}
	select {
	case <-accepted:
	default:
		t.Fatal("business handler was not invoked")
	}
}
