package sagernet

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

// A peer that drops the connection closes every AnyTLS stream from the
// session's receive loop while callers may still be reading and writing
// them. Under -race this covers the stream's close error publication.
func TestAnyTLSStreamCloseDuringReadWrite(t *testing.T) {
	var scheme atomic.TypedValue[*padding.PaddingFactory]
	scheme.Store(padding.NewPaddingFactory(padding.DefaultPaddingScheme))
	for range 20 {
		client, peer := net.Pipe()
		sess := session.NewClientSession(client, &scheme, logger.NOP())
		sess.Run()
		stream, err := sess.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			_, _ = io.Copy(io.Discard, peer)
		}()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			payload := make([]byte, 64)
			for {
				if _, err := stream.Write(payload); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			_, _ = stream.Read(make([]byte, 64))
		}()
		_ = peer.Close()
		wg.Wait()
		<-drained
		if !sess.IsClosed() {
			t.Fatal("session stayed open after the peer closed")
		}
		if _, err := stream.Write([]byte{0}); err == nil {
			t.Fatal("write succeeded on a closed stream")
		}
		if _, err := stream.Read(make([]byte, 1)); err == nil {
			t.Fatal("read succeeded on a closed stream")
		}
	}
}

// The receive loop answers heartbeats and records the server's protocol
// version while the client opens further streams on the same session.
func TestAnyTLSOpenStreamDuringServerFrames(t *testing.T) {
	var scheme atomic.TypedValue[*padding.PaddingFactory]
	scheme.Store(padding.NewPaddingFactory(padding.DefaultPaddingScheme))
	client, peer := net.Pipe()
	sess := session.NewClientSession(client, &scheme, logger.NOP())
	t.Cleanup(func() { _ = sess.Close() })
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	frame := func(cmd byte, data []byte) []byte {
		header := make([]byte, 7, 7+len(data))
		header[0] = cmd
		binary.BigEndian.PutUint16(header[5:], uint16(len(data)))
		return append(header, data...)
	}
	const heartRequest, serverSettings = 8, 10
	frames := append(frame(heartRequest, nil), frame(serverSettings, util.StringMap{"v": "2"}.ToBytes())...)
	stop := make(chan struct{})
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := peer.Write(frames); err != nil {
				return
			}
		}
	}()
	sess.Run()
	for range 100 {
		stream, err := sess.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	_ = peer.Close()
	<-sent
}
