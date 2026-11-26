package sagernet

import (
	"io"
	"net"
	"sync"
	"testing"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
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
