package sagernet

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/buf"
	B "github.com/sagernet/sing/common/bufio"
)

func TestCachedConnectionReadCloseOwnership(t *testing.T) {
	for i := 0; i < 500; i++ {
		a, b := net.Pipe()
		buffer := buf.As([]byte("cached-protocol-handshake"))
		c := B.NewCachedConn(a, buffer)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(io.Discard, c) }()
		go func() { defer wg.Done(); c.Close(); b.Close() }()
		wg.Wait()
	}
}
func TestCachedConnectionWriteToConsumesBufferOnce(t *testing.T) {
	a, b := net.Pipe()
	b.Close()
	defer a.Close()
	c := B.NewCachedConn(a, buf.As([]byte("once")))
	defer c.Close()
	var output bytes.Buffer
	for i := 0; i < 2; i++ {
		c.WriteTo(&output)
	}
	if output.String() != "once" {
		t.Fatal("cached prefix duplicated", output.String())
	}
}
