package sagernet

import (
	"bytes"
	"context"
	"fmt"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net/netip"
	"testing"
	"time"
)

func TestShadowTLSConcurrentFirstVectorAndOrdinaryWriteStayAtomic(t *testing.T) {
	for _, version := range []int{2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			destination, err := netip.ParseAddrPort(echoServer(t).String())
			if err != nil {
				t.Fatal(err)
			}
			spec := SSPluginSpec{Type: "shadow-tls", Version: version, Password: "outer-key", Host: "plugin.test"}
			port, security := pluginTestPeer(t, spec, destination)
			spec.TLS = security
			b := New(Options{Logger: testLogger(t)})
			defer b.Close()
			p, err := newSSPlugin(b.ctx, b.logger, N.SystemDialer, M.ParseSocksaddr(loopback(port).String()), spec)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			for range 32 {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				conn, err := p.DialContext(ctx)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				vector := conn.(N.VectorisedWriter)
				a := bytes.Repeat([]byte("a"), 65536)
				z := bytes.Repeat([]byte("z"), 65536)
				start := make(chan struct{})
				done := make(chan error, 2)
				go func() { <-start; _, err := conn.Write(a); done <- err }()
				go func() {
					<-start
					done <- vector.WriteVectorised([]*buf.Buffer{buf.As(z[:16384]), buf.As(z[16384:32768]), buf.As(z[32768:])})
				}()
				close(start)
				reply := make([]byte, len(a)+len(z))
				_, err = io.ReadFull(conn, reply)
				conn.Close()
				cancel()
				if err != nil {
					t.Fatal("concurrent first writes lost authentication or data", err)
				}
				for range 2 {
					if err := <-done; err != nil {
						t.Fatal(err)
					}
				}
				az := append(bytes.Clone(a), z...)
				za := append(bytes.Clone(z), a...)
				if !bytes.Equal(reply, az) && !bytes.Equal(reply, za) {
					t.Fatal("logical vector interleaved with another Write")
				}
			}
		})
	}
}
