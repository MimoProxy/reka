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

func TestShadowTLSV2TLSVersionsSmallRecordsAndClose(t *testing.T) {
	for _, fingerprint := range []string{"", "chrome"} {
		for _, tls12 := range []bool{false, true} {
			t.Run(fmt.Sprintf("fingerprint-%s/tls12-%v", fingerprint, tls12), func(t *testing.T) {
				spec := SSPluginSpec{Type: "shadow-tls", Version: 2, Password: "record-key", Host: "plugin.test", ForceTLS12: tls12, TLS: &TLSSpec{Fingerprint: fingerprint}}
				port, security := pluginTestPeer(t, spec, echoServer(t))
				spec.TLS = security
				spec.TLS.ALPN = []string{"h2"}
				b := New(Options{Logger: testLogger(t)})
				defer b.Close()
				plugin, err := newSSPlugin(b.ctx, b.logger, N.SystemDialer, M.ParseSocksaddr(loopback(port).String()), spec)
				if err != nil {
					t.Fatal(err)
				}
				defer plugin.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				c, err := plugin.DialContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				for _, size := range []int{1, 8, 16385, 65536} {
					payload := bytes.Repeat([]byte{'r'}, size)
					written := make(chan error, 1)
					go func() { _, err := c.Write(payload); written <- err }()
					reply := make([]byte, size)
					if _, err = io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, payload) {
						t.Fatal("TLS/proxy record boundary", size, err)
					}
					if err = <-written; err != nil {
						t.Fatal(err)
					}
				}
				readDone := make(chan error, 1)
				go func() { _, err := c.Read(make([]byte, 1)); readDone <- err }()
				c.Close()
				select {
				case err = <-readDone:
					if err == nil {
						t.Fatal("closed connection remained readable")
					}
				case <-time.After(time.Second):
					t.Fatal("close did not interrupt reader")
				}
			})
		}
	}
}
