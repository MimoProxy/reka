package sagernet

import (
	"context"
	"crypto/tls"
	RD "github.com/MimoProxy/reka/internal/dns"
	D "github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSPoolReusesEncryptedStreamsAndSeparatesRouteScope(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		q := new(D.Msg)
		if err := q.Unpack(raw); err != nil {
			t.Error(err)
			return
		}
		raw, _ = dnsTestAnswer(q).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(raw)
	})
	https := httptest.NewTLSServer(handler)
	defer https.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: https.TLS.Certificates, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	server := &D.Server{Listener: listener, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) { _ = w.WriteMsg(dnsTestAnswer(q)) })}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go server.ActivateAndServe()
	<-ready
	defer server.Shutdown()
	for _, raw := range []string{https.URL + "/dns-query", "tls://" + listener.Addr().String()} {
		t.Run(raw, func(t *testing.T) {
			pool := NewDNSPool()
			defer pool.Retire()
			var dials, closes atomic.Int32
			dial := func(ctx context.Context, network, address, via string) (net.Conn, error) {
				if via != "a" && via != "b" {
					t.Error("route lost", via)
				}
				c, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				dials.Add(1)
				return &dnsCountConn{Conn: c, closed: &closes}, nil
			}
			ep, err := RD.ParseEndpoint(raw)
			if err != nil {
				t.Fatal(err)
			}
			ep.Params = map[string]string{"skip-cert-verify": "true"}
			ep.Via = "a"
			ep.Scope = "normal"
			lookup := func(context.Context, string) ([]netip.Addr, error) {
				t.Error("IP endpoint bootstrapped")
				return nil, nil
			}
			var warmed int32
			for i := range 24 {
				q := new(D.Msg)
				q.SetQuestion("reuse.test.", D.TypeA)
				q.Id = uint16(100 + i)
				m, err := pool.Exchange(context.Background(), ep, q, lookup, dial)
				if err != nil || m.Id != q.Id {
					t.Fatal(m, err)
				}
				if i == 11 {
					warmed = dials.Load()
				}
			}
			// sing-box first probes whether a stream supports reuse. Those
			// bounded probe connections must stop once the transport is warm.
			if dials.Load() != warmed || warmed >= 12 {
				t.Fatal("stream was not reused", dials.Load())
			}
			q := new(D.Msg)
			q.SetQuestion("scope.test.", D.TypeA)
			ep.Scope = "proxy"
			if _, err := pool.Exchange(context.Background(), ep, q, lookup, dial); err != nil {
				t.Fatal(err)
			}
			afterScope := dials.Load()
			ep.Via = "b"
			if _, err := pool.Exchange(context.Background(), ep, q, lookup, dial); err != nil {
				t.Fatal(err)
			}
			if afterScope <= warmed || dials.Load() <= afterScope {
				t.Fatal("route/scope pool collision", dials.Load())
			}
			pool.Retire()
			deadline := time.Now().Add(time.Second)
			for closes.Load() != dials.Load() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if closes.Load() != dials.Load() {
				t.Fatal("idle socket leaked", dials.Load(), closes.Load())
			}
			if _, err := pool.Exchange(context.Background(), ep, q, lookup, dial); err != nil {
				t.Fatal("retired pinned foreground query failed", err)
			}
		})
	}
}

type dnsCountConn struct {
	net.Conn
	closed *atomic.Int32
	once   atomic.Bool
}

func (c *dnsCountConn) Close() error {
	if c.once.CompareAndSwap(false, true) {
		c.closed.Add(1)
	}
	return c.Conn.Close()
}

func TestDNSPoolRejectsWrongWireIdentityBeforeReuseIsKnown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				dc := &D.Conn{Conn: c}
				q, err := dc.ReadMsg()
				if err != nil {
					return
				}
				m := dnsTestAnswer(q)
				m.Id++
				_ = dc.WriteMsg(m)
			}()
		}
	}()
	pool := NewDNSPool()
	defer pool.Retire()
	ep, _ := RD.ParseEndpoint("tcp://" + listener.Addr().String())
	q := new(D.Msg)
	q.SetQuestion("wrong-id.test.", D.TypeA)
	dial := func(ctx context.Context, network, address, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	if m, err := pool.Exchange(context.Background(), ep, q, nil, dial); err == nil {
		t.Fatal("wrong wire identity was accepted", m)
	}
}
