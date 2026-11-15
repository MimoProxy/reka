package sagernet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	RD "github.com/MimoProxy/reka/internal/dns"
	D "github.com/miekg/dns"
)

func dnsTestAnswer(q *D.Msg) *D.Msg {
	m := new(D.Msg)
	m.SetReply(q)
	rr, _ := D.NewRR(q.Question[0].Name + " 30 IN A 192.0.2.8")
	m.Answer = []D.RR{rr}
	return m
}

func TestEncryptedDNS(t *testing.T) {
	var invalid atomic.Bool
	https := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/dns-message" {
			t.Error("invalid DoH request")
		}
		b, _ := io.ReadAll(r.Body)
		q := new(D.Msg)
		if err := q.Unpack(b); err != nil {
			t.Error(err)
			return
		}
		if invalid.Load() {
			w.Header().Set("Content-Type", "text/html")
		} else {
			w.Header().Set("Content-Type", "application/dns-message")
		}
		b, _ = dnsTestAnswer(q).Pack()
		_, _ = w.Write(b)
	}))
	defer https.Close()
	cert := https.TLS.Certificates[0]
	root, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				dc := &D.Conn{Conn: conn}
				if q, err := dc.ReadMsg(); err == nil {
					_ = dc.WriteMsg(dnsTestAnswer(q))
				}
			})
		}
	})
	defer func() { listener.Close(); wg.Wait() }()
	dial := func(ctx context.Context, network, address, via string) (net.Conn, error) {
		if network != "tcp" || via != "proxy" {
			t.Error("encrypted DNS routing lost", network, via)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	q := new(D.Msg)
	q.SetQuestion("example.test.", D.TypeA)
	for _, endpoint := range []string{"tls://" + listener.Addr().String() + "#proxy", https.URL + "/dns-query#proxy"} {
		ep, _ := RD.ParseEndpoint(endpoint)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		m, err := exchangeDNS(ctx, ep, q, nil, dial, roots)
		if err != nil || len(m.Answer) != 1 || m.Id != q.Id {
			t.Fatal(endpoint, m, err)
		}
		if _, err = ExchangeDNS(ctx, ep, q, nil, dial); err == nil {
			t.Fatal("untrusted TLS certificate accepted")
		}
		cancel()
	}
	invalid.Store(true)
	ep, _ := RD.ParseEndpoint(https.URL)
	ep.Via = "proxy"
	if _, err = exchangeDNS(context.Background(), ep, q, nil, dial, roots); err == nil {
		t.Fatal("non-DNS DoH response accepted")
	}
}

func TestDNSTruncatedUDPUsesTCP(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", packet.LocalAddr().String())
	if err != nil {
		packet.Close()
		t.Fatal(err)
	}
	handler := D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		m := dnsTestAnswer(q)
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			m.Answer = nil
			m.Truncated = true
		}
		_ = w.WriteMsg(m)
	})
	u, s := &D.Server{PacketConn: packet, Handler: handler}, &D.Server{Listener: listener, Handler: handler}
	ready := make(chan struct{}, 2)
	u.NotifyStartedFunc = func() { ready <- struct{}{} }
	s.NotifyStartedFunc = func() { ready <- struct{}{} }
	go u.ActivateAndServe()
	go s.ActivateAndServe()
	<-ready
	<-ready
	defer u.Shutdown()
	defer s.Shutdown()
	dial := func(ctx context.Context, network, address, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	ep, _ := RD.ParseEndpoint(packet.LocalAddr().String())
	q := new(D.Msg)
	q.SetQuestion("example.test.", D.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	m, err := ExchangeDNS(ctx, ep, q, nil, dial)
	if err != nil || m.Truncated || len(m.Answer) != 1 {
		t.Fatal(m, err)
	}
}
