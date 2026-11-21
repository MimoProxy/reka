package sagernet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/testnet"
	D "github.com/miekg/dns"
)

func dnsTestAnswer(q *D.Msg) *D.Msg {
	m := new(D.Msg)
	m.SetReply(q)
	rr, _ := D.NewRR(q.Question[0].Name + " 30 IN A 192.0.2.8")
	m.Answer = []D.RR{rr}
	return m
}

type dnsTestRoundTripper func(*http.Request) (*http.Response, error)

func (f dnsTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDoHErrorRedactsRequestURL(t *testing.T) {
	const origin = "https://resolver.example.test:8443"
	const pathToken, queryToken = "test-path-token", "test-query-token"
	const requestURI = "/dns-query/" + pathToken + "?token=" + queryToken
	ep, err := RD.ParseEndpoint(origin + requestURI)
	if err != nil {
		t.Fatal(err)
	}
	q := new(D.Msg).SetQuestion("example.test.", D.TypeA)
	checkRedacted := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected an exchange error")
		}
		message := err.Error()
		if strings.Contains(message, pathToken) || strings.Contains(message, queryToken) {
			t.Errorf("exchange error exposes request credentials: %s", message)
		}
		if !strings.Contains(message, origin) {
			t.Errorf("exchange error omits %s: %s", origin, message)
		}
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			transport := dnsTestRoundTripper(func(req *http.Request) (*http.Response, error) {
				if got := req.URL.RequestURI(); got != requestURI {
					t.Errorf("request URI = %q, want %q", got, requestURI)
				}
				return nil, cause
			})
			_, err := exchangeDoHTransport(t.Context(), ep, q, transport)
			if !errors.Is(err, cause) {
				t.Fatalf("exchange error = %v, want cause %v", err, cause)
			}
			checkRedacted(t, err)
			if cause == context.DeadlineExceeded {
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Errorf("exchange error does not report a timeout: %v", err)
				}
			}
		})
	}
	t.Run("request construction", func(t *testing.T) {
		ep := ep
		ep.Path = "/%zz" + requestURI
		transport := dnsTestRoundTripper(func(*http.Request) (*http.Response, error) {
			t.Fatal("sent request with an invalid URL")
			return nil, nil
		})
		_, err := exchangeDoHTransport(t.Context(), ep, q, transport)
		checkRedacted(t, err)
	})
	t.Run("malformed redirect", func(t *testing.T) {
		transport := dnsTestRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": {origin + "/%zz" + requestURI}},
				Body:       http.NoBody,
				Request:    req,
			}, nil
		})
		_, err := exchangeDoHTransport(t.Context(), ep, q, transport)
		checkRedacted(t, err)
	})
	t.Run("HTTP3", func(t *testing.T) {
		ep := ep
		ep.Scheme = "h3"
		open := func(context.Context, string) (net.Conn, error) { return nil, context.Canceled }
		_, err := exchangeQUICDNS(t.Context(), ep, q, open, dnsTLSConfig(ep, nil), "192.0.2.1:8443")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("exchange error = %v, want cause %v", err, context.Canceled)
		}
		checkRedacted(t, err)
	})
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
		if ep.Scheme == "https" {
			ep.PreferH3 = true
			probeDial := func(ctx context.Context, network, address, via string) (net.Conn, error) {
				if via != "proxy" {
					t.Error("probe lost routing", via)
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			if m, e := exchangeDNS(ctx, ep, q, nil, probeDial, roots); e != nil || len(m.Answer) != 1 {
				t.Fatal("prefer-h3 TLS fallback", m, e)
			}
			ep.PreferH3 = false
		}
		m, err := exchangeDNS(ctx, ep, q, nil, dial, roots)
		if err != nil || len(m.Answer) != 1 || m.Id != q.Id {
			t.Fatal(endpoint, m, err)
		}
		if _, err = ExchangeDNS(ctx, ep, q, nil, dial); err == nil {
			t.Fatal("untrusted TLS certificate accepted")
		}
		ep.Params = map[string]string{"skip-cert-verify": "true"}
		if _, err = ExchangeDNS(ctx, ep, q, nil, dial); err != nil {
			t.Fatal("explicit TLS verification skip", err)
		}
		name := "example.com"
		if len(root.DNSNames) > 0 {
			name = root.DNSNames[0]
		} else if len(root.IPAddresses) > 0 {
			name = root.IPAddresses[0].String()
		}
		ep.Params = map[string]string{"name-cert-verify": name}
		if _, err = exchangeDNS(ctx, ep, q, nil, dial, roots); err != nil {
			t.Fatal("explicit certificate name", err)
		}
		ep.Params = map[string]string{"skip-cert-verify": "true", "name-cert-verify": "wrong.invalid"}
		if _, err = exchangeDNS(ctx, ep, q, nil, dial, roots); err == nil {
			t.Fatal("verification name was ignored")
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
	listener, packet := testnet.ListenTCPUDP(t)
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
