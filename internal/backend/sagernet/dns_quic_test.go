package sagernet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
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
	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

func TestDoQAndHTTP3DNS(t *testing.T) {
	https := httptest.NewTLSServer(http.NotFoundHandler())
	cert := https.TLS.Certificates[0]
	https.Close()
	parsed, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	var wrong atomic.Bool
	var calls atomic.Int32
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13}
	listener, e := quic.ListenAddr("127.0.0.1:0", cfg, nil)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	wg.Go(func() {
		for {
			conn, e := listener.Accept(ctx)
			if e != nil {
				return
			}
			wg.Go(func() {
				defer conn.CloseWithError(0, "")
				stream, e := conn.AcceptStream(ctx)
				if e != nil {
					return
				}
				stream.SetDeadline(time.Now().Add(3 * time.Second))
				header := make([]byte, 2)
				if _, e = io.ReadFull(stream, header); e != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint16(header))
				if _, e = io.ReadFull(stream, body); e != nil {
					return
				}
				q := new(D.Msg)
				if e = q.Unpack(body); e != nil {
					return
				}
				if q.Id != 0 {
					t.Error("DoQ query ID must be zero")
				}
				calls.Add(1)
				m := dnsTestAnswer(q)
				if wrong.Load() {
					m.Id = 7
				}
				body, _ = m.Pack()
				binary.BigEndian.PutUint16(header, uint16(len(body)))
				stream.Write(append(header, body...))
				stream.Close()
				<-conn.Context().Done()
			})
		}
	})
	defer func() { cancel(); listener.Close(); wg.Wait() }()
	packet, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	h3 := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 || r.Method != "POST" || r.Header.Get("Content-Type") != "application/dns-message" {
			t.Error("invalid HTTP3 DNS request")
		}
		wire, _ := io.ReadAll(r.Body)
		q := new(D.Msg)
		if e := q.Unpack(wire); e != nil {
			t.Error(e)
			return
		}
		calls.Add(1)
		m := dnsTestAnswer(q)
		if wrong.Load() {
			m.Question[0].Name = "wrong.test."
		}
		wire, _ = m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(wire)
	})}
	done := make(chan struct{})
	go func() { defer close(done); h3.Serve(packet) }()
	defer func() { h3.Close(); packet.Close(); <-done }()
	dial := func(ctx context.Context, network, address, via string) (net.Conn, error) {
		if network != "udp" || via != "proxy" {
			t.Error("QUIC DNS lost its selected outbound", network, via)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	q := new(D.Msg)
	q.SetQuestion("example.test.", D.TypeA)
	q.Id = 4321
	for _, raw := range []string{"quic://" + listener.Addr().String() + "#proxy", "h3://" + packet.LocalAddr().String() + "/dns-query#proxy"} {
		ep, e := RD.ParseEndpoint(raw)
		if e != nil {
			t.Fatal(e)
		}
		for _, invalid := range []bool{false, true} {
			wrong.Store(invalid)
			m, e := exchangeDNS(ctx, ep, q, nil, dial, roots)
			if invalid {
				if e == nil {
					t.Fatal("invalid response identity accepted", m)
				}
			} else if e != nil || m.Id != 4321 || len(m.Answer) != 1 {
				t.Fatal(raw, m, e)
			}
		}
		if _, e := ExchangeDNS(ctx, ep, q, nil, dial); e == nil {
			t.Fatal("untrusted QUIC DNS certificate accepted")
		}
	}
	wrong.Store(false)
	ep, _ := RD.ParseEndpoint("https://" + packet.LocalAddr().String() + "/dns-query#proxy")
	ep.PreferH3 = true
	m, e := exchangeDNS(ctx, ep, q, nil, func(ctx context.Context, network, address, via string) (net.Conn, error) {
		if via != "proxy" {
			t.Error("probe lost selected outbound")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}, roots)
	if e != nil || len(m.Answer) != 1 {
		t.Fatal("prefer-h3 did not select the available QUIC transport", m, e)
	}
	if calls.Load() != 5 {
		t.Fatal("unexpected exchange count", calls.Load())
	}
}
