package sagernet

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
	S "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func TestECHExplicitAndDNSConfigsNegotiateRealSTDAndUTLS(t *testing.T) {
	configPEM, keyPEM, err := S.ECHKeygenDefault("public.test")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(configPEM))
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	keys, err := S.UnmarshalECHKeys(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	wrongPEM, _, _ := S.ECHKeygenDefault("public.test")
	wrong, _ := pem.Decode([]byte(wrongPEM))
	var accepted atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || !r.TLS.ECHAccepted || r.TLS.ServerName != "example.com" {
			w.WriteHeader(403)
			return
		}
		accepted.Add(1)
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		io.Copy(c, c)
	}))
	server.TLS = &tls.Config{EncryptedClientHelloKeys: keys}
	server.StartTLS()
	defer server.Close()
	pin := sha256.Sum256(server.TLS.Certificates[0].Certificate[0])
	address := server.Listener.Addr().(*net.TCPAddr).AddrPort()
	for _, fingerprint := range []string{"", "chrome"} {
		for _, automatic := range []bool{false, true} {
			for _, valid := range []bool{false, true} {
				list := block.Bytes
				if !valid {
					list = wrong.Bytes
				}
				ech := &ECHSpec{Config: base64.StdEncoding.EncodeToString(list)}
				var lookups atomic.Int32
				if automatic {
					ech.Config = ""
					ech.QueryServerName = "query.example"
					ech.Lookup = func(ctx context.Context, name string) ([]byte, error) {
						if name != "query.example" {
							return nil, errors.New("ECH query name dropped")
						}
						lookups.Add(1)
						return ResolveECH(ctx, name, func(_ context.Context, q *D.Msg) (*D.Msg, error) {
							reply := new(D.Msg)
							reply.SetReply(q)
							reply.Answer = []D.RR{&D.HTTPS{SVCB: D.SVCB{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeHTTPS, Class: D.ClassINET, Ttl: 30}, Priority: 1, Target: ".", Value: []D.SVCBKeyValue{&D.SVCBECHConfig{ECH: list}}}}}
							return reply, nil
						})
					}
				}
				b := New(Options{Logger: testLogger(t)})
				out, err := b.NewOutbound("ech", ProxySpec{Type: "http", Server: "127.0.0.1", Port: address.Port(), TLS: &TLSSpec{ServerName: "example.com", Fingerprint: fingerprint, CertificatePin: hex.EncodeToString(pin[:]), ECH: ech}})
				if err != nil {
					b.Close()
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				c, err := out.Dial(ctx, "tcp", "198.51.100.1:443")
				cancel()
				if (err == nil) != valid {
					t.Fatalf("fingerprint=%q automatic=%v valid=%v: %v", fingerprint, automatic, valid, err)
				}
				if c != nil {
					c.SetDeadline(time.Now().Add(time.Second))
					c.Write([]byte("encrypted"))
					response := make([]byte, 9)
					if _, err = io.ReadFull(c, response); err != nil || string(response) != "encrypted" {
						t.Fatal(err)
					}
					c.Close()
				}
				if automatic && lookups.Load() != 1 {
					t.Fatal("ECH lookup count", lookups.Load())
				}
				out.Close()
				b.Close()
			}
		}
	}
	if accepted.Load() != 4 {
		t.Fatal("ECH not actually accepted", accepted.Load())
	}
}

func TestECHDNSAliasesAndMissingConfigurationFailClosed(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		calls := 0
		_, err := ResolveECH(context.Background(), "first.test", func(_ context.Context, q *D.Msg) (*D.Msg, error) {
			calls++
			reply := new(D.Msg)
			reply.SetReply(q)
			if cycle {
				reply.Answer = []D.RR{&D.CNAME{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeCNAME}, Target: "first.test."}}
			}
			return reply, nil
		})
		if err == nil || calls > 2 {
			t.Fatal("alias cycle or absent ECH accepted", err, calls)
		}
	}
}

func TestECHServerRetryDoesNotPermanentlyOverrideDNS(t *testing.T) {
	var calls atomic.Int32
	ctx := configureECHContext(context.Background(), &TLSSpec{ECH: &ECHSpec{Lookup: func(context.Context, string) ([]byte, error) { calls.Add(1); return []byte("DNS-config"), nil }}})
	config, err := S.NewClient(ctx, logger.NOP(), "inner.test", option.OutboundTLSOptions{Enabled: true, ECH: &option.OutboundECHOptions{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	config.(S.ECHCapableConfig).SetECHConfigList([]byte("server-retry"))
	first, err := config.STDConfig()
	if err != nil {
		t.Fatal(err)
	}
	second, err := config.STDConfig()
	if err != nil {
		t.Fatal(err)
	}
	if string(first.EncryptedClientHelloConfigList) != "server-retry" || string(second.EncryptedClientHelloConfigList) != "DNS-config" || calls.Load() != 1 {
		t.Fatal("server retry permanently masked DNS updates")
	}
}

func TestECHDNSFollowsCNAMEAndHTTPSAliasRecords(t *testing.T) {
	for _, split := range []bool{false, true} {
		calls := 0
		got, err := ResolveECH(context.Background(), "first.test", func(_ context.Context, q *D.Msg) (*D.Msg, error) {
			calls++
			m := new(D.Msg)
			m.SetReply(q)
			if q.Question[0].Name == "first.test." {
				m.Answer = append(m.Answer, &D.CNAME{Hdr: D.RR_Header{Name: "first.test.", Rrtype: D.TypeCNAME}, Target: "alias.test."})
				if split {
					return m, nil
				}
			}
			m.Answer = append(m.Answer, &D.HTTPS{SVCB: D.SVCB{Hdr: D.RR_Header{Name: "alias.test.", Rrtype: D.TypeHTTPS}, Priority: 0, Target: "final.test."}}, &D.HTTPS{SVCB: D.SVCB{Hdr: D.RR_Header{Name: "final.test.", Rrtype: D.TypeHTTPS}, Priority: 1, Target: ".", Value: []D.SVCBKeyValue{&D.SVCBECHConfig{ECH: []byte("config")}}}})
			return m, nil
		})
		expected := 1
		if split {
			expected = 2
		}
		if err != nil || string(got) != "config" || calls != expected {
			t.Fatal(split, string(got), err, calls)
		}
	}
}
