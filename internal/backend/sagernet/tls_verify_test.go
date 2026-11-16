package sagernet

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

func TestTLSCertificatePinIsFullCertificateAndFailClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		io.Copy(c, c)
	}))
	defer server.Close()
	pin := sha256.Sum256(server.TLS.Certificates[0].Certificate[0])
	spki := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	address := server.Listener.Addr().(*net.TCPAddr).AddrPort()
	for _, fingerprint := range []string{"", "chrome"} {
		for _, valid := range []bool{false, true} {
			digest := hex.EncodeToString(pin[:])
			if !valid {
				digest = hex.EncodeToString(spki[:])
			}
			b := New(Options{Logger: testLogger(t)})
			out, err := b.NewOutbound("pin", ProxySpec{Type: "http", Server: "127.0.0.1", Port: address.Port(), TLS: &TLSSpec{CertificatePin: digest, ServerName: "unrelated.test", Fingerprint: fingerprint}})
			if err != nil {
				b.Close()
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			c, err := out.Dial(ctx, "tcp", "198.51.100.1:443")
			cancel()
			if !valid {
				if err == nil {
					c.Close()
					t.Fatal("SPKI digest accepted as whole certificate pin")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				c.SetDeadline(time.Now().Add(3 * time.Second))
				c.Write([]byte("pin"))
				reply := make([]byte, 3)
				if _, err = io.ReadFull(c, reply); err != nil || string(reply) != "pin" {
					t.Fatal(err, string(reply))
				}
				c.Close()
			}
			out.Close()
			b.Close()
		}
	}
}
func TestTLSAlternateVerificationNamePreservesSNIAndTrust(t *testing.T) {
	seen := make(chan string, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	server.TLS = &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) { seen <- info.ServerName; return nil, nil }}
	server.StartTLS()
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	for _, browser := range []bool{false, true} {
		for _, valid := range []bool{false, true} {
			name := "example.com"
			if !valid {
				name = "wrong.test"
			}
			ctx, configured := configureTLSContext(context.Background(), &TLSSpec{VerifyName: name})
			hook := ctx.Value("reka.tls.configure.v1").(func(any) error)
			raw, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			raw.SetDeadline(time.Now().Add(3 * time.Second))
			if browser {
				config := &utls.Config{ServerName: "front.test", RootCAs: pool}
				if err = hook(config); err != nil {
					t.Fatal(err)
				}
				c := utls.UClient(raw, config, utls.HelloChrome_Auto)
				err = c.Handshake()
				c.Close()
			} else {
				config := &tls.Config{ServerName: "front.test", RootCAs: pool}
				if err = hook(config); err != nil {
					t.Fatal(err)
				}
				c := tls.Client(raw, config)
				err = c.Handshake()
				c.Close()
			}
			if (err == nil) != valid || !configured.Load() {
				t.Fatal(browser, valid, err)
			}
			if sni := <-seen; sni != "front.test" {
				t.Fatal("SNI changed by verification name", sni)
			}
		}
	}
}
