package sagernet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testClientCertificate(t *testing.T) (string, string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "reka-client"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), cert
}
func TestClientCertificateRequiresMatchingMutualTLSIdentity(t *testing.T) {
	cert, key, leaf := testClientCertificate(t)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		io.Copy(c, c)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	for _, browser := range []string{"", "chrome"} {
		for _, identity := range []bool{false, true} {
			spec := &TLSSpec{ServerName: "localhost", Insecure: true, Fingerprint: browser}
			if identity {
				spec.Certificate, spec.PrivateKey = cert, key
			}
			b := New(Options{Logger: testLogger(t)})
			out, err := b.NewOutbound("mtls", ProxySpec{Type: "http", Server: "127.0.0.1", Port: server.Listener.Addr().(*net.TCPAddr).AddrPort().Port(), TLS: spec})
			if err != nil {
				b.Close()
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			c, err := out.Dial(ctx, "tcp", "198.51.100.1:443")
			cancel()
			if !identity {
				if err == nil {
					c.Close()
					t.Fatal("missing client identity accepted")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				c.SetDeadline(time.Now().Add(3 * time.Second))
				c.Write([]byte("mtls"))
				p := make([]byte, 4)
				if _, err = io.ReadFull(c, p); err != nil || string(p) != "mtls" {
					t.Fatal(err)
				}
				c.Close()
			}
			out.Close()
			b.Close()
		}
	}
}
