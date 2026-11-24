package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"net"
	"slices"
	"testing"
	"time"
)

func TestIssuerCertificate(t *testing.T) {
	a := generateCA(t, GenerateOptions{})
	roots := certPool(a.cert)
	unrelatedRoots := certPool(generateCA(t, GenerateOptions{}).cert)
	now := time.Now().Truncate(time.Second)
	issuer := newTestIssuer(t, a, IssuerOptions{Now: func() time.Time { return now }})
	for _, tc := range []struct {
		requested string
		host      string
		isIP      bool
	}{
		{"MiXeD.example.", "mixed.example", false},
		{"192.0.2.10", "192.0.2.10", true},
		{"[2001:0DB8:0000::10]", "2001:db8::10", true},
	} {
		t.Run(tc.requested, func(t *testing.T) {
			cert := issueCertificate(t, issuer, tc.requested)
			if fromNormalized := issueCertificate(t, issuer, tc.host); fromNormalized != cert {
				t.Fatal("normalized hostname did not reuse the certificate")
			}
			leaf := cert.Leaf
			if leaf == nil || len(cert.Certificate) != 2 || !bytes.Equal(cert.Certificate[0], leaf.Raw) ||
				!bytes.Equal(cert.Certificate[1], a.CertificateDER()) {
				t.Fatal("expected the leaf and CA certificate in the TLS chain")
			}
			if leaf.Subject.CommonName != tc.host || leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() > 128 ||
				leaf.KeyUsage != x509.KeyUsageDigitalSignature || !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) ||
				!bytes.Equal(leaf.AuthorityKeyId, a.cert.SubjectKeyId) || leaf.PublicKey.(*ecdsa.PublicKey).Curve != elliptic.P256() {
				t.Fatal("unexpected leaf certificate fields")
			}
			if !leaf.NotBefore.Equal(now.Add(-time.Hour)) || !leaf.NotAfter.Equal(now.Add(7*24*time.Hour)) {
				t.Fatalf("unexpected leaf validity %v to %v", leaf.NotBefore, leaf.NotAfter)
			}
			if tc.isIP {
				if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != tc.host || len(leaf.DNSNames) != 0 {
					t.Fatal("expected a single IP SAN")
				}
			} else if !slices.Equal(leaf.DNSNames, []string{tc.host}) || len(leaf.IPAddresses) != 0 {
				t.Fatal("expected a single DNS SAN")
			}
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: tc.host, Roots: roots}); err != nil {
				t.Fatal(err)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: tc.host, Roots: unrelatedRoots}); err == nil {
				t.Fatal("unrelated CA validated the leaf")
			}
		})
	}
}

func TestIssuerTLSHandshake(t *testing.T) {
	a := generateCA(t, GenerateOptions{})
	issuer := newTestIssuer(t, a, IssuerOptions{})
	if _, err := issuer.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("GetCertificate accepted an empty SNI")
	}
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	const host = "handshake.example"
	server := tls.Server(serverConn, &tls.Config{GetCertificate: issuer.GetCertificate})
	client := tls.Client(clientConn, &tls.Config{RootCAs: certPool(a.cert), ServerName: host})
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if verified := client.ConnectionState().VerifiedChains; len(verified) != 1 || len(verified[0]) != 2 {
		t.Fatal("client did not verify the leaf and CA chain")
	}
}

func TestIssuerCapsValidity(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	expires := now.Add(3 * time.Hour)
	const name = "Session CA"
	a := generateCA(t, GenerateOptions{CommonName: name, NotAfter: expires})
	if info := a.Info(); info.Subject != name || !info.NotAfter.Equal(expires) {
		t.Fatalf("generation ignored overrides: %+v", info)
	}
	issuer := newTestIssuer(t, a, IssuerOptions{Now: func() time.Time { return now }})
	cert := issueCertificate(t, issuer, "limited.example")
	if !cert.Leaf.NotAfter.Equal(expires) {
		t.Fatalf("leaf expires at %v, want %v", cert.Leaf.NotAfter, expires)
	}
}

func TestIssuerRefreshesExpiringLeaf(t *testing.T) {
	a := generateCA(t, GenerateOptions{})
	now := time.Now().Truncate(time.Second)
	validity := 8 * time.Hour
	issuer := newTestIssuer(t, a, IssuerOptions{Validity: validity, Now: func() time.Time { return now }})
	const host = "refresh.example"
	first := issueCertificate(t, issuer, host)
	now = now.Add(6 * time.Hour)
	if got := issueCertificate(t, issuer, host); got != first {
		t.Fatal("leaf was refreshed before the threshold")
	}
	now = now.Add(time.Second)
	refreshed := issueCertificate(t, issuer, host)
	if refreshed.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 || !refreshed.Leaf.NotAfter.Equal(now.Add(validity)) {
		t.Fatal("expiring leaf was not replaced")
	}
}

func TestIssuerEvictsLeastRecentlyUsed(t *testing.T) {
	issuer := newTestIssuer(t, generateCA(t, GenerateOptions{}), IssuerOptions{CacheSize: 2})
	a := issueCertificate(t, issuer, "a.example")
	b := issueCertificate(t, issuer, "b.example")
	issueCertificate(t, issuer, "a.example")
	issueCertificate(t, issuer, "c.example")
	if issuer.Len() != 2 || issueCertificate(t, issuer, "a.example") != a {
		t.Fatal("recently used certificate was not retained")
	}
	if issueCertificate(t, issuer, "b.example") == b {
		t.Fatal("least recently used certificate was not evicted")
	}
}

func TestIssuerPurge(t *testing.T) {
	a := generateCA(t, GenerateOptions{})
	first := newTestIssuer(t, a, IssuerOptions{})
	second := newTestIssuer(t, a, IssuerOptions{})
	const host = "purge.example"
	issueCertificate(t, first, host)
	issueCertificate(t, second, host)
	first.Purge()
	if first.Len() != 0 || second.Len() != 1 {
		t.Fatal("Purge must clear only the receiver")
	}
	issueCertificate(t, first, host)
	PurgeAll()
	if first.Len() != 0 || second.Len() != 0 {
		t.Fatal("PurgeAll did not clear the registered issuers")
	}
	issueCertificate(t, first, host)
	first.Close()
	PurgeAll()
	if first.Len() != 1 {
		t.Fatal("PurgeAll touched an unregistered issuer")
	}
}

func TestIssuerConcurrentSigning(t *testing.T) {
	issuer := newTestIssuer(t, generateCA(t, GenerateOptions{}), IssuerOptions{})
	const callers = 64
	type result struct {
		cert *tls.Certificate
		err  error
	}
	start := make(chan struct{})
	results := make(chan result, callers)
	for range callers {
		go func() {
			<-start
			cert, err := issuer.Certificate("concurrent.example")
			results <- result{cert, err}
		}()
	}
	close(start)
	var serial string
	for range callers {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if got := result.cert.Leaf.SerialNumber.Text(16); serial == "" {
			serial = got
		} else if got != serial {
			t.Fatalf("concurrent certificate serial = %s, want %s", got, serial)
		}
	}
	if issuer.Len() != 1 {
		t.Fatalf("cached %d certificates, want 1", issuer.Len())
	}
}

func newTestIssuer(t *testing.T, a *Authority, opts IssuerOptions) *Issuer {
	t.Helper()
	issuer := NewIssuer(a, opts)
	t.Cleanup(issuer.Close)
	return issuer
}

func issueCertificate(t *testing.T, issuer *Issuer, host string) *tls.Certificate {
	t.Helper()
	cert, err := issuer.Certificate(host)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func certPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
