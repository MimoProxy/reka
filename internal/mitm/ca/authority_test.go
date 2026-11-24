package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func TestGenerate(t *testing.T) {
	before := time.Now().UTC().Truncate(time.Second)
	a := generateCA(t, GenerateOptions{})
	after := time.Now().UTC()
	der := a.CertificateDER()
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^Mimo Reka CA [0-9a-f]{8}$`).MatchString(root.Subject.CommonName) ||
		!slices.Equal(root.Subject.Organization, []string{"Mimo Reka"}) {
		t.Fatalf("unexpected CA subject: %v", root.Subject)
	}
	if !root.BasicConstraintsValid || !root.IsCA || !root.MaxPathLenZero || root.MaxPathLen != 0 {
		t.Fatal("invalid CA basic constraints")
	}
	const wantUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	if root.KeyUsage != wantUsage {
		t.Fatalf("CA key usage = %v, want %v", root.KeyUsage, wantUsage)
	}
	for _, oid := range []asn1.ObjectIdentifier{{2, 5, 29, 19}, {2, 5, 29, 15}} {
		if !slices.ContainsFunc(root.Extensions, func(ext pkix.Extension) bool {
			return ext.Id.Equal(oid) && ext.Critical
		}) {
			t.Fatalf("missing critical extension %v", oid)
		}
	}
	pub, ok := root.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || root.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("CA public key = %T, signature algorithm = %v", root.PublicKey, root.SignatureAlgorithm)
	}
	pubBytes, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	wantSKI := sha1.Sum(pubBytes)
	if !bytes.Equal(root.SubjectKeyId, wantSKI[:]) {
		t.Fatalf("CA subject key identifier = %x, want %x", root.SubjectKeyId, wantSKI)
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatal(err)
	}
	if root.NotBefore.Before(before.Add(-time.Hour)) || root.NotBefore.After(after.Add(-time.Hour)) ||
		root.NotAfter.Before(before.AddDate(10, 0, 0)) || root.NotAfter.After(after.AddDate(10, 0, 0)) {
		t.Fatalf("unexpected CA validity %v to %v", root.NotBefore, root.NotAfter)
	}
	if root.SerialNumber.Sign() <= 0 || root.SerialNumber.BitLen() > 128 {
		t.Fatalf("unexpected CA serial %v", root.SerialNumber)
	}
	info := a.Info()
	wantFingerprint := strings.ReplaceAll(fmt.Sprintf("% X", sha256.Sum256(der)), " ", ":")
	if info.FingerprintSHA256 != wantFingerprint || info.KeyType != "ECDSA P-256" ||
		info.Subject != root.Subject.CommonName || info.SerialNumber != root.SerialNumber.Text(16) ||
		!info.NotBefore.Equal(root.NotBefore) || !info.NotAfter.Equal(root.NotAfter) {
		t.Fatalf("unexpected CA info: %+v", info)
	}
	pemBlock, rest := pem.Decode(a.CertificatePEM())
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" || len(rest) != 0 || !bytes.Equal(pemBlock.Bytes, der) {
		t.Fatal("PEM must contain only the CA certificate")
	}
	der[0] ^= 1
	if !bytes.Equal(a.CertificateDER(), pemBlock.Bytes) {
		t.Fatal("exported DER aliases CA data")
	}
}

func TestImportPKCS12(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	ecdsaCA := generateCA(t, GenerateOptions{})
	key384 := generateECKey(t, elliptic.P384())
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		encoder *pkcs12.Encoder
		key     crypto.Signer
		cert    *x509.Certificate
		keyType string
	}{
		{"modern ECDSA", pkcs12.Modern, ecdsaCA.signer, ecdsaCA.cert, "ECDSA P-256"},
		{"ECDSA P-384 without key usage", pkcs12.Modern, key384,
			selfSigned(t, key384, true, 0, now), "ECDSA P-384"},
		{"legacy RSA", pkcs12.Legacy, rsaKey,
			selfSigned(t, rsaKey, true, x509.KeyUsageCertSign, now), "RSA 2048"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const password = "import-test-password"
			data, err := tc.encoder.Encode(tc.key, tc.cert, nil, password)
			if err != nil {
				t.Fatal(err)
			}
			a, err := ImportPKCS12(data, password, now)
			if err != nil {
				t.Fatal(err)
			}
			if a.Info().KeyType != tc.keyType || !bytes.Equal(a.CertificateDER(), tc.cert.Raw) {
				t.Fatalf("unexpected imported CA info: %+v", a.Info())
			}
			const host = "import.example"
			leaf, err := a.Issue(host, now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			pub, ok := leaf.Leaf.PublicKey.(*ecdsa.PublicKey)
			if !ok || pub.Curve != elliptic.P256() {
				t.Fatalf("leaf key = %T, want ECDSA P-256", leaf.Leaf.PublicKey)
			}
			if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: certPool(tc.cert)}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestImportPKCS12RejectsInvalidCA(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key := generateECKey(t, elliptic.P256())
	otherKey := generateECKey(t, elliptic.P256())
	unsupportedKey := generateECKey(t, elliptic.P521())
	root := selfSigned(t, key, true, x509.KeyUsageCertSign, now)
	const password = "import-test-password"
	for _, tc := range []struct {
		name     string
		key      crypto.Signer
		cert     *x509.Certificate
		password string
		want     string
	}{
		{"wrong password", key, root, "wrong-test-password", "incorrect PKCS#12 password"},
		{"invalid data", nil, nil, password, "invalid or unsupported PKCS#12 data"},
		{"not a CA", key, selfSigned(t, key, false, x509.KeyUsageDigitalSignature, now), password, "not a CA"},
		{"no certSign usage", key, selfSigned(t, key, true, x509.KeyUsageDigitalSignature, now), password, "does not permit certificate signing"},
		{"mismatched key", otherKey, root, password, "does not match"},
		{"expired", key, selfSigned(t, key, true, x509.KeyUsageCertSign, now.Add(-2*time.Hour)), password, "expired"},
		{"not yet valid", key, selfSigned(t, key, true, x509.KeyUsageCertSign, now.Add(2*time.Hour)), password, "not yet valid"},
		{"unsupported curve", unsupportedKey, selfSigned(t, unsupportedKey, true, x509.KeyUsageCertSign, now), password, "P-256 or P-384"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("not a PKCS#12 file")
			if tc.cert != nil {
				var err error
				data, err = pkcs12.Modern.Encode(tc.key, tc.cert, nil, password)
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err := ImportPKCS12(data, tc.password, now)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), tc.password) {
				t.Fatal("unexpected import result")
			}
		})
	}
	t.Run("missing private key", func(t *testing.T) {
		data, err := pkcs12.Modern.EncodeTrustStore([]*x509.Certificate{root}, password)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ImportPKCS12(data, password, now); err == nil || !strings.Contains(err.Error(), "no private key") {
			t.Fatal("trust store accepted as a signing identity")
		}
	})
}

func generateCA(t *testing.T, opts GenerateOptions) *Authority {
	t.Helper()
	a, err := Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func generateECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func selfSigned(t *testing.T, key crypto.Signer, isCA bool, usage x509.KeyUsage, center time.Time) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test certificate"},
		NotBefore:             center.Add(-time.Hour),
		NotAfter:              center.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
