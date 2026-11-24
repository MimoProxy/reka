// Package ca manages the local CA and issues certificates for TLS interception.
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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

const clockSkew = time.Hour

var oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

// Authority is a CA certificate with its signing key. The key never leaves
// the package except through the secret store.
type Authority struct {
	cert   *x509.Certificate
	signer crypto.Signer
}

// GenerateOptions overrides the defaults of Generate.
type GenerateOptions struct {
	CommonName string
	NotAfter   time.Time
}

// Info describes the CA certificate for display.
type Info struct {
	Subject           string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
	KeyType           string
	SerialNumber      string
}

// Generate creates a self-signed ECDSA P-256 root. The defaults (a per-device
// name, ten years like mitmproxy, critical basic constraints and key usage)
// satisfy what iOS needs to fully trust a manually installed root.
func Generate(opts GenerateOptions) (*Authority, error) {
	now := time.Now().UTC()
	if opts.CommonName == "" {
		var suffix [4]byte
		rand.Read(suffix[:])
		opts.CommonName = "Mimo Reka CA " + hex.EncodeToString(suffix[:])
	}
	if opts.NotAfter.IsZero() {
		opts.NotAfter = now.AddDate(10, 0, 0)
	}
	notBefore := now.Add(-clockSkew)
	if !opts.NotAfter.After(notBefore) {
		return nil, errors.New("CA expiration must be after its start time")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("could not generate CA key")
	}
	publicKey, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, errors.New("could not encode CA public key")
	}
	// Set the SHA-1 key identifier explicitly because Go defaults to SHA-256.
	subjectKeyID := sha1.Sum(publicKey)
	cert := &x509.Certificate{
		SerialNumber: newSerialNumber(),
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{"Mimo Reka"},
		},
		NotBefore:             notBefore,
		NotAfter:              opts.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          subjectKeyID[:],
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		return nil, errors.New("could not create CA certificate")
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("could not parse generated CA certificate")
	}
	return &Authority{cert: parsed, signer: key}, nil
}

// ImportPKCS12 decodes a CA and its key, for example one exported from
// another proxy app. RSA and ECDSA keys are accepted; leaves are always ECDSA.
func ImportPKCS12(data []byte, password string, now time.Time) (*Authority, error) {
	key, cert, _, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		switch {
		case errors.Is(err, pkcs12.ErrIncorrectPassword), errors.Is(err, pkcs12.ErrDecryption):
			return nil, errors.New("incorrect PKCS#12 password")
		// The decoder does not export errors for missing bags.
		case err.Error() == "pkcs12: certificate missing":
			return nil, errors.New("PKCS#12 has no certificate")
		case err.Error() == "pkcs12: private key missing":
			return nil, errors.New("PKCS#12 has no private key")
		default:
			return nil, errors.New("invalid or unsupported PKCS#12 data")
		}
	}
	a, err := validateAuthority(cert, key)
	if err != nil {
		return nil, err
	}
	if now.Before(cert.NotBefore) {
		return nil, errors.New("CA certificate is not yet valid")
	}
	if now.After(cert.NotAfter) {
		return nil, errors.New("CA certificate has expired")
	}
	return a, nil
}

func validateAuthority(cert *x509.Certificate, key any) (*Authority, error) {
	if cert == nil {
		return nil, errors.New("CA certificate is missing")
	}
	if key == nil {
		return nil, errors.New("CA private key is missing")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return nil, errors.New("certificate is not a CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		for _, extension := range cert.Extensions {
			if extension.Id.Equal(oidKeyUsage) {
				return nil, errors.New("CA key usage does not permit certificate signing")
			}
		}
	}
	var signer crypto.Signer
	var matches bool
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() {
			return nil, errors.New("CA ECDSA key must use P-256 or P-384")
		}
		signer = key
		matches = key.PublicKey.Equal(cert.PublicKey)
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 {
			return nil, errors.New("CA RSA key must be at least 2048 bits")
		}
		signer = key
		matches = key.PublicKey.Equal(cert.PublicKey)
	default:
		return nil, errors.New("CA private key must be ECDSA or RSA")
	}
	if !matches {
		return nil, errors.New("CA private key does not match the certificate")
	}
	return &Authority{cert: cert, signer: signer}, nil
}

// CertificatePEM returns the public certificate only.
func (a *Authority) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})
}

// CertificateDER returns the public certificate only.
func (a *Authority) CertificateDER() []byte { return bytes.Clone(a.cert.Raw) }

func (a *Authority) Info() Info {
	digest := sha256.Sum256(a.cert.Raw)
	var fingerprint strings.Builder
	fingerprint.Grow(3*len(digest) - 1)
	for i, b := range digest {
		if i > 0 {
			fingerprint.WriteByte(':')
		}
		fmt.Fprintf(&fingerprint, "%02X", b)
	}
	var keyType string
	switch key := a.cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		keyType = "ECDSA " + key.Curve.Params().Name
	case *rsa.PublicKey:
		keyType = fmt.Sprintf("RSA %d", key.N.BitLen())
	}
	return Info{
		Subject:           a.cert.Subject.CommonName,
		FingerprintSHA256: fingerprint.String(),
		NotBefore:         a.cert.NotBefore,
		NotAfter:          a.cert.NotAfter,
		KeyType:           keyType,
		SerialNumber:      a.cert.SerialNumber.Text(16),
	}
}

func newSerialNumber() *big.Int {
	var raw [16]byte
	serial := new(big.Int)
	for serial.Sign() == 0 {
		rand.Read(raw[:])
		serial.SetBytes(raw[:])
	}
	return serial
}
