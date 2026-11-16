package sagernet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	utls "github.com/metacubex/utls"
)

func configureTLSContext(ctx context.Context, s *TLSSpec) (context.Context, *atomic.Bool) {
	if s == nil || s.CertificatePin == "" && s.VerifyName == "" {
		return ctx, nil
	}
	configured := &atomic.Bool{}
	hook := func(value any) error {
		verify := func(certs []*x509.Certificate, serverName string, roots *x509.CertPool, now func() time.Time) error {
			if len(certs) == 0 {
				return errors.New("TLS peer supplied no certificate")
			}
			if s.VerifyName != "" {
				serverName = s.VerifyName
			}
			intermediates := x509.NewCertPool()
			for _, cert := range certs[1:] {
				intermediates.AddCert(cert)
			}
			options := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: serverName}
			if now != nil {
				options.CurrentTime = now()
			}
			if s.CertificatePin != "" {
				pin, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s.CertificatePin), ":", ""))
				if err != nil || len(pin) != 32 {
					return errors.New("invalid TLS certificate SHA256 pin")
				}
				for i, cert := range certs {
					sum := sha256.Sum256(cert.Raw)
					if bytes.Equal(pin, sum[:]) {
						if i == 0 {
							return nil
						}
						options.Roots = x509.NewCertPool()
						options.Roots.AddCert(cert)
						options.Intermediates = x509.NewCertPool()
						for _, chain := range certs[1 : i+1] {
							options.Intermediates.AddCert(chain)
						}
						_, err = certs[0].Verify(options)
						return err
					}
				}
				return errors.New("TLS certificate SHA256 pin mismatch")
			}
			_, err := certs[0].Verify(options)
			return err
		}
		switch config := value.(type) {
		case *tls.Config:
			config.InsecureSkipVerify = true
			config.VerifyConnection = nil
			config.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
				certs, err := parsePeerCertificates(raw)
				if err != nil {
					return err
				}
				return verify(certs, config.ServerName, config.RootCAs, config.Time)
			}
		case *utls.Config:
			config.InsecureSkipVerify = true
			config.VerifyConnection = func(state utls.ConnectionState) error {
				return verify(state.PeerCertificates, state.ServerName, config.RootCAs, config.Time)
			}
		default:
			return errors.New("unsupported TLS configuration for certificate verification")
		}
		configured.Store(true)
		return nil
	}
	// The key and function signature are the pinned component overlay contract.
	return context.WithValue(ctx, "reka.tls.configure.v1", hook), configured
}

func parsePeerCertificates(raw [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(raw))
	for i, b := range raw {
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, err
		}
		certs[i] = cert
	}
	return certs, nil
}
