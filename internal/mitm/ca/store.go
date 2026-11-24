package ca

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/MimoProxy/reka/internal/secret"
)

// SecretName holds the CA as a PEM certificate followed by a PKCS#8 key.
// Configurations reference it as secret://mitm/ca but cannot resolve it.
const SecretName = "mitm/ca"

// ErrNotFound reports that no CA is stored.
var ErrNotFound = secret.ErrNotFound

// Save stores the CA and its key in the secret store.
func Save(store secret.Store, a *Authority) error {
	bundle, err := a.marshalBundle()
	if err != nil {
		return err
	}
	if err := store.Set(SecretName, bundle); err != nil {
		// A backend error may include the value supplied to it.
		return errors.New("could not save MITM CA")
	}
	return nil
}

// Load reads and validates the stored CA. An expired CA still loads so
// clients can show it; issuing from it fails.
func Load(store secret.Store) (*Authority, error) {
	bundle, err := store.Get(SecretName)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, errors.New("could not load MITM CA")
	}
	certBlock, rest := pem.Decode([]byte(bundle))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("stored MITM CA certificate is missing")
	}
	keyBlock, rest := pem.Decode(rest)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, errors.New("stored MITM CA private key is missing")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("stored MITM CA bundle has unexpected data")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errors.New("stored MITM CA certificate is invalid")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, errors.New("stored MITM CA private key is invalid")
	}
	a, err := validateAuthority(cert, key)
	if err != nil {
		return nil, err
	}
	if time.Now().Before(cert.NotBefore) {
		return nil, errors.New("CA certificate is not yet valid")
	}
	return a, nil
}

// Delete removes the stored CA.
func Delete(store secret.Store) error {
	err := store.Delete(SecretName)
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return errors.New("could not delete MITM CA")
	}
	return nil
}

func (a *Authority) marshalBundle() (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(a.signer)
	if err != nil {
		return "", errors.New("could not encode MITM CA private key")
	}
	return string(append(a.CertificatePEM(), pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})...)), nil
}
