package ca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/secret"
)

func TestStoreRoundTrip(t *testing.T) {
	store := newTestStore(t)
	if _, err := Load(store); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing CA load = %v", err)
	}
	a := generateCA(t, GenerateOptions{})
	if err := Save(store, a); err != nil {
		t.Fatal(err)
	}
	bundle, err := store.Get(SecretName)
	if err != nil {
		t.Fatal(err)
	}
	certBlock, rest := pem.Decode([]byte(bundle))
	keyBlock, rest := pem.Decode(rest)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("stored CA is not a certificate and PKCS#8 PEM bundle")
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		t.Fatal("stored key is not PKCS#8")
	}
	loaded, err := Load(store)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Info().FingerprintSHA256 != a.Info().FingerprintSHA256 {
		t.Fatal("CA fingerprint changed after storage")
	}
	const host = "stored.example"
	leaf, err := loaded.Issue(host, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: certPool(a.cert)}); err != nil {
		t.Fatal(err)
	}
	if err := Delete(store); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(store); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted CA load = %v", err)
	}
	if err := Delete(store); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing CA delete = %v", err)
	}
}

func TestLoadExpiredAndMismatchedCA(t *testing.T) {
	store := newTestStore(t)
	a := generateCA(t, GenerateOptions{NotAfter: time.Now().Add(-time.Minute)})
	if err := Save(store, a); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(store)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Info().NotAfter.Before(time.Now()) {
		t.Fatal("expired CA is not visible in status")
	}
	issuer := newTestIssuer(t, loaded, IssuerOptions{})
	if _, err := issuer.Certificate("expired.example"); err == nil || issuer.Len() != 0 {
		t.Fatal("expired CA produced a cached leaf")
	}
	a.signer = generateCA(t, GenerateOptions{}).signer
	if err := Save(store, a); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(store); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatal("Load accepted a mismatched private key")
	}
}

func TestStoreErrorsHidePrivateMaterial(t *testing.T) {
	store := leakingStore{}
	a := generateCA(t, GenerateOptions{})
	_, loadErr := Load(store)
	for _, err := range []error{Save(store, a), loadErr, Delete(store)} {
		if err == nil || strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Fatal("storage error included private data or was ignored")
		}
	}
}

func newTestStore(t *testing.T) *secret.FileStore {
	t.Helper()
	store, err := secret.NewFileStore(filepath.Join(t.TempDir(), "secrets.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

type leakingStore struct{ secret.Store }

func (leakingStore) Set(_, value string) error { return fmt.Errorf("write failed with %s", value) }
func (leakingStore) Get(string) (string, error) {
	return "", errors.New("read failed with PRIVATE KEY")
}
func (leakingStore) Delete(string) error { return errors.New("delete failed with PRIVATE KEY") }
