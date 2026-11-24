package secret

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func exercise(t *testing.T, s Store) {
	t.Helper()
	if _, err := s.Get("outbounds/a/password"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	values := map[string]string{
		"outbounds/a/password": "p@ss \"quoted\" 'x' \n newline ü",
		"outbounds/b/uuid":     "b831381d-6324-4d53-ad4f-8cda48b30811",
	}
	for n, v := range values {
		if err := s.Set(n, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Set("outbounds/b/uuid", "replaced"); err != nil {
		t.Fatal(err)
	}
	values["outbounds/b/uuid"] = "replaced"
	for n, v := range values {
		got, err := s.Get(n)
		if err != nil || got != v {
			t.Fatalf("get %s = %q, %v; want %q", n, got, err, v)
		}
	}
	names, err := s.List()
	if err != nil || len(names) != 2 || names[0] != "outbounds/a/password" {
		t.Fatalf("list = %v, %v", names, err)
	}
	for n := range values {
		if err := s.Delete(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Delete("outbounds/a/password"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	if err := s.Set("../escape", "x"); err == nil {
		t.Fatal("invalid name accepted")
	}
}

func TestFileStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "secrets.json")
	s, err := NewFileStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, s)
	if runtime.GOOS != "windows" {
		s.Set("x", "y")
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, %v", fi.Mode(), err)
		}
	}
}

type xorCipher struct{}

func (xorCipher) Seal(p []byte) ([]byte, error) { return xor(p), nil }
func (xorCipher) Open(p []byte) ([]byte, error) { return xor(p), nil }
func xor(p []byte) []byte {
	out := make([]byte, len(p))
	for i, b := range p {
		out[i] = b ^ 0x5a
	}
	return out
}

func TestHostStoreEncrypts(t *testing.T) {
	root := t.TempDir()
	s, err := NewHostStore(root, CallbackCipher{SealFunc: xorCipher{}.Seal, OpenFunc: xorCipher{}.Open})
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, s)
	s.Set("k", "plain-value-here")
	b, _ := os.ReadFile(filepath.Join(root, "secrets", "secrets.json"))
	if bytes.Contains(b, []byte("plain-value-here")) {
		t.Fatal("value stored in plain text")
	}
}

func TestDefaultStore(t *testing.T) {
	if runtime.GOOS == "darwin" && os.Getenv("REKA_TEST_KEYCHAIN") == "" {
		t.Skip("set REKA_TEST_KEYCHAIN=1 to write test items to the login keychain")
	}
	s, err := Default(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, s)
}

func TestRef(t *testing.T) {
	if n, ok := ParseRef(Ref("outbounds/x/uuid")); !ok || n != "outbounds/x/uuid" {
		t.Fatal(n, ok)
	}
}

func TestReserved(t *testing.T) {
	for _, name := range []string{"mitm/ca", "mitm/other", "mitm/nested/entry"} {
		if !Reserved(name) {
			t.Errorf("Reserved(%q) = false", name)
		}
	}
	for _, name := range []string{"mitm", "mitm-other/ca", "outbounds/mitm/password"} {
		if Reserved(name) {
			t.Errorf("Reserved(%q) = true", name)
		}
	}
}
