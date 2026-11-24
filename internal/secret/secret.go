// Package secret stores credentials referenced from configuration as
// "secret://<name>". Backends: the macOS Keychain, Windows DPAPI, a host
// callback on Android, and a 0600 file elsewhere (and in tests).
package secret

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// ErrNotFound is returned by Get for a name that is not stored.
var ErrNotFound = errors.New("secret: not found")

// Store holds named secrets.
type Store interface {
	Get(name string) (string, error)
	Set(name, value string) error
	Delete(name string) error
	// List returns the stored names, sorted. Never the values.
	List() ([]string, error)
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)

// ValidName checks a secret name: slash-separated segments of letters,
// digits, ".", "_" and "-", without "." or ".." segments.
func ValidName(name string) error {
	if len(name) > 256 || !nameRE.MatchString(name) {
		return fmt.Errorf("secret: invalid name %q", name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("secret: invalid name %q", name)
		}
	}
	return nil
}

// Reserved reports whether only a dedicated API may manage the name.
// Reject references in configurations, subscriptions, and modules so they
// cannot send a CA private key to a remote server as a credential.
func Reserved(name string) bool { return strings.HasPrefix(name, "mitm/") }

// Ref returns the configuration reference for name.
func Ref(name string) string { return "secret://" + name }

// ParseRef returns the name in a "secret://" reference.
func ParseRef(v string) (string, bool) {
	name, ok := strings.CutPrefix(v, "secret://")
	return name, ok
}

// Cipher encrypts secrets at rest for a file-backed store.
type Cipher interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(ciphertext []byte) ([]byte, error)
}

// FileStore keeps secrets in one JSON file with mode 0600, optionally
// encrypted entry by entry with a Cipher.
type FileStore struct {
	path   string
	cipher Cipher
	mu     sync.Mutex
}

// NewFileStore uses path for storage; its directory is created 0700.
func NewFileStore(path string, cipher Cipher) (*FileStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &FileStore{path: path, cipher: cipher}, nil
}

type fileData struct {
	Version int               `json:"version"`
	Entries map[string]string `json:"entries"` // base64 of the (sealed) value
}

// Path is the backing file.
func (s *FileStore) Path() string { return s.path }

func (s *FileStore) load() (fileData, error) {
	d := fileData{Version: 1, Entries: map[string]string{}}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, fmt.Errorf("secret: %s: %w", s.path, err)
	}
	if d.Entries == nil {
		d.Entries = map[string]string{}
	}
	return d, nil
}

func (s *FileStore) save(d fileData) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.path, b, 0o600)
}

func (s *FileStore) Get(name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		return "", err
	}
	enc, ok := d.Entries[name]
	if !ok {
		return "", ErrNotFound
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("secret: %s: %w", name, err)
	}
	if s.cipher != nil {
		if raw, err = s.cipher.Open(raw); err != nil {
			return "", fmt.Errorf("secret: decrypt %s: %w", name, err)
		}
	}
	return string(raw), nil
}

func (s *FileStore) Set(name, value string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	raw := []byte(value)
	if s.cipher != nil {
		var err error
		if raw, err = s.cipher.Seal(raw); err != nil {
			return fmt.Errorf("secret: encrypt %s: %w", name, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		return err
	}
	d.Entries[name] = base64.StdEncoding.EncodeToString(raw)
	return s.save(d)
}

func (s *FileStore) Delete(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := d.Entries[name]; !ok {
		return ErrNotFound
	}
	delete(d.Entries, name)
	return s.save(d)
}

func (s *FileStore) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(d.Entries))
	for n := range d.Entries {
		names = append(names, n)
	}
	slices.Sort(names)
	return names, nil
}

// WriteFileAtomic writes data to a temporary file in the same directory,
// syncs it, renames it over path and syncs the directory.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil && !isChmodUnsupported(err) {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return SyncDir(dir)
}

// SyncDir makes a rename in dir durable. It is a no-op where directories
// cannot be synced (Windows).
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !isSyncDirUnsupported(err) {
		return err
	}
	return nil
}

// Default returns the platform's store for a state root.
func Default(stateRoot string) (Store, error) { return platformDefault(stateRoot) }
