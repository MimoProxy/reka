// Package resource stores immutable, private subscription documents by hash.
package resource

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/MimoProxy/reka/internal/secret"
)

const MaxSize = 16 << 20

var hashRE = regexp.MustCompile(`^[a-f0-9]{64}$`)
var ErrCorrupt = errors.New("resource: missing, oversized or corrupt blob")

type Store struct{ dir string }

func At(root string) *Store { return &Store{dir: filepath.Join(root, "resources", "sha256")} }
func Open(root string) (*Store, error) {
	dir := At(root).dir
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &Store{dir}, nil
}
func Hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func ValidHash(s string) bool { return hashRE.MatchString(s) }
func (s *Store) Read(hash string) ([]byte, error) {
	if !ValidHash(hash) {
		return nil, ErrCorrupt
	}
	path := filepath.Join(s.dir, hash)
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrCorrupt
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxSize {
		return nil, ErrCorrupt
	}
	data := make([]byte, info.Size())
	n := 0
	for n < len(data) {
		count, e := f.Read(data[n:])
		n += count
		if e != nil && n < len(data) {
			return nil, ErrCorrupt
		}
	}
	if Hash(data) != hash {
		return nil, ErrCorrupt
	}
	return data, nil
}
func (s *Store) Put(data []byte) (string, error) {
	if len(data) > MaxSize {
		return "", ErrCorrupt
	}
	hash := Hash(data)
	path := filepath.Join(s.dir, hash)
	if _, err := os.Stat(path); err == nil {
		_, err = s.Read(hash)
		return hash, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := secret.WriteFileAtomic(path, data, 0600); err != nil {
		return "", err
	}
	return hash, nil
}
