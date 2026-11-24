package appbridge

import (
	"errors"

	"github.com/MimoProxy/reka/internal/secret"
)

// KeychainStore adapts the host callbacks to a secret store. Read returns the
// number of bytes written, zero for missing, or a negative number on error.
// Write returns true for success, including deletion of a missing item. A nil
// value requests deletion. Callbacks must consume the buffers synchronously.
type KeychainStore struct {
	Read  func(name string, output []byte) int
	Write func(name string, value []byte) bool
}

// Match the existing reader and host Keychain entry limit.
const keychainValueBytes = 16 << 10

var errKeychainUnavailable = errors.New("iOS Keychain unavailable")

func (s KeychainStore) Get(name string) (string, error) {
	output := make([]byte, keychainValueBytes)
	defer clear(output)
	n, err := s.read(name, output)
	if err != nil {
		return "", err
	}
	return string(output[:n]), nil
}

func (s KeychainStore) read(name string, output []byte) (int, error) {
	if s.Read == nil || secret.ValidName(name) != nil {
		return 0, errKeychainUnavailable
	}
	n := s.Read(name, output)
	if n == 0 {
		return 0, secret.ErrNotFound
	}
	if n < 0 || n > len(output) {
		return 0, errors.New("iOS Keychain read failed")
	}
	return n, nil
}

func (s KeychainStore) Set(name, value string) error {
	if s.Write == nil || secret.ValidName(name) != nil {
		return errKeychainUnavailable
	}
	if len(value) == 0 || len(value) > keychainValueBytes {
		return errors.New("invalid iOS Keychain value size")
	}
	data := []byte(value)
	defer clear(data)
	if !s.Write(name, data) {
		return errors.New("iOS Keychain write failed")
	}
	return nil
}

func (s KeychainStore) Delete(name string) error {
	if s.Write == nil {
		return errKeychainUnavailable
	}
	// The writer treats an already absent item as success. Preserve the
	// secret.Store not-found result without constructing a secret string.
	output := make([]byte, keychainValueBytes)
	_, err := s.read(name, output)
	clear(output)
	if err != nil {
		return err
	}
	if !s.Write(name, nil) {
		return errors.New("iOS Keychain delete failed")
	}
	return nil
}

func (KeychainStore) List() ([]string, error) { return nil, errors.ErrUnsupported }
