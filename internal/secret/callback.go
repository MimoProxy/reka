package secret

import "path/filepath"

// CallbackCipher adapts host-provided functions, such as Android Keystore
// encryption supplied through the library binding, to Cipher.
type CallbackCipher struct {
	SealFunc func([]byte) ([]byte, error)
	OpenFunc func([]byte) ([]byte, error)
}

func (c CallbackCipher) Seal(p []byte) ([]byte, error) { return c.SealFunc(p) }
func (c CallbackCipher) Open(p []byte) ([]byte, error) { return c.OpenFunc(p) }

// NewHostStore is the Android store: a file under the app's private state
// root, each entry encrypted by the host's cipher.
func NewHostStore(stateRoot string, c Cipher) (*FileStore, error) {
	return NewFileStore(filepath.Join(stateRoot, "secrets", "secrets.json"), c)
}
