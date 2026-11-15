//go:build !darwin && !windows

package secret

import "path/filepath"

// On Linux (and Android when the host does not supply a cipher) secrets
// live in a 0600 file under the state root.
func platformDefault(stateRoot string) (Store, error) {
	return NewFileStore(filepath.Join(stateRoot, "secrets", "secrets.json"), nil)
}
