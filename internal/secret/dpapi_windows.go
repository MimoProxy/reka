//go:build windows

package secret

import (
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPI encrypts with the Windows Data Protection API, bound to the
// current user (or to the machine when the service runs as LocalSystem).
type DPAPI struct{}

var dpapiEntropy = []byte("reka secret store v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(out *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

func (DPAPI) Seal(plaintext []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(plaintext), nil, blob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

func (DPAPI) Open(ciphertext []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(ciphertext), nil, blob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

func platformDefault(stateRoot string) (Store, error) {
	return NewFileStore(filepath.Join(stateRoot, "secrets", "secrets.json"), DPAPI{})
}
