//go:build darwin

package secret

func platformDefault(stateRoot string) (Store, error) { return NewKeychain(stateRoot) }
