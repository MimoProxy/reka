//go:build darwin

package secret

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// Keychain stores secrets as generic passwords in the macOS Keychain (the
// login keychain for a user process, the System keychain for a daemon),
// through /usr/bin/security so the build stays free of cgo. Values never
// appear on a command line: writes go through security's interactive mode
// on stdin, hex-encoded. Values are stored base64-encoded so reads are
// always printable.
//
// The Keychain cannot list items cheaply, so names (not values) are kept in
// an index file under the state root.
type Keychain struct {
	service string
	index   string
	mu      sync.Mutex
}

const securityTool = "/usr/bin/security"

// NewKeychain scopes items to stateRoot, so two state roots never share
// secrets.
func NewKeychain(stateRoot string) (*Keychain, error) {
	abs, err := filepath.Abs(stateRoot)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(abs))
	dir := filepath.Join(abs, "secrets")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Keychain{
		service: "org.mimoproxy.reka." + hex.EncodeToString(sum[:6]),
		index:   filepath.Join(dir, "keychain-index.json"),
	}, nil
}

// errItemNotFound is security's exit status for a missing item.
const errItemNotFound = 44

func (k *Keychain) run(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(securityTool, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == errItemNotFound {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("secret: keychain: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	// Interactive mode reports command failures on stderr with status 0.
	if stdin != nil && stderr.Len() > 0 {
		return nil, fmt.Errorf("secret: keychain: %s", strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (k *Keychain) Get(name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	out, err := k.run(nil, "find-generic-password", "-s", k.service, "-a", name, "-w")
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", fmt.Errorf("secret: keychain item %s is not Reka's: %w", name, err)
	}
	return string(raw), nil
}

func (k *Keychain) Set(name, value string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	enc := hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(value))))
	cmd := fmt.Sprintf("add-generic-password -U -s %s -a %s -l %s -X %s\n", k.service, name, "Reka:"+name, enc)
	if _, err := k.run([]byte(cmd), "-i"); err != nil {
		return err
	}
	return k.updateIndex(func(names []string) []string {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
		return names
	})
}

func (k *Keychain) Delete(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if _, err := k.run(nil, "delete-generic-password", "-s", k.service, "-a", name); err != nil {
		return err
	}
	return k.updateIndex(func(names []string) []string {
		return slices.DeleteFunc(names, func(n string) bool { return n == name })
	})
}

func (k *Keychain) List() ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.readIndex()
}

func (k *Keychain) readIndex() ([]string, error) {
	b, err := os.ReadFile(k.index)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	if err := json.Unmarshal(b, &names); err != nil {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}

func (k *Keychain) updateIndex(fn func([]string) []string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	names, err := k.readIndex()
	if err != nil {
		return err
	}
	names = fn(names)
	slices.Sort(names)
	b, _ := json.Marshal(names)
	return WriteFileAtomic(k.index, b, 0o600)
}
