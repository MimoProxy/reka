//go:build with_gvisor

package packettunnel

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/mobile/profile"
)

func TestPacketTunnelMITMStatusRequiresProfile(t *testing.T) {
	session := &Session{ctx: t.Context()}
	if _, err := session.RunOperation(Operation{Action: "mitmStatus"}); err == nil {
		t.Fatal("MITM status succeeded without a profile")
	}
}

func TestPacketTunnelLoadsMITMCAFromProfileSecrets(t *testing.T) {
	store := make(memoryMITMSecrets)
	authority, err := ca.Generate(ca.GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Save(store, authority); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "profile.yaml"), filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(input, []byte("schema-version: 1\nmitm: {hostnames: [origin.test]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := profile.PrepareOptions{MITM: &profile.LocalMITM{Enabled: true}, Secrets: store}
	if err := profile.PrepareFileWithOptions(t.Context(), input, output, dir, options); err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	controls := profile.Controls{Secrets: readOnlyMITMSecrets{store}}
	session, err := StartProfile(snapshot, controls, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	status := func() api.MITMStatus {
		t.Helper()
		value, err := session.RunOperation(Operation{Action: "mitmStatus"})
		if err != nil {
			t.Fatal(err)
		}
		return value.(api.MITMStatus)
	}
	if got := status(); !got.Enabled || !got.CALoaded || got.CAError != "" || got.HostnameCount != 1 {
		t.Fatalf("installed CA status = %+v", got)
	}
	if err := ca.Delete(store); err != nil {
		t.Fatal(err)
	}
	if err := session.ReplaceProfile(snapshot, controls); err != nil {
		t.Fatal(err)
	}
	if got := status(); !got.Enabled || got.CALoaded || got.CAError != "no MITM CA installed" || got.HostnameCount != 1 {
		t.Fatalf("deleted CA status = %+v", got)
	}
}

type memoryMITMSecrets map[string]string

func (s memoryMITMSecrets) Get(name string) (string, error) {
	value, ok := s[name]
	if !ok {
		return "", secret.ErrNotFound
	}
	return value, nil
}

func (s memoryMITMSecrets) Set(name, value string) error {
	s[name] = value
	return nil
}

func (s memoryMITMSecrets) Delete(name string) error {
	if _, ok := s[name]; !ok {
		return secret.ErrNotFound
	}
	delete(s, name)
	return nil
}

func (memoryMITMSecrets) List() ([]string, error) { return nil, errors.ErrUnsupported }

type readOnlyMITMSecrets struct{ memoryMITMSecrets }

func (readOnlyMITMSecrets) Set(string, string) error { return errors.ErrUnsupported }
func (readOnlyMITMSecrets) Delete(string) error      { return errors.ErrUnsupported }
