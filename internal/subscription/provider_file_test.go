package subscription

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProviderFilesStayInsideExplicitRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(root, "nodes.yaml"), []byte("safe"), 0600)
	os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0600)
	if data, err := ReadProviderFile(root, "nodes.yaml"); err != nil || string(data) != "safe" {
		t.Fatal(err)
	}
	for _, path := range []string{"../secret", filepath.Join(outside, "secret"), "."} {
		if _, err := ReadProviderFile(root, path); err == nil {
			t.Fatal("unsafe path accepted")
		}
	}
	if _, err := ReadProviderFile("", "nodes.yaml"); err == nil {
		t.Fatal("implicit root accepted")
	}
	if os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "escape")) == nil {
		if _, err := ReadProviderFile(root, "escape"); err == nil {
			t.Fatal("symlink escaped root")
		}
	}
}
