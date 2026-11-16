package resource

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRejectsSymlinkedBlobOrResourceDirectories(t *testing.T) {
	for _, component := range []string{"blob", "sha256", "resources"} {
		t.Run(component, func(t *testing.T) {
			root := t.TempDir()
			s, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("approved bytes")
			hash, err := s.Put(data)
			if err != nil {
				t.Fatal(err)
			}
			original := filepath.Join(root, "resources", "sha256", hash)
			path := original
			if component == "sha256" {
				path = filepath.Dir(path)
			}
			if component == "resources" {
				path = filepath.Dir(filepath.Dir(path))
			}
			target := path + "-original"
			if err := os.Rename(path, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Skip("symlinks unavailable", err)
			}
			if _, err := s.Read(hash); err == nil {
				t.Fatal("resource read followed a symlink", component)
			}
		})
	}
}
