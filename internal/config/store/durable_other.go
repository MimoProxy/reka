//go:build !darwin

package store

import (
	"os"

	"github.com/MimoProxy/reka/internal/secret"
)

func syncFile(f *os.File) error { return f.Sync() }

// syncDir is a no-op where directories cannot be synced (Windows).
func syncDir(dir string) error { return secret.SyncDir(dir) }

// barrier does nothing: a sync is already a full flush on these systems.
func barrier(string) error { return nil }
