package store

import (
	"os"
	"path/filepath"
	"runtime"
)

// Durability. Every file and directory change is synced with syncFile or
// syncDir, which on macOS only hands the data to the drive (fsync there
// does not flush the drive's cache). Barrier then flushes the drive cache
// once, making everything synced before it durable. A commit needs two
// barriers: after the revision and the operation intent are written (before
// the switch), and after active.json is written (before reporting
// success). On Linux and Windows a sync is already a full flush and Barrier
// does nothing.

// writeAtomic writes data to a temporary file next to path, syncs it,
// renames it over path and syncs the directory.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := syncFile(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// writeNew creates path with data and syncs it.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := syncFile(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Barrier makes everything synced so far durable.
func (s *Store) Barrier() error { return barrier(s.root) }
