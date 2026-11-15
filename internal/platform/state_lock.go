package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// StateLock lives for the entire daemon, before any recovery or OS mutation.
// Its file remains after close; deleting it would allow locking another inode.
type StateLock struct {
	file *os.File
	once sync.Once
}

func LockStateRoot(root string) (*StateLock, error) {
	if e := os.MkdirAll(root, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(root, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = lockStateFile(f); e != nil {
		f.Close()
		return nil, fmt.Errorf("state root is already in use or cannot be locked: %w", e)
	}
	return &StateLock{file: f}, nil
}
func (l *StateLock) Close() error { var e error; l.once.Do(func() { e = l.file.Close() }); return e }
