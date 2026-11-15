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
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(root, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockStateFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("state root is already in use or cannot be locked: %w", err)
	}
	return &StateLock{file: f}, nil
}
func (l *StateLock) Close() error {
	var err error
	l.once.Do(func() { err = l.file.Close() })
	return err
}
