//go:build darwin

package control

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPeerIsCurrentUser(t *testing.T) {
	dir, _ := os.MkdirTemp("", "rk")
	defer os.RemoveAll(dir)
	ln, err := Listen("unix://" + filepath.Join(dir, "c.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := Dial("unix://" + filepath.Join(dir, "c.sock"))
		if err == nil {
			time.Sleep(100 * time.Millisecond)
			c.Close()
		}
	}()
	c, err := ln.(*peerListener).Listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid, err := peerUID(c)
	if err != nil || uid != os.Geteuid() {
		t.Fatalf("peer uid %d, %v", uid, err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "c.sock"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode())
	}
	// A second server on the same live socket is refused.
	if _, err := Listen("unix://" + filepath.Join(dir, "c.sock")); err == nil {
		t.Fatal("second listener on a live socket")
	}
}
