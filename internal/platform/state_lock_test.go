package platform

import (
	"os"
	"os/exec"
	"testing"
)

func TestStateRootExclusiveUntilClose(t *testing.T) {
	root := t.TempDir()
	first, err := LockStateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := LockStateRoot(root); err == nil {
		second.Close()
		t.Fatal("second kernel admitted before recovery")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := LockStateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	third.Close()
}
func TestStateRootLockReleasedByProcessExit(t *testing.T) {
	if root := os.Getenv("REKA_LOCK_CHILD"); root != "" {
		if _, err := LockStateRoot(root); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	root := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestStateRootLockReleasedByProcessExit$")
	cmd.Env = append(os.Environ(), "REKA_LOCK_CHILD="+root)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(b))
	}
	l, err := LockStateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
}
