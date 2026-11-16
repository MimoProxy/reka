//go:build windows

package control

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Exercise both authorization layers against a real client process token.
func TestPipeRejectsNonOwnerToken(t *testing.T) {
	self, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	if self.Equals(systemSID) {
		t.Skip("LocalSystem is an explicitly trusted control client")
	}
	foreign, err := windows.StringToSid("S-1-5-19")
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Equals(self) {
		foreign, _ = windows.StringToSid("S-1-5-20")
	}
	name := fmt.Sprintf(`\\.\pipe\reka-peer-negative-%d-%d`, os.Getpid(), time.Now().UnixNano())
	listener, err := listenPipe(name)
	if err != nil {
		t.Fatal(err)
	}
	l := listener.(*pipeListener)
	defer l.Close()
	// Retain the real current-user DACL so the connection reaches the SID
	// check, but require a different owner there. This is not a fake token.
	l.self = foreign
	done := make(chan error, 1)
	go func() {
		c, e := l.accept()
		if c != nil {
			c.Close()
		}
		done <- e
	}()
	c, err := Dial("pipe://" + name[len(`\\.\pipe\`):])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case err = <-done:
		if !errors.Is(err, ErrPeerDenied) {
			t.Fatalf("non-owner token was not refused: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SID check did not complete")
	}
}
