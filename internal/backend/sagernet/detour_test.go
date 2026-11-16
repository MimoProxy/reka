package sagernet

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestDependencyPinAllowsOldParentAndReleasesAfterBorrowedSocket(t *testing.T) {
	b := New(Options{Logger: testLogger(t)})
	defer b.Close()
	out, err := b.NewOutbound("parent", DirectSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	pin, err := out.Pin()
	if err != nil {
		t.Fatal(err)
	}
	out.Lease().Retire()
	c, err := pin.Dial(context.Background(), "tcp", echoServer(t).String())
	if err != nil {
		t.Fatal("pinned retired parent could not dial", err)
	}
	pin.Close()
	if _, err = pin.Dial(context.Background(), "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("closed dependency accepted a new borrow")
	}
	if out.Active() != 0 || out.Lease().Active() != 1 {
		t.Fatal("dependency accounting", out.Active(), out.Lease().Active())
	}
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("kept"))
	reply := make([]byte, 4)
	if _, err = io.ReadFull(c, reply); err != nil || string(reply) != "kept" {
		t.Fatal(err)
	}
	c.Close()
	select {
	case <-out.Lease().Drained():
	case <-time.After(time.Second):
		t.Fatal("dependency pin leaked after its last borrowed socket")
	}
}
