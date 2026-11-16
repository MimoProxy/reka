package sagernet

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestRejectDropHasNoRemoteSocketAndWaitsForLocalDeadline(t *testing.T) {
	b := New(Options{Logger: testLogger(t), ProtectFD: func(int) error { t.Error("drop opened a physical socket"); return nil }})
	defer b.Close()
	out, err := b.NewOutbound("drop", DropSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	c, err := out.Dial(context.Background(), "tcp", "198.51.100.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := c.Write([]byte("discard")); err != nil || n != 7 {
		t.Fatal(n, err)
	}
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	var timeout net.Error
	if errors.Is(err, io.EOF) || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("drop was an immediate reject", err)
	}
	c.Close()
	if out.Active() != 0 {
		t.Fatal("drop lease leaked")
	}
}
