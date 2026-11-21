package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/store"
	"golang.org/x/net/proxy"
)

// Rotating a secret that only a listener's authentication uses must
// restart that listener with the new credentials.
func TestReapplyRotatesListenerOnlySecret(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	e := newEnv(t)
	if err := e.sec.Set("listeners/auth/password", "first-password"); err != nil {
		t.Fatal(err)
	}
	s, port := e.openOn(profileWith("alt"), func(port int) string {
		return fmt.Sprintf("listeners: [{id: auth, type: mixed, listen: \"127.0.0.1:%d\", users: [{username: Alice, password: secret://listeners/auth/password}]}]\n", port)
	})
	defer s.Close()
	address := fmt.Sprintf("127.0.0.1:%d", port)

	dial := func(password string) error {
		d, err := proxy.SOCKS5("tcp", address, &proxy.Auth{User: "Alice", Password: password}, &net.Dialer{Timeout: time.Second})
		if err != nil {
			return err
		}
		c, err := d.Dial("tcp", echo.Addr().String())
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.WriteString(c, "ping"); err != nil {
			return err
		}
		got := make([]byte, 4)
		if _, err := io.ReadFull(c, got); err != nil {
			return err
		}
		if string(got) != "ping" {
			return fmt.Errorf("echo returned %q", got)
		}
		return nil
	}
	if err := dial("first-password"); err != nil {
		t.Fatal("listener rejected its configured password:", err)
	}

	if err := e.sec.Set("listeners/auth/password", "second-password"); err != nil {
		t.Fatal(err)
	}
	before := s.ActiveRevision()
	res, err := s.Reapply(context.Background(), "secret")
	if err != nil || res.State != store.OpCommitted || res.NoChange || res.Revision == before {
		t.Fatalf("reapply after rotating the listener password: %+v, %v", res, err)
	}
	if err := dial("second-password"); err != nil {
		t.Fatal("listener rejected the rotated password:", err)
	}
	if err := dial("first-password"); err == nil {
		t.Fatal("listener still accepts the old password")
	}
}
