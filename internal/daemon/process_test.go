//go:build darwin || windows || (linux && !android)

package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/secret"
	"golang.org/x/net/proxy"
)

// This uses the native OS socket owner table, with no ProcessLookup callback.
func TestNativeProcessRuleRejectAndRestore(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	reserved.Close()
	profile := func(name string) []byte {
		return []byte(fmt.Sprintf("schema-version: 1\nlog: {level: error}\nrules: [{id: process, match: {process-name: %s}, outbound: reject},{id: final, match: {all: true}, outbound: direct}]\n", strconv.Quote(name)))
	}
	root := t.TempDir()
	store, err := secret.NewFileStore(filepath.Join(root, "secrets.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := Start(Options{StateRoot: root, Secrets: store, ControlAddress: "-", InitialProfile: profile("not-the-test-process"), InitialLocal: []byte(fmt.Sprintf("listeners: [{id: mixed, type: mixed, listen: %q}]\n", address))})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if message := k.Service.StartError(); message != "" {
		t.Fatal(message)
	}
	dialer, err := proxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	probe := func(wantReject bool) {
		t.Helper()
		c, e := dialer.Dial("tcp", echo.Addr().String())
		if wantReject {
			if e == nil {
				c.Close()
				t.Fatal("own process rule did not reject")
			}
			if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
				t.Fatalf("probe timed out instead of rejecting: %v", e)
			}
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(c, "native-owner")
		b := make([]byte, 12)
		if _, e = io.ReadFull(c, b); e != nil || string(b) != "native-owner" {
			t.Fatalf("forwarding: %q %v", b, e)
		}
	}
	probe(false)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		name   string
		reject bool
	}{{filepath.Base(executable), true}, {"not-the-test-process", false}} {
		text := string(profile(entry.name))
		result, e := k.Service.Commit(context.Background(), service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: k.Service.ActiveRevision(), Profile: &text}})
		if e != nil || result.State != "committed" {
			t.Fatalf("commit: %+v %v", result, e)
		}
		probe(entry.reject)
	}
}
