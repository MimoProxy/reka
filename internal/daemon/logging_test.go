package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/secret"
	"golang.org/x/net/proxy"
)

// Real inbound/outbound traffic exercises the default logger both before and
// after a configured level change. No custom handler masks the default path.
func TestDefaultLoggerFollowsActiveConfiguration(t *testing.T) {
	root := t.TempDir()
	logFile, err := os.Create(filepath.Join(root, "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = logFile
	defer func() { os.Stderr = oldStderr; logFile.Close() }()
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
	secrets, err := secret.NewFileStore(filepath.Join(root, "secrets.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	k, address := startListening(t, func(address string) Options {
		return Options{StateRoot: t.TempDir(), Secrets: secrets, ControlAddress: "-", InitialProfile: []byte("schema-version: 1\nlog: {level: error}\nrules: [{id: final, match: {all: true}, outbound: direct}]\n"), InitialLocal: []byte(fmt.Sprintf("listeners: [{id: mixed, type: mixed, listen: %q}]\n", address))}
	})
	defer k.Close()
	if e := k.Service.StartError(); e != "" {
		t.Fatal(e)
	}
	if err = logFile.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err = logFile.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	dialer, err := proxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	roundTrip := func() {
		c, e := dialer.Dial("tcp", echo.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.WriteString(c, "ping")
		b := make([]byte, 4)
		if _, e = io.ReadFull(c, b); e != nil || string(b) != "ping" {
			t.Fatalf("forward: %q, %v", b, e)
		}
	}
	roundTrip()
	data, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("error-level config leaked traffic logs: %s", data)
	}
	result, err := k.Service.Commit(context.Background(), service.CommitRequest{ChangeRequest: service.ChangeRequest{BaseRevision: k.Service.ActiveRevision(), Patch: []model.Op{{Op: "set", Path: "/log/level", Value: []byte(`"info"`)}}}})
	if err != nil || result.State != "committed" {
		t.Fatalf("level commit: %+v, %v", result, err)
	}
	roundTrip()
	data, err = os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "outbound connection") {
		t.Fatalf("info level did not enable traffic logs: %s", data)
	}
	var mirrored bool
	for _, event := range k.Service.Events().Recent(service.EventLog, 256) {
		data, _ := json.Marshal(event.Data)
		mirrored = mirrored || strings.Contains(string(data), "outbound connection")
	}
	if !mirrored {
		t.Fatal("actual traffic log was not exposed to native clients")
	}
}
