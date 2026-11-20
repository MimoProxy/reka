package generation

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"golang.org/x/net/proxy"
)

type authTestLog struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *authTestLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}
func (b *authTestLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buffer.String() }

func TestAuthenticatedMixedRulesAndCredentialRotation(t *testing.T) {
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
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	port := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	log := new(authTestLog)
	e := NewEngine(EngineOptions{Backend: sagernet.Options{Logger: slog.New(slog.NewTextHandler(log, nil))}})
	defer e.Close()
	apply := func(password string, revision uint64) Plan {
		t.Helper()
		profile := fmt.Sprintf("schema-version: 1\nrules: [{id: authenticated, match: {and: [{in-user: Alice}, {in-type: SOCKS5}, {in-port: %d}, {in-name: auth}]}, outbound: direct}, {match: {all: true}, outbound: reject}]\n", port)
		local := fmt.Sprintf("listeners: [{id: auth, type: mixed, listen: %q, users: [{username: Alice, password: %q}]}]\n", address, password)
		eff, ds := compile.Compile([]byte(profile), []byte(local), compile.Options{})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		p, err := e.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		plan := p.Plan()
		if _, err := e.Activate(p, revision); err != nil {
			t.Fatal(err)
		}
		return plan
	}
	apply("first-password", 1)
	dial := func(password string) (net.Conn, error) {
		d, err := proxy.SOCKS5("tcp", address, &proxy.Auth{User: "Alice", Password: password}, &net.Dialer{Timeout: time.Second})
		if err != nil {
			return nil, err
		}
		return d.Dial("tcp", echo.Addr().String())
	}
	roundTrip := func(c net.Conn, payload string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.WriteString(c, payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != payload {
			t.Fatalf("echo=%q error=%v", got, err)
		}
	}
	old, err := dial("first-password")
	if err != nil {
		t.Fatal("authenticated SOCKS5 conditions did not match", err)
	}
	defer old.Close()
	roundTrip(old, "before")
	if wrong, err := dial("private-wrong-password"); err == nil {
		wrong.Close()
		t.Fatal("wrong credentials accepted")
	}
	// The same mixed port and user must identify HTTP rather than SOCKS5.
	httpConn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = httpConn.SetDeadline(time.Now().Add(time.Second))
	_, _ = fmt.Fprintf(httpConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic QWxpY2U6Zmlyc3QtcGFzc3dvcmQ=\r\n\r\n", echo.Addr(), echo.Addr())
	reader := bufio.NewReader(httpConn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal("HTTP CONNECT response", err)
		}
		if line == "\r\n" {
			break
		}
	}
	_, _ = io.WriteString(httpConn, "must-not-echo")
	response := make([]byte, 4096)
	n, readErr := reader.Read(response)
	httpConn.Close()
	if n != 0 || readErr == nil {
		t.Fatal("HTTP was misclassified as SOCKS5")
	}
	plan := apply("second-password", 2)
	if !plan.Interrupts || len(plan.Listeners) != 1 || plan.Listeners[0].Action != ActionRestart {
		t.Fatalf("rotation did not plan listener rebind: %+v", plan)
	}
	roundTrip(old, "after")
	if stale, err := dial("first-password"); err == nil {
		stale.Close()
		t.Fatal("retired password still accepted")
	}
	current, err := dial("second-password")
	if err != nil {
		t.Fatal("new credentials did not activate", err)
	}
	roundTrip(current, "new")
	current.Close()
	if strings.Contains(log.String(), "private-wrong-password") || strings.Contains(log.String(), "QWxpY2U6") {
		t.Fatal("failed credentials leaked into logs")
	}
}

func TestListenerAddressChangesKeepSocketsTracked(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    int
	}{
		{name: "swap addresses", b: 0},
		{name: "move to previous address", b: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reserved [3]net.Listener
			var addresses [3]string
			for i := range reserved {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { ln.Close() })
				reserved[i], addresses[i] = ln, ln.Addr().String()
			}
			e := NewEngine(EngineOptions{Backend: sagernet.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}})
			defer e.Close()
			apply := func(a, b string, revision uint64) {
				t.Helper()
				local := fmt.Sprintf("listeners: [{id: a, type: http, listen: %q}, {id: b, type: http, listen: %q}]\n", a, b)
				eff, ds := compile.Compile([]byte("schema-version: 1\n"), []byte(local), compile.Options{})
				if ds.HasErrors() {
					t.Fatal(ds)
				}
				prepared, err := e.Prepare(eff)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := e.Activate(prepared, revision); err != nil {
					t.Fatal(err)
				}
			}
			reserved[0].Close()
			reserved[1].Close()
			apply(addresses[0], addresses[1], 1)
			reserved[2].Close()
			apply(addresses[1], addresses[tc.b], 2)

			if len(e.listeners) != 2 {
				t.Errorf("tracked %d listeners, want two", len(e.listeners))
			}
			for id, want := range map[string]string{"a": addresses[1], "b": addresses[tc.b]} {
				if got := e.listeners[id]; got == nil || got.cfg.Listen.String() != want {
					t.Errorf("listener %s is not tracked at %s", id, want)
				}
			}
			checkFree := func(addr string) {
				t.Helper()
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					t.Errorf("listener address %s is still occupied: %v", addr, err)
					return
				}
				ln.Close()
			}
			if tc.b != 0 {
				checkFree(addresses[0])
			}
			e.Close()
			for _, addr := range addresses {
				checkFree(addr)
			}
		})
	}
}
