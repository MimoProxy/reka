package core

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

type fakeHost struct {
	mu     sync.Mutex
	events []string
}

func (h *fakeHost) Protect(int) bool              { return true }
func (h *fakeHost) Seal(p []byte) ([]byte, error) { return append([]byte("sealed:"), p...), nil }
func (h *fakeHost) Open(p []byte) ([]byte, error) {
	return []byte(strings.TrimPrefix(string(p), "sealed:")), nil
}
func (h *fakeHost) OnMessage(b []byte) {
	h.mu.Lock()
	h.events = append(h.events, string(b))
	h.mu.Unlock()
}
func (h *fakeHost) count() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.events) }

func TestEmbedded(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	host := &fakeHost{}
	profile := "schema-version: 1\noutbounds:\n  - {id: alt, type: direct}\ngroups:\n  - {id: proxy, type: select, members: [direct, alt]}\nrules:\n  - {match: {all: true}, outbound: proxy}\n"
	local := fmt.Sprintf("listeners:\n  - {id: mixed, type: mixed, listen: \"127.0.0.1:%d\"}\n", port)
	in, err := Start(Options{StateRoot: t.TempDir(), InitialProfile: []byte(profile), InitialLocal: []byte(local),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, host)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Stop()
	call := func(id int, method, params string) map[string]any {
		resp := in.Call([]byte(fmt.Sprintf(`{"id":%d,"method":%q,"params":%s}`, id, method, params)))
		var m map[string]any
		json.Unmarshal(resp, &m)
		if m["error"] != nil {
			t.Fatalf("%s: %v", method, m["error"])
		}
		return m["result"].(map[string]any)
	}
	call(1, "Hello", `{"versions":[1]}`)
	call(2, "Subscribe", `{}`)

	// A long connection through the proxy stays up across a commit.
	d, _ := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, proxy.Direct)
	c, err := d.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roundTrip := func(msg string) {
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, msg)
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
			t.Fatalf("echo %q: %q %v", msg, buf, err)
		}
	}
	roundTrip("before")
	res := call(3, "CommitConfiguration", `{"base_revision":1,"patch":[{"op":"set","path":"/groups/proxy/selected","value":"alt"}]}`)
	if res["state"] != "committed" {
		t.Fatalf("commit %v", res)
	}
	roundTrip("after")
	call(4, "SetSecret", `{"name":"x/y","value":"v","apply":false}`)
	deadline := time.Now().Add(2 * time.Second)
	for host.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if host.count() < 2 {
		t.Fatalf("events: %v", host.events)
	}
	b, _ := os.ReadFile(in.k.Service.Secrets().(interface{ Path() string }).Path())
	if !strings.Contains(string(b), "c2VhbGVkOn") { // base64 of "sealed:"
		t.Fatalf("secret not sealed by the host: %s", b)
	}
}
