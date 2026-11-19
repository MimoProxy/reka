package generation

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/history"
	"golang.org/x/net/proxy"
)

func TestHistoryLateCloseBelongsToTheProfileThatRoutedIt(t *testing.T) {
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		conn, err := server.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()
	lease, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := lease.Addr().String()
	lease.Close()

	engine := NewEngine(EngineOptions{ProfileID: "first"})
	defer engine.Close()
	profile := []byte("schema-version: 1\nrules: [{match: {all: true}, outbound: direct}]\n")
	local := fmt.Appendf(nil, "listeners: [{id: mixed, type: mixed, listen: %q}]\n", listen)
	eff, diagnostics := compile.Compile(profile, local, compile.Options{})
	if eff == nil {
		t.Fatal(diagnostics)
	}
	activate := func(profile string) {
		t.Helper()
		p, err := engine.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := engine.ActivateProfile(p, 1, profile); err != nil {
			t.Fatal(err)
		}
	}
	activate("first")
	dialer, _ := proxy.SOCKS5("tcp", listen, nil, &net.Dialer{Timeout: time.Second})
	conn, err := dialer.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	activate("second")
	if _, err := conn.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil || b[0] != 'a' {
		t.Fatal(b, err)
	}
	live := engine.Connections()
	if len(live) != 1 || engine.CloseConnections([]uint64{live[0].ID}) != 1 {
		t.Fatal("missing active flow", live)
	}
	records, active := engine.History()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(time.Millisecond) {
		first, _ := records.List(history.Connections, "first", history.ListOptions{})
		second, _ := records.List(history.Connections, active.ProfileID, history.ListOptions{})
		if len(second.Rows) != 0 {
			t.Fatal("record attached to the new profile")
		}
		if len(first.Rows) == 1 {
			data := string(first.Rows[0].Data)
			if !strings.Contains(data, fmt.Sprintf(`"id":%d`, live[0].ID)) ||
				!strings.Contains(data, `"close_reason":"manual"`) ||
				!strings.Contains(data, `"target_ip":"127.0.0.1"`) {
				t.Fatal(data)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no record for the retired profile")
		}
	}
}
