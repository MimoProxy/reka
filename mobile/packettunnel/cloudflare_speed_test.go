//go:build with_gvisor

package packettunnel

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/mobile/profile"
)

func TestSpeedOperationUsesSourceAndCancels(t *testing.T) {
	tests := []struct {
		name        string
		operation   string
		source      string
		destination string
	}{
		{
			name:        "default Cloudflare",
			operation:   `{"action":"speedStart","id":1234,"member":"choice"}`,
			source:      "cloudflare",
			destination: "speed.cloudflare.com:443",
		},
		{
			name:        "Ookla",
			operation:   `{"action":"speedStart","id":1234,"member":"choice","source":"ookla"}`,
			source:      "ookla",
			destination: "www.speedtest.net:443",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var operation Operation
			if err := json.Unmarshal([]byte(test.operation), &operation); err != nil {
				t.Fatal(err)
			}
			testSpeedOperation(t, operation, test.source, test.destination)
		})
	}
}

func testSpeedOperation(t *testing.T, operation Operation, source, destination string) {
	t.Helper()
	connects := make(chan string, 1)
	disconnected := make(chan struct{}, 1)
	proxy := ipCheckTestHTTPServer(t, "tcp4", "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conn, stream, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		connects <- r.Host
		// Keep CONNECT pending to exercise cancellation of outbound dialing.
		if _, err := stream.ReadByte(); err != nil {
			if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				disconnected <- struct{}{}
			}
		}
	}))
	snapshot := prepareSnapshot(t, fmt.Sprintf(`
schema-version: 1
outbounds: [{id: relay, name: Relay, type: http, server: 127.0.0.1, port: %d}]
groups: [{id: choice, type: select, members: [direct, relay]}]
rules: [{match: {all: true}, outbound: reject}]
`, proxy.Listener.Addr().(*net.TCPAddr).Port))
	session, err := StartProfile(snapshot, profile.Controls{Selections: map[string]string{"choice": "relay"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)

	if started, err := session.RunOperation(operation); err != nil || started != true {
		t.Fatalf("start speed test: %v, %v", started, err)
	}
	select {
	case target := <-connects:
		if target != destination {
			t.Fatalf("proxy destination = %q, want %q", target, destination)
		}
	case <-time.After(time.Second):
		t.Fatal("selected outbound never received CONNECT")
	}
	if canceled, err := session.RunOperation(Operation{Action: "speedCancel", ID: operation.ID}); err != nil || canceled != true {
		t.Fatalf("cancel speed test: %v, %v", canceled, err)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close pending CONNECT")
	}
	status := completedSpeedOperation(t, session, operation.ID)
	if status.Source != source || status.Resolved != "relay" || status.Error == "" || status.UploadMbps != nil {
		t.Fatalf("unexpected canceled speed test status: %+v", status)
	}
}

func TestSpeedOperationRejectsUnknownSource(t *testing.T) {
	snapshot := prepareSnapshot(t, `
schema-version: 1
rules: [{match: {all: true}, outbound: direct}]
`)
	session, err := StartProbeProfile(snapshot, profile.Controls{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)

	var operation Operation
	if err := json.Unmarshal([]byte(`{"action":"speedStart","id":1,"member":"direct","source":"invalid"}`), &operation); err != nil {
		t.Fatal(err)
	}
	if started, err := session.RunOperation(operation); err != nil || started != true {
		t.Fatalf("start speed test: %v, %v", started, err)
	}
	status := completedSpeedOperation(t, session, operation.ID)
	if !strings.Contains(status.Error, "source") || !strings.Contains(status.Error, operation.Source) {
		t.Fatalf("unexpected error for unknown speed source: %q", status.Error)
	}
}

func completedSpeedOperation(t *testing.T, session *Session, id uint64) speedTestReply {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		output, err := session.RunOperation(Operation{Action: "speedRead", ID: id})
		if err != nil {
			t.Fatal(err)
		}
		status := output.(speedTestReply)
		if status.Complete {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("speed test did not finish")
	return speedTestReply{}
}
