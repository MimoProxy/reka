//go:build with_gvisor

package packettunnel

import (
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/MimoProxy/reka/mobile/profile"
)

func TestCloudflareSpeedOperationUsesSelectedLeafAndCancels(t *testing.T) {
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
		_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
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

	const probeID = 1234
	if started, err := session.RunOperation(Operation{Action: "speedStart", ID: probeID, Member: "choice"}); err != nil || started != true {
		t.Fatalf("start speed test: %v, %v", started, err)
	}
	select {
	case destination := <-connects:
		if destination != "speed.cloudflare.com:443" {
			t.Fatalf("unexpected proxy destination %q", destination)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("selected outbound never received CONNECT")
	}
	if canceled, err := session.RunOperation(Operation{Action: "speedCancel", ID: probeID}); err != nil || canceled != true {
		t.Fatalf("cancel speed test: %v, %v", canceled, err)
	}
	select {
	case <-disconnected:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not close pending CONNECT")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		output, err := session.RunOperation(Operation{Action: "speedRead", ID: probeID})
		if err != nil {
			t.Fatal(err)
		}
		status := output.(cloudflareSpeedReply)
		if status.Complete {
			if status.Resolved != "relay" || status.Error == "" || status.UploadMbps != nil {
				t.Fatalf("unexpected canceled speed test status: %+v", status)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("speed test did not finish after cancellation")
}
