package acceptance

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// Opt-in duration: scheduled CI uses 600s; local acceptance records its actual
// duration. Always finishes with resource/byte-integrity assertions.
func TestSoak(t *testing.T) {
	seconds, _ := strconv.Atoi(os.Getenv("REKA_SOAK_SECONDS"))
	if seconds <= 0 {
		t.Skip("set REKA_SOAK_SECONDS for sustained acceptance")
	}
	if seconds > 86400 {
		t.Fatal("soak duration exceeds 24 hours")
	}
	h := newHarness(t, "schema-version: 1\noutbounds: [{id: alt, type: direct}]\ngroups: [{id: proxy, type: select, members: [direct, alt]}]\nrules: [{id: final, match: {all: true}, outbound: proxy}]\n")
	echo := echoServer(t)
	c, err := socks5Connect(h.proxy(), echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	base := runtime.NumGoroutine()
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	updates := 0
	bytes := 0
	for time.Now().Before(deadline) {
		selected := "direct"
		if updates%2 == 0 {
			selected = "alt"
		}
		h.mustCommit(patch("/groups/proxy/selected", fmt.Sprintf("%q", selected)))
		payload := fmt.Sprintf("soak-%08d-%s", updates, string(make([]byte, 4096)))
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = io.WriteString(c, payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err = io.ReadFull(c, got); err != nil || string(got) != payload {
			t.Fatal("stream changed", err)
		}
		bytes += len(got)
		updates++
		time.Sleep(20 * time.Millisecond)
	}
	c.Close()
	h.engine().CloseConnections(nil)
	waitFor(t, "soak drain", 10*time.Second, func() bool { return h.engine().Status().Draining == 0 && h.engine().Status().Connections == 0 })
	runtime.GC()
	if g := runtime.NumGoroutine(); g > base+4 {
		t.Fatalf("goroutines %d -> %d", base, g)
	}
	t.Logf("duration=%ds commits=%d bytes=%d forced=%d", seconds, updates, bytes, h.engine().Status().Forced)
}
