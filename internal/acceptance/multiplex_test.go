package acceptance

import (
	"fmt"
	"testing"
	"time"
)

func TestMultiplexDetourReplacementDrainsAndReusesCurrentPolicy(t *testing.T) {
	for _, protocol := range []string{"h2mux", "smux", "yamux"} {
		t.Run(protocol, func(t *testing.T) {
			_, node := realityServer(t, true)
			key := newSSKey()
			parent := ssServer(t, key)
			profile := "schema-version: 1\noutbounds:\n" + node + fmt.Sprintf(`    multiplex: {enabled: true, protocol: %s, padding: true, max-connections: 1}
    dialer: {proxy: parent}
  - {id: parent, type: shadowsocks, server: 127.0.0.1, port: %d, method: %s, password: %q}
rules: [{id: final, match: {all: true}, outbound: reality}]
`, protocol, parent.Port(), ssMethod, key)
			h := newHarness(t, profile)
			target := echoServer(t)
			old := openStream(t, h.proxy(), target)
			waitFor(t, "old mux payload", 2*time.Second, func() bool { return old.received.Load() >= 16384 })
			previous := h.engine().OutboundInstance("reality")
			h.mustCommit(patch("/rules/final/match", `{"network":"tcp"}`))
			if h.engine().OutboundInstance("reality") != previous {
				t.Fatal("rule-only edit rebuilt mux pool")
			}
			h.mustCommit(patch("/outbounds/reality/multiplex/padding", `false`))
			if h.engine().OutboundInstance("reality") == previous || !previous.Lease().Retired() {
				t.Fatal("mux transport edit did not retire old pool")
			}
			fresh := openStream(t, h.proxy(), target)
			waitFor(t, "fresh mux payload", 2*time.Second, func() bool { return fresh.received.Load() >= 16384 })
			if err := old.finish(); err != nil {
				t.Fatal("mux replacement interrupted old stream", err)
			}
			if err := fresh.finish(); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "mux pool drained", 5*time.Second, func() bool { return h.engine().Status().Draining == 0 })
			if h.engine().Status().Forced != 0 {
				t.Fatal("mux pool required forced close")
			}
		})
	}
}
