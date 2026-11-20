package acceptance

import (
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/service"
)

func TestSourceRefreshKeepsLiveConnections(t *testing.T) {
	h := newHarness(t, baseProfile)
	profile := `schema-version: 1
imports: [{source: sub, outbounds: true, groups: true}]
rules: [{id: final, match: {all: true}, outbound: sub/proxy}]
`
	sources := `sources:
 - id: sub
   outbounds:
    - {id: a, type: direct}
    - {id: b, type: direct}
   groups: [{id: proxy, type: select, members: [a, b], selected: a}]
`
	h.mustCommit(service.CommitRequest{ChangeRequest: service.ChangeRequest{Profile: &profile, Sources: &sources}})
	echo := echoServer(t)
	listener := h.engine().ListenerInstance("mixed")
	a, b := h.engine().OutboundInstance("sub/a"), h.engine().OutboundInstance("sub/b")
	old := openStream(t, h.proxy(), echo)
	waitFor(t, "source connection", 2*time.Second, func() bool { return a.Active() == 1 && len(connsByDest(h, echo.String())) == 1 })
	before := connsByDest(h, echo.String())[0]
	overlay := "patches: [{op: set, path: /groups/sub~1proxy/selected, value: sub/b}]\n"
	h.mustCommit(service.CommitRequest{ChangeRequest: service.ChangeRequest{Overlay: &overlay}})
	// Upstream removes an unselected node, repairing its own references.
	// The old connection keeps the removed node's lease until it finishes.
	sources = strings.Replace(sources, "    - {id: a, type: direct}\n", "", 1)
	sources = strings.Replace(sources, "members: [a, b], selected: a", "members: [b], selected: b", 1)
	h.mustCommit(service.CommitRequest{ChangeRequest: service.ChangeRequest{Sources: &sources}})
	fresh := openStream(t, h.proxy(), echo)
	waitFor(t, "new source connection", 2*time.Second, func() bool { return b.Active() == 1 })
	for _, c := range connsByDest(h, echo.String()) {
		if c.ID == before.ID {
			if c.Outbound != "sub/a" || c.Generation != before.Generation {
				t.Fatal("old connection changed", c)
			}
		} else if c.Outbound != "sub/b" {
			t.Fatal("new connection used wrong selection", c)
		}
	}
	if h.engine().ListenerInstance("mixed") != listener || h.engine().OutboundInstance("sub/b") != b {
		t.Fatal("refresh rebuilt retained resources")
	}
	cfg := h.svc.GetConfiguration(true)
	if cfg.Overlay != overlay || cfg.Local != h.local() {
		t.Fatal("refresh changed user documents")
	}
	time.Sleep(100 * time.Millisecond)
	if err := old.finish(); err != nil {
		t.Fatal("old stream", err)
	}
	if err := fresh.finish(); err != nil {
		t.Fatal("new stream", err)
	}
	waitFor(t, "removed source instance drained", 2*time.Second, func() bool { return h.engine().Status().Draining == 0 })
}
