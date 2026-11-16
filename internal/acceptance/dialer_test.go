package acceptance

import (
	"testing"
	"time"
)

func TestDialerChangeDrainsInstanceAndKeepsOldStream(t *testing.T) {
	h := newHarness(t, "schema-version: 1\noutbounds: [{id: node, type: direct, dialer: {ip-version: ipv4}}]\nrules: [{match: {all: true}, outbound: node}]\n")
	echo := echoServer(t)
	previous := h.engine().OutboundInstance("node")
	old := openStream(t, h.proxy(), echo)
	waitFor(t, "old dialer stream", 2*time.Second, func() bool { return previous.Active() == 1 })
	h.mustCommit(patch("/outbounds/node/dialer/ip-version", `"dual"`))
	if current := h.engine().OutboundInstance("node"); current == previous || !previous.Lease().Retired() {
		t.Fatal("dialer edit did not replace and retire old instance")
	}
	fresh := openStream(t, h.proxy(), echo)
	if e := old.finish(); e != nil {
		t.Fatal("dialer edit interrupted old stream", e)
	}
	if e := fresh.finish(); e != nil {
		t.Fatal(e)
	}
	waitFor(t, "old dialer drained", 2*time.Second, func() bool { return previous.Active() == 0 })
}
