package acceptance

import (
	"fmt"
	"io"
	"testing"
	"time"
)

func TestDetourTwoShadowsocksHopsTCPUDPAndParentRotation(t *testing.T) {
	innerKey, parentKey := newSSKey(), newSSKey()
	inner, parent := ssServer(t, innerKey), ssServer(t, parentKey)
	profile := fmt.Sprintf(`schema-version: 1
outbounds:
 - {id: child, type: shadowsocks, server: 127.0.0.1, port: %d, method: %s, password: %q, dialer: {proxy: parent}}
 - {id: parent, type: shadowsocks, server: 127.0.0.1, port: %d, method: %s, password: %q}
rules: [{id: final, match: {all: true}, outbound: child}]
`, inner.Port(), ssMethod, innerKey, parent.Port(), ssMethod, parentKey)
	h := newHarness(t, profile)
	target := echoServer(t)
	oldChild, oldParent := h.engine().OutboundInstance("child"), h.engine().OutboundInstance("parent")
	if oldParent.Active() != 0 || oldParent.Lease().Active() != 1 {
		t.Fatal("dependency pin was counted as a client connection")
	}
	old := openStream(t, h.proxy(), target)
	udp := udpEcho(t)
	assoc := associate(t, h.proxy())
	assoc.send(udp, "two-hops")
	if replies := assoc.recv(time.Second); replies[udp.String()] != "two-hops" {
		t.Fatal("two-hop UDP did not round trip", replies)
	}
	assoc.ctrl.Close()
	assoc.udp.Close()
	waitFor(t, "UDP detour closed", 3*time.Second, func() bool { return oldChild.Active() == 1 })
	h.mustCommit(patch("/outbounds/parent/password", fmt.Sprintf("%q", newSSKey())))
	if h.engine().OutboundInstance("child") == oldChild || !oldChild.Lease().Retired() || !oldParent.Lease().Retired() {
		t.Fatal("parent edit did not replace the child graph")
	}
	// A wrong parent key proves that the child's node was not dialed directly.
	c, err := socks5Connect(h.proxy(), target)
	if err == nil {
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write([]byte("must-not-bypass-parent"))
		reply := make([]byte, 21)
		_, err = io.ReadFull(c, reply)
		c.Close()
		if err == nil {
			t.Fatal("failed detour fell back directly to the child server")
		}
	}
	if err = old.finish(); err != nil {
		t.Fatal("parent rotation interrupted an existing two-hop stream", err)
	}
	h.mustCommit(patch("/outbounds/parent/password", fmt.Sprintf("%q", parentKey)))
	child := h.engine().OutboundInstance("child")
	fresh := openStream(t, h.proxy(), target)
	h.mustCommit(patch("/rules/final/match", `{"network":"tcp"}`))
	if h.engine().OutboundInstance("child") != child {
		t.Fatal("rule-only edit rebuilt the detour")
	}
	if err = fresh.finish(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "detour dependencies drained", 5*time.Second, func() bool { return h.engine().Status().Draining == 0 })
	if h.engine().Status().Forced != 0 {
		t.Fatal("detour required forced closure")
	}
}
func TestDirectDetourGroupSelectionUsesNewParent(t *testing.T) {
	key := newSSKey()
	a, b := ssServer(t, key), ssServer(t, key)
	profile := fmt.Sprintf(`schema-version: 1
outbounds:
 - {id: child, type: direct, dialer: {proxy: hop}}
 - {id: a, type: shadowsocks, server: 127.0.0.1, port: %d, method: %s, password: %q}
 - {id: b, type: shadowsocks, server: 127.0.0.1, port: %d, method: %s, password: %q}
groups: [{id: hop, type: select, members: [a,b], selected: a}]
rules: [{id: final, match: {all: true}, outbound: child}]
`, a.Port(), ssMethod, key, b.Port(), ssMethod, key)
	h := newHarness(t, profile)
	target := echoServer(t)
	old := openStream(t, h.proxy(), target)
	previous := h.engine().OutboundInstance("child")
	h.mustCommit(patch("/groups/hop/selected", `"b"`))
	if h.engine().OutboundInstance("child") == previous {
		t.Fatal("detour selection did not change child fingerprint")
	}
	fresh := openStream(t, h.proxy(), target)
	if err := old.finish(); err != nil {
		t.Fatal(err)
	}
	if err := fresh.finish(); err != nil {
		t.Fatal(err)
	}
}
