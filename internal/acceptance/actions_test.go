package acceptance

import (
	"io"
	"testing"
	"time"
)

func TestPASSSelectionFallsThroughWithoutClosingExistingStream(t *testing.T) {
	h := newHarness(t, "schema-version: 1\ngroups: [{id: choice, type: select, members: [direct, pass], selected: direct}]\nrules: [{id: choose, match: {all: true}, outbound: choice}, {id: block, match: {all: true}, outbound: reject}]\n")
	target := echoServer(t)
	old := openStream(t, h.proxy(), target)
	h.mustCommit(patch("/groups/choice/selected", `"pass"`))
	c, err := socks5Connect(h.proxy(), target)
	if err == nil {
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte("must-not-echo"))
		reply := make([]byte, 13)
		_, err = io.ReadFull(c, reply)
		c.Close()
		if err == nil {
			t.Fatal("PASS was treated as direct instead of continuing to reject")
		}
	}
	if err = old.finish(); err != nil {
		t.Fatal("PASS selection closed old flow", err)
	}
	h.mustCommit(patch("/groups/choice/selected", `"direct"`))
	if err = openStream(t, h.proxy(), target).finish(); err != nil {
		t.Fatal(err)
	}
}
