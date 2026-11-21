package acceptance

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
)

func TestBlockQUICCommitAppliesToNewUDPFlows(t *testing.T) {
	h := newHarness(t, "schema-version: 1\nrouting: {block-quic: off}\n")
	session := associate(t, h.proxy())
	res := h.mustCommit(patch("/routing/block-quic", `"all"`))
	if res.NoChange || res.Plan == nil || !res.Plan.RoutingChanged || res.Plan.RulesChanged {
		t.Fatalf("block-quic commit did not activate a routing-only change: %+v", res)
	}
	destination := netip.MustParseAddrPort("127.0.0.2:443")
	session.send(destination, "datagram")
	records, scope := h.engine().History()
	waitFor(t, "block-quic flow history", 3*time.Second, func() bool {
		page, err := records.List(history.Connections, scope.ProfileID, history.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Rows) == 0 {
			return false
		}
		var trace api.ConnectionTrace
		if err := json.Unmarshal(page.Rows[0].Data, &trace); err != nil {
			t.Fatal(err)
		}
		if trace.Revision != res.Revision || trace.Destination != destination.String() ||
			trace.CloseReason != "rejected" || trace.RejectReason != "block-quic" || !trace.DialStartedAt.IsZero() {
			t.Fatalf("unexpected flow history: %s", page.Rows[0].Data)
		}
		return true
	})
}
