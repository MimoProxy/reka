//go:build with_gvisor

package packettunnel

import (
	"io"
	"testing"
	"time"

	"github.com/MimoProxy/reka/mobile/profile"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
)

func TestProfileSwitchClosesPreviousProfileConnections(t *testing.T) {
	// The drop outbound keeps a flow open in memory until it is closed.
	const config = `schema-version: 1
groups: [{id: egress, type: select, members: [reject-drop]}]
rules: [{match: {all: true}, outbound: egress}]
`
	snapshot := prepareSnapshot(t, config)
	first := profile.Controls{Mode: "rule", ProfileID: "first"}
	session, err := StartProfile(snapshot, first, false)
	if err != nil {
		t.Fatal(err)
	}
	client, ctx := attachTestClient(t, session, "172.27.255.2")
	open := func() {
		t.Helper()
		conn, err := gonet.DialContextTCP(ctx, client, packetTestAddress("192.0.2.1", 443), ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetWriteDeadline(time.Now().Add(4 * time.Second))
		if _, err := io.WriteString(conn, "hello"); err != nil {
			t.Fatal(err)
		}
	}
	open()
	waitPacketTest(t, "the first connection", func() bool { return len(readConnectionRows(t, session)) == 1 })

	// Refreshing the same profile keeps its connections draining.
	if err := session.ReplaceProfile(snapshot, first); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if rows := readConnectionRows(t, session); len(rows) != 1 {
		t.Fatalf("refresh of the same profile left %d connections, want 1", len(rows))
	}

	// Switching to another profile closes the previous profile's flows.
	if err := session.ReplaceProfile(snapshot, profile.Controls{Mode: "rule", ProfileID: "second"}); err != nil {
		t.Fatal(err)
	}
	waitPacketTest(t, "the previous profile's connection to close", func() bool {
		return len(readConnectionRows(t, session)) == 0
	})
	open()
	waitPacketTest(t, "a connection on the new profile", func() bool { return len(readConnectionRows(t, session)) == 1 })
}
