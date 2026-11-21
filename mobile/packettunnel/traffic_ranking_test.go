//go:build with_gvisor

package packettunnel

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/mobile/profile"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
)

func TestTrafficRankingAcrossCloseAndProfileReplacement(t *testing.T) {
	peer := startPacketTestPeer(t)
	controls := profile.Controls{Mode: "rule"}
	session, err := StartProfile(packetTestProfile(t, peer), controls, false)
	if err != nil {
		t.Fatal(err)
	}
	client, ctx := attachTestClient(t, session, "172.27.255.2")
	dialPacketTestTCP(t, ctx, client, packetTestAddress(peer.Destination, peer.TCPPort))
	first := readConnectionRows(t, session)
	if len(first) != 1 {
		t.Fatalf("expected one active TCP connection, got %v", first)
	}
	dest := packetTestAddress(peer.Destination, peer.UDPPort)
	udp, err := gonet.DialUDP(client, nil, &dest, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	echoPacketTestPayload(t, udp, []byte("echo over UDP"))

	const bytes = uint64(len("echo") + len("echo over UDP"))
	waitPacketTest(t, "relayed traffic", func() bool {
		up, down := session.Traffic()
		return up == bytes && down == bytes
	})
	initial := readTrafficRanking(t, session, 0)
	want := TrafficTotals{Uploaded: bytes, Downloaded: bytes, Connections: 2}
	checkRankedTraffic(t, initial, peer.Destination, "Choice", "Relay", want)

	closeRankedConnection(t, session, first[0].ID, 1)
	if got := readTrafficRanking(t, session, 0); !reflect.DeepEqual(got, initial) {
		t.Fatalf("traffic changed after TCP close: %+v; want %+v", got, initial)
	}
	if err := session.ReplaceProfile(prepareSnapshot(t, "rules: ['MATCH,DIRECT']\n"), controls); err != nil {
		t.Fatal(err)
	}
	if got := readTrafficRanking(t, session, 0); !reflect.DeepEqual(got, initial) {
		t.Fatalf("traffic changed after profile replacement: %+v; want %+v", got, initial)
	}

	resetTrafficForTest(t, session)
	checkEmptyRanking(t, readTrafficRanking(t, session, 0))
	const extra = "more UDP traffic"
	echoPacketTestPayload(t, udp, []byte(extra))
	waitPacketTest(t, "traffic after reset", func() bool {
		up, down := session.Traffic()
		return up == bytes+uint64(len(extra)) && down == bytes+uint64(len(extra))
	})
	afterReset := readTrafficRanking(t, session, 0)
	checkRankedTraffic(t, afterReset, peer.Destination, "Choice", "Relay",
		TrafficTotals{Uploaded: uint64(len(extra)), Downloaded: uint64(len(extra)), Connections: 1})
	remaining := readConnectionRows(t, session)
	if len(remaining) != 1 {
		t.Fatalf("expected one active UDP connection, got %v", remaining)
	}
	closeRankedConnection(t, session, remaining[0].ID, 0)
	if got := readTrafficRanking(t, session, 0); !reflect.DeepEqual(got, afterReset) {
		t.Fatalf("traffic changed after UDP close: %+v; want %+v", got, afterReset)
	}
}

func TestTrafficRankingBoundsLimitAndReset(t *testing.T) {
	session := startTrafficTestSession(t)
	const connections = maxTrafficHosts + 13
	var total TrafficTotals
	for i := 1; i <= connections; i++ {
		conn := sagernet.ConnInfo{
			ID: uint64(i), Upload: int64(i), Download: int64(i) * 2,
			Metadata: sagernet.Metadata{Destination: sagernet.Destination{Domain: fmt.Sprintf("host-%d.test", i)}},
			Outbound: fmt.Sprintf("outbound-%d", i),
		}
		session.ranking.recordClosed(conn)
		total.add(TrafficTotals{Uploaded: uint64(i), Downloaded: uint64(i) * 2, Connections: 1})
	}
	for _, test := range []struct {
		table trafficTable
		cap   int
	}{
		{session.ranking.hosts, maxTrafficHosts},
		{session.ranking.outbounds, maxTrafficOutbounds},
	} {
		if len(test.table.rows) != test.cap {
			t.Fatalf("retained %d names, want %d", len(test.table.rows), test.cap)
		}
		rest := uint64(connections - test.cap)
		wantOther := TrafficTotals{Uploaded: rest * (rest + 1) / 2, Downloaded: rest * (rest + 1), Connections: rest}
		if test.table.other != wantOther {
			t.Fatalf("overflow = %+v, want %+v", test.table.other, wantOther)
		}
		got := test.table.other
		for _, row := range test.table.rows {
			got.add(row.TrafficTotals)
		}
		if got != total {
			t.Fatalf("traffic was lost during eviction: %+v, want %+v", got, total)
		}
	}
	for _, test := range []struct{ request, want int }{{1, 1}, {3, 3}, {0, 50}, {250, 200}} {
		ranking := readTrafficRanking(t, session, test.request)
		if len(ranking.Hosts) != test.want || len(ranking.Outbounds) != test.want {
			t.Fatalf("limit %d: got %d hosts and %d outbounds, want %d of each", test.request,
				len(ranking.Hosts), len(ranking.Outbounds), test.want)
		}
		for i, host := range ranking.Hosts {
			if want := uint64(connections - i); host.Uploaded != want || ranking.Outbounds[i].Downloaded != 2*want {
				t.Fatalf("unexpected order at row %d: host %+v, outbound %+v", i, host, ranking.Outbounds[i])
			}
		}
		if ranking.Other != session.ranking.hosts.other || ranking.OtherOutbounds != session.ranking.outbounds.other {
			t.Fatal("changing limit affected overflow totals")
		}
	}
	session.ranking.sinceMS = 1
	beforeReset := time.Now().UnixMilli()
	resetTrafficForTest(t, session)
	cleared := readTrafficRanking(t, session, 0)
	checkEmptyRanking(t, cleared)
	if cleared.SinceMS < beforeReset || cleared.SinceMS > time.Now().UnixMilli() {
		t.Fatalf("invalid reset time: %d", cleared.SinceMS)
	}
}

func TestTrafficRankingUsesRoutingLabelsAndNewestNode(t *testing.T) {
	session := startTrafficTestSession(t)
	ip := netip.MustParseAddr("2001:db8::1")
	conn := sagernet.ConnInfo{
		ID: 1, Outbound: "new-node", Start: time.UnixMilli(20), Upload: 2, Download: 3,
		Metadata: sagernet.Metadata{Destination: sagernet.Destination{Addr: ip, Port: 443}},
		Info: &api.FlowInfo{
			DestinationDomain: "Route.Example.Test.", SniffedDomain: "sniff.example.test",
			Chain: []string{"group"}, PolicyName: "Choice", OutboundName: "New node",
		},
	}
	session.ranking.recordClosed(conn)
	conn.ID, conn.Outbound, conn.Start = 2, "old-node", time.UnixMilli(10)
	conn.Info = &api.FlowInfo{SniffedDomain: "sniff.example.test", Chain: []string{"group"}, PolicyName: "Choice", OutboundName: "Old node"}
	session.ranking.recordClosed(conn)
	conn.ID, conn.Outbound, conn.Info = 3, "direct", nil
	session.ranking.recordClosed(conn)
	ranking := readTrafficRanking(t, session, 0)
	if len(ranking.Hosts) != 3 || ranking.Hosts[0].Name != ip.String() || ranking.Hosts[1].Name != "route.example.test" ||
		ranking.Hosts[2].Name != "sniff.example.test" {
		t.Fatalf("unexpected destination names: %+v", ranking.Hosts)
	}
	want := TrafficRow{Name: "Choice", Node: "New node", TrafficTotals: TrafficTotals{Uploaded: 4, Downloaded: 6, Connections: 2}}
	if len(ranking.Outbounds) != 2 || ranking.Outbounds[0] != want || ranking.Outbounds[1].Node != "direct" {
		t.Fatalf("unexpected policy and node names: %+v", ranking.Outbounds)
	}
}

func TestTrafficRankingFitsBridgeResponse(t *testing.T) {
	session := startTrafficTestSession(t)
	totals := TrafficTotals{Uploaded: math.MaxUint64, Downloaded: math.MaxUint64, Connections: math.MaxUint64}
	for i := range maxTrafficLimit {
		name := fmt.Sprintf("%03d", i) + strings.Repeat("<>&\x00\u2028", 50)
		session.ranking.hosts.add(trafficEntry{TrafficRow: TrafficRow{Name: name, TrafficTotals: totals}}, maxTrafficHostName)
		session.ranking.outbounds.add(trafficEntry{TrafficRow: TrafficRow{Name: name, Node: name, TrafficTotals: totals}}, maxTrafficOutboundName)
	}
	ranking := readTrafficRanking(t, session, maxTrafficLimit)
	data, err := json.Marshal(ranking)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 128<<10 || len(ranking.Hosts) != maxTrafficLimit || len(ranking.Outbounds) != maxTrafficLimit {
		t.Fatalf("response contains %d hosts and %d outbounds in %d bytes", len(ranking.Hosts), len(ranking.Outbounds), len(data))
	}
}

func TestTrafficRankingKeepsDistinctLongNames(t *testing.T) {
	var ranking trafficRanking
	prefix := strings.Repeat("a", maxTrafficOutboundName)
	for i := range 2 {
		ranking.recordClosed(sagernet.ConnInfo{
			ID: uint64(i + 1), Outbound: fmt.Sprintf("%s%d", prefix, i), Upload: 10,
		})
	}
	rows := ranking.outbounds.top(maxTrafficOutbounds, maxTrafficLimit)
	if len(rows) != 2 || rows[0].Connections != 1 || rows[1].Connections != 1 {
		t.Fatalf("long names were merged: %+v", rows)
	}
}

func startTrafficTestSession(t *testing.T) *Session {
	t.Helper()
	session, err := StartProbeProfile(prepareSnapshot(t, "rules: ['MATCH,DIRECT']\n"), profile.Controls{Mode: "rule"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	return session
}

func readTrafficRanking(t *testing.T, session *Session, limit int) TrafficRanking {
	t.Helper()
	result, err := session.RunOperation(Operation{Action: "trafficRanking", Limit: limit})
	if err != nil {
		t.Fatal(err)
	}
	return result.(TrafficRanking)
}

func resetTrafficForTest(t *testing.T, session *Session) {
	t.Helper()
	if result, err := session.RunOperation(Operation{Action: "resetTrafficRanking"}); result != true || err != nil {
		t.Fatalf("reset: %v, %v", result, err)
	}
}

func checkEmptyRanking(t *testing.T, ranking TrafficRanking) {
	t.Helper()
	if ranking.Hosts == nil || ranking.Outbounds == nil || len(ranking.Hosts)+len(ranking.Outbounds) != 0 ||
		ranking.Other != (TrafficTotals{}) || ranking.OtherOutbounds != (TrafficTotals{}) {
		t.Fatalf("expected empty ranking, got %+v", ranking)
	}
}

func checkRankedTraffic(t *testing.T, ranking TrafficRanking, host, policy, node string, totals TrafficTotals) {
	t.Helper()
	if len(ranking.Hosts) != 1 || len(ranking.Outbounds) != 1 || ranking.Other != (TrafficTotals{}) ||
		ranking.Hosts[0] != (TrafficRow{Name: host, TrafficTotals: totals}) ||
		ranking.Outbounds[0] != (TrafficRow{Name: policy, Node: node, TrafficTotals: totals}) {
		t.Fatalf("unexpected ranking for %s and %s: %+v", host, policy, ranking)
	}
}

func closeRankedConnection(t *testing.T, session *Session, id uint64, remaining int) {
	t.Helper()
	if result, err := session.RunOperation(Operation{Action: "close", ID: id}); result != true || err != nil {
		t.Fatalf("close: %v, %v", result, err)
	}
	waitPacketTest(t, "connection removal", func() bool {
		count, _ := session.Counts()
		return count == remaining
	})
}

func waitPacketTest(t *testing.T, name string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", name)
		}
		time.Sleep(time.Millisecond)
	}
}
