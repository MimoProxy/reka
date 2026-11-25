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
	wantFlows := TrafficFlows{SinceMS: initial.SinceMS, Flows: []TrafficFlowRow{
		{Host: peer.Destination, Policy: "Choice", Node: "Relay", TrafficTotals: want},
	}, Routes: []TrafficFlowRow{{Policy: "Choice", Node: "Relay", TrafficTotals: want}}}
	if got := readTrafficFlows(t, session, 0); !reflect.DeepEqual(got, wantFlows) {
		t.Fatalf("active flows: got %+v, want %+v", got, wantFlows)
	}

	closeRankedConnection(t, session, first[0].ID, 1)
	if got := readTrafficRanking(t, session, 0); !reflect.DeepEqual(got, initial) {
		t.Fatalf("traffic changed after TCP close: %+v; want %+v", got, initial)
	}
	if got := readTrafficFlows(t, session, 0); !reflect.DeepEqual(got, wantFlows) {
		t.Fatalf("active and closed flows: got %+v, want %+v", got, wantFlows)
	}
	if err := session.ReplaceProfile(prepareSnapshot(t, "rules: ['MATCH,DIRECT']\n"), controls); err != nil {
		t.Fatal(err)
	}
	if got := readTrafficRanking(t, session, 0); !reflect.DeepEqual(got, initial) {
		t.Fatalf("traffic changed after profile replacement: %+v; want %+v", got, initial)
	}
	if got := readTrafficFlows(t, session, 0); !reflect.DeepEqual(got, wantFlows) {
		t.Fatalf("flows changed after profile replacement: %+v, want %+v", got, wantFlows)
	}

	resetTrafficForTest(t, session)
	checkEmptyRanking(t, readTrafficRanking(t, session, 0))
	if got := readTrafficFlows(t, session, 0); got.Flows == nil || len(got.Flows) != 0 || got.Other != (TrafficTotals{}) {
		t.Fatalf("expected empty flows after reset, got %+v", got)
	}
	const extra = "more UDP traffic"
	echoPacketTestPayload(t, udp, []byte(extra))
	waitPacketTest(t, "traffic after reset", func() bool {
		up, down := session.Traffic()
		return up == bytes+uint64(len(extra)) && down == bytes+uint64(len(extra))
	})
	afterReset := readTrafficRanking(t, session, 0)
	want = TrafficTotals{Uploaded: uint64(len(extra)), Downloaded: uint64(len(extra)), Connections: 1}
	checkRankedTraffic(t, afterReset, peer.Destination, "Choice", "Relay", want)
	wantFlows.SinceMS = afterReset.SinceMS
	wantFlows.Flows[0].TrafficTotals = want
	wantFlows.Routes[0].TrafficTotals = want
	if got := readTrafficFlows(t, session, 0); !reflect.DeepEqual(got, wantFlows) {
		t.Fatalf("flows after reset and new traffic: got %+v, want %+v", got, wantFlows)
	}
	remaining := readConnectionRows(t, session)
	if len(remaining) != 1 {
		t.Fatalf("expected one active UDP connection, got %v", remaining)
	}
	closeRankedConnection(t, session, remaining[0].ID, 0)
	if got := readTrafficRanking(t, session, 0); !reflect.DeepEqual(got, afterReset) {
		t.Fatalf("traffic changed after UDP close: %+v; want %+v", got, afterReset)
	}
	if got := readTrafficFlows(t, session, 0); !reflect.DeepEqual(got, wantFlows) {
		t.Fatalf("flows changed after UDP close: %+v, want %+v", got, wantFlows)
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

func TestTrafficFlowsGroupByHostPolicyAndNode(t *testing.T) {
	session := startTrafficTestSession(t)
	for i, conn := range []struct {
		host, policy, node string
		upload, download   int64
	}{
		{"b.example.test", "Choice", "First", 6, 4},
		{"A.Example.Test.", "Other", "First", 6, 4},
		{"a.example.test", "Choice", "Second", 6, 4},
		{"a.example.test", "Choice", "First", 5, 3},
		{"a.example.test", "Choice", "First", 1, 1},
	} {
		session.ranking.recordClosed(trafficFlowTestConn(uint64(i+1), conn.host, conn.policy, conn.node, conn.upload, conn.download))
	}
	totals := TrafficTotals{Uploaded: 6, Downloaded: 4, Connections: 1}
	want := []TrafficFlowRow{
		{Host: "a.example.test", Policy: "Choice", Node: "First", TrafficTotals: TrafficTotals{Uploaded: 6, Downloaded: 4, Connections: 2}},
		{Host: "a.example.test", Policy: "Choice", Node: "Second", TrafficTotals: totals},
		{Host: "a.example.test", Policy: "Other", Node: "First", TrafficTotals: totals},
		{Host: "b.example.test", Policy: "Choice", Node: "First", TrafficTotals: totals},
	}
	flows := readTrafficFlows(t, session, 0)
	if !reflect.DeepEqual(flows.Flows, want) || flows.Other != (TrafficTotals{}) {
		t.Fatalf("flows: got %+v, want %+v", flows, want)
	}
	hostTotals := make(map[string]TrafficTotals)
	for _, row := range flows.Flows {
		total := hostTotals[row.Host]
		total.add(row.TrafficTotals)
		hostTotals[row.Host] = total
	}
	for _, host := range readTrafficRanking(t, session, 0).Hosts {
		if got := hostTotals[host.Name]; got != host.TrafficTotals {
			t.Fatalf("flows for %s: got %+v, want %+v", host.Name, got, host.TrafficTotals)
		}
	}
}

func TestTrafficFlowsEvictionAndLimitConserveTotals(t *testing.T) {
	session := startTrafficTestSession(t)
	const connections = maxTrafficFlows + 13
	totalsForFirst := func(n uint64) TrafficTotals {
		return TrafficTotals{Uploaded: n * (n + 1) / 2, Downloaded: n * (n + 1), Connections: n}
	}
	for i := 1; i <= connections; i++ {
		session.ranking.recordClosed(trafficFlowTestConn(uint64(i), "host.test", "policy", fmt.Sprintf("node-%d", i), int64(i), 2*int64(i)))
	}
	if table := session.ranking.flows; len(table.rows) != maxTrafficFlows || table.other != totalsForFirst(connections-maxTrafficFlows) {
		t.Fatalf("retained %d flows with overflow %+v", len(table.rows), table.other)
	}
	for _, test := range []struct{ request, want int }{{1, 1}, {0, 200}, {-1, 200}, {maxTrafficFlowLimit + 1, maxTrafficFlowLimit}} {
		flows := readTrafficFlows(t, session, test.request)
		if len(flows.Flows) != test.want {
			t.Fatalf("limit %d: got %d flows, want %d", test.request, len(flows.Flows), test.want)
		}
		if want := totalsForFirst(uint64(connections - test.want)); flows.Other != want {
			t.Fatalf("limit %d: got other %+v, want %+v", test.request, flows.Other, want)
		}
		got := flows.Other
		for i, flow := range flows.Flows {
			want := uint64(connections - i)
			if flow.TrafficTotals != (TrafficTotals{Uploaded: want, Downloaded: 2 * want, Connections: 1}) {
				t.Fatalf("limit %d: unexpected row %d: %+v", test.request, i, flow)
			}
			got.add(flow.TrafficTotals)
		}
		if want := totalsForFirst(connections); got != want {
			t.Fatalf("limit %d: got total %+v, want %+v", test.request, got, want)
		}
	}
	if got := session.ranking.flows.other; got != totalsForFirst(connections-maxTrafficFlows) {
		t.Fatalf("reading flows changed the session overflow to %+v", got)
	}
	resetTrafficForTest(t, session)
	if got := readTrafficFlows(t, session, 0); got.Flows == nil || len(got.Flows) != 0 || got.Other != (TrafficTotals{}) {
		t.Fatalf("expected empty flows and overflow after reset, got %+v", got)
	}
}

func TestTrafficFlowsFitBridgeResponse(t *testing.T) {
	session := startTrafficTestSession(t)
	totals := TrafficTotals{Uploaded: math.MaxUint64, Downloaded: math.MaxUint64, Connections: math.MaxUint64}
	session.ranking.sinceMS = math.MinInt64
	session.ranking.flows.other = totals
	host := strings.Repeat("<", maxTrafficHostName)
	// The ASCII characters let the six-byte escapes fill either quoted budget exactly.
	prefix := strings.Repeat("<", 15) + "abcd" + strings.Repeat("<", 5) + "ef"
	policy := prefix + strings.Repeat("<", maxTrafficOutboundName-len(prefix))
	for i := range maxTrafficFlowLimit {
		node := policy[:len(policy)-3] + fmt.Sprintf("%03d", i)
		session.ranking.flows.add(TrafficFlowRow{Host: host, Policy: policy, Node: node, TrafficTotals: totals})
	}
	session.ranking.routes.other = totals
	for i := range maxTrafficRoutes {
		node := policy[:len(policy)-3] + fmt.Sprintf("%03d", i)
		session.ranking.routes.add(TrafficFlowRow{Policy: policy, Node: node, TrafficTotals: totals})
	}
	flows := readTrafficFlows(t, session, maxTrafficFlowLimit)
	data, err := json.Marshal(flows)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 128<<10 || len(flows.Flows) != maxTrafficFlowLimit || len(flows.Routes) != maxTrafficRoutes {
		t.Fatalf("response contains %d flows and %d routes in %d bytes", len(flows.Flows), len(flows.Routes), len(data))
	}
}

func TestTrafficFlowsKeepDistinctLongNames(t *testing.T) {
	session := startTrafficTestSession(t)
	host := strings.Repeat("h", maxTrafficHostName)
	policy := strings.Repeat("p", maxTrafficOutboundName)
	node := strings.Repeat("n", maxTrafficOutboundName)
	suffixes := [][3]string{{"a", "a", "a"}, {"b", "a", "a"}, {"a", "b", "a"}, {"a", "a", "b"}}
	for i, suffix := range suffixes {
		session.ranking.recordClosed(trafficFlowTestConn(uint64(i+1), host+suffix[0], policy+suffix[1], node+suffix[2], 10, 0))
	}
	got := readTrafficFlows(t, session, 0)
	if len(got.Flows) != len(suffixes) || got.Other != (TrafficTotals{}) {
		t.Fatalf("long flow labels were merged: %+v", got)
	}
	for _, row := range got.Flows {
		if row != got.Flows[0] || row.TrafficTotals != (TrafficTotals{Uploaded: 10, Connections: 1}) {
			t.Fatalf("long flow labels did not retain separate totals behind the common display prefixes: %+v", got)
		}
	}
}

func trafficFlowTestConn(id uint64, host, policy, node string, upload, download int64) sagernet.ConnInfo {
	return sagernet.ConnInfo{ID: id, Upload: upload, Download: download, Info: &api.FlowInfo{
		DestinationDomain: host, PolicyName: policy, OutboundName: node,
	}}
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

func readTrafficFlows(t *testing.T, session *Session, limit int) TrafficFlows {
	t.Helper()
	result, err := session.RunOperation(Operation{Action: "trafficFlows", Limit: limit})
	if err != nil {
		t.Fatal(err)
	}
	return result.(TrafficFlows)
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

func TestTrafficFlowRoutesCoverHostsOutsideTheTopList(t *testing.T) {
	session := startTrafficTestSession(t)
	for i := range 5 {
		session.ranking.recordClosed(trafficFlowTestConn(uint64(i+1), fmt.Sprintf("h%d.test", i), "Proxy", "HK", int64(i+1), 0))
	}
	session.ranking.recordClosed(trafficFlowTestConn(6, "d.test", "DIRECT", "DIRECT", 2, 2))
	flows := readTrafficFlows(t, session, 2)
	want := []TrafficFlowRow{
		{Policy: "Proxy", Node: "HK", TrafficTotals: TrafficTotals{Uploaded: 15, Connections: 5}},
		{Policy: "DIRECT", Node: "DIRECT", TrafficTotals: TrafficTotals{Uploaded: 2, Downloaded: 2, Connections: 1}},
	}
	if len(flows.Flows) != 2 || !reflect.DeepEqual(flows.Routes, want) || flows.OtherRoutes != (TrafficTotals{}) {
		t.Fatalf("got flows %+v and routes %+v", flows.Flows, flows.Routes)
	}
	resetTrafficForTest(t, session)
	if got := readTrafficFlows(t, session, 0); len(got.Routes) != 0 {
		t.Fatalf("expected no routes after reset, got %+v", got.Routes)
	}
}
