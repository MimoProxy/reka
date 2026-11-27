//go:build with_gvisor

package packettunnel

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/platform"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/mobile/profile"
)

func TestPacketTunnelHistoryLimits(t *testing.T) {
	session := newSession()
	t.Cleanup(session.cancel)
	t.Cleanup(session.device.endpoint.Close)
	// Two copies of the JSON string and 128 bytes of overhead use 4 KiB.
	large := strings.Repeat("x", 1982)
	now := time.Now()
	rows := map[history.Kind]int{
		history.Connections: eventRows, history.DNS: eventRows, history.Logs: eventRows, history.Requests: requestEventRows,
		history.Scripts: scriptEventRows,
	}
	for kind, want := range rows {
		for range want + 6 {
			session.events.Record(kind, history.Scope{}, now, "small", nil)
		}
		if got := session.events.Count(kind); got != want {
			t.Fatalf("%s history retained %d small rows, want %d", kind, got, want)
		}
		for range want + 6 {
			session.events.Record(kind, history.Scope{}, now, large, nil)
		}
	}
	for kind, want := range map[history.Kind]int{
		history.Connections: 48, history.DNS: 24, history.Logs: 24, history.Requests: 80, history.Scripts: 48,
	} {
		if got := session.events.Count(kind); got != want {
			t.Errorf("%s history retained %d large rows, want %d", kind, got, want)
		}
	}
}

func TestPacketTunnelTimelineLimitsLinkedRows(t *testing.T) {
	for _, tt := range []struct {
		name    string
		dnsRows int
		wantDNS []int
	}{
		{name: "http limit"},
		{name: "combined limit", dnsRows: 28, wantDNS: []int{1, 2, 3, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			records := history.NewBounded(eventRows, eventBytes)
			engine := generation.NewEngine(generation.EngineOptions{HostPacketFlow: true, PacketHistory: records})
			t.Cleanup(engine.Close)
			session := &Session{ctx: t.Context(), profile: &profileSession{engine: engine}}
			const id = 1
			start := time.Now().UTC().Add(-time.Minute)
			structured := make([]api.ConnEvent, 24)
			for i := range structured {
				structured[i] = api.ConnEvent{T: int64(i), Kind: "dial"}
			}
			ms := 0.2
			structured[22] = api.ConnEvent{T: 22, Kind: "connect", Addr: "192.0.2.1:443"}
			structured[23] = api.ConnEvent{
				T: 23, Kind: "connected", Addr: "192.0.2.1:443", Peer: "192.0.2.2:50000", Name: "test0", MS: &ms,
			}
			trace := api.ConnectionTrace{
				Connection: api.Connection{ID: id, Start: start}, EndedAt: start.Add(time.Minute),
				Events: structured, EventsDropped: 5,
				ServerAddr: structured[23].Addr, LocalAddr: structured[23].Peer, Interface: structured[23].Name,
			}
			records.RecordFlow(history.Connections, trace.Scope, start, id, trace, nil)
			recordLinked := func(kind history.Kind, offset int) {
				at := start.Add(time.Duration(offset) * time.Second)
				row := struct {
					Start time.Time `json:"start"`
				}{at}
				records.RecordFlow(kind, trace.Scope, at, id, row, nil)
			}
			for i := 1; i <= 12; i++ {
				recordLinked(history.Requests, i)
			}
			const dnsOffset = 19
			for i := 1; i <= tt.dnsRows; i++ {
				recordLinked(history.DNS, dnsOffset+i)
			}

			value, err := session.RunOperation(Operation{Action: "timeline", ID: id})
			if err != nil {
				t.Fatal(err)
			}
			timeline := value.(api.ConnectionTimeline)
			if !timeline.Truncated || timeline.Live || !slices.EqualFunc(timeline.Trace.Events, structured, func(a, b api.ConnEvent) bool {
				return a.T == b.T && a.Kind == b.Kind && a.Addr == b.Addr && a.Peer == b.Peer && a.Name == b.Name
			}) || timeline.Trace.EventsDropped != 5 {
				t.Fatalf("unexpected structured timeline: %+v", timeline)
			}
			connected := timeline.Trace.Events[23]
			if timeline.Trace.ServerAddr != trace.ServerAddr || timeline.Trace.LocalAddr != trace.LocalAddr ||
				timeline.Trace.Interface != trace.Interface || connected.MS == nil || *connected.MS != ms {
				t.Fatalf("unexpected socket diagnostics: %+v", timeline.Trace)
			}
			wantHTTP := []int{1, 2, 3, 4, 9, 10, 11, 12}
			events := timeline.Events
			if len(events) != 2+len(wantHTTP)+len(tt.wantDNS) ||
				events[0].Stage != "accepted" || events[len(events)-1].Stage != "closed" {
				t.Fatalf("unexpected legacy timeline: %+v", events)
			}
			var gotHTTP, gotDNS []int
			for _, event := range events {
				offset := int(event.At.Sub(start) / time.Second)
				switch event.Stage {
				case "http":
					gotHTTP = append(gotHTTP, offset)
				case "dns":
					gotDNS = append(gotDNS, offset-dnsOffset)
				}
			}
			if !slices.Equal(gotHTTP, wantHTTP) || !slices.Equal(gotDNS, tt.wantDNS) {
				t.Fatalf("retained HTTP = %v, DNS = %v, want HTTP = %v, DNS = %v", gotHTTP, gotDNS, wantHTTP, tt.wantDNS)
			}
		})
	}
}

func TestPacketTunnelHistoryPreservesMITMFields(t *testing.T) {
	records := history.NewBounded(eventRows, eventBytes)
	engine := generation.NewEngine(generation.EngineOptions{HostPacketFlow: true, PacketHistory: records})
	t.Cleanup(engine.Close)
	session := &Session{ctx: t.Context(), events: records, profile: &profileSession{engine: engine}}
	const id = 42
	start := time.Now().UTC().Add(-time.Second)
	trace := api.ConnectionTrace{
		Connection: api.Connection{
			ID: id, Start: start,
			MITMConnectionInfo: api.MITMConnectionInfo{
				MITM: true, MITMRequests: 2, MITMMatchedIDs: []string{"rewrite"}, MITMBodyPassthroughs: 1,
				MITMClientProtocol: "h2", MITMUpstreamProtocols: []string{"http/1.1", "h2"},
			},
		},
		EndedAt: start.Add(time.Second),
	}
	records.RecordFlow(history.Connections, trace.Scope, start, id, trace, nil)
	requestFields := map[string]string{
		"mitm": "true", "connection_id": "42", "matched_ids": `["rewrite"]`, "body_passthroughs": "1", "resource_error": "true",
	}
	for i, path := range []string{"/small", "/" + strings.Repeat("a", 800)} {
		at := start.Add(time.Duration(i+1) * time.Millisecond)
		row := map[string]any{"start": at, "path": path}
		for key, value := range requestFields {
			row[key] = json.RawMessage(value)
		}
		records.RecordFlow(history.Requests, trace.Scope, at, id, row, nil)
	}
	run := func(op Operation) any {
		t.Helper()
		value, err := session.RunOperation(op)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	assertFields := func(raw []byte, want map[string]string) map[string]json.RawMessage {
		t.Helper()
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		for field, expected := range want {
			if string(fields[field]) != expected {
				t.Errorf("%s = %s, want %s", field, fields[field], expected)
			}
		}
		return fields
	}
	connections := run(Operation{Action: "connectionHistory"}).(history.Page)
	if len(connections.Rows) != 1 {
		t.Fatalf("connection history has %d rows, want 1", len(connections.Rows))
	}
	connectionFields := map[string]string{
		"mitm": "true", "mitm_requests": "2", "mitm_matched_ids": `["rewrite"]`, "mitm_body_passthroughs": "1",
		"mitm_client_protocol": `"h2"`, "mitm_upstream_protocols": `["http/1.1","h2"]`,
	}
	assertFields(connections.Rows[0].Data, connectionFields)
	requests := run(Operation{Action: "requestHistory"}).(history.Page)
	if len(requests.Rows) != 2 {
		t.Fatalf("request history has %d rows, want 2", len(requests.Rows))
	}
	for _, row := range requests.Rows {
		if assertFields(row.Data, requestFields)["path"] == nil {
			t.Error("request history lost the request path")
		}
	}
	timeline, err := json.Marshal(run(Operation{Action: "timeline", ID: id}))
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Connection json.RawMessage     `json:"connection"`
		Events     []api.TimelineEvent `json:"events"`
	}
	if err := json.Unmarshal(timeline, &data); err != nil {
		t.Fatal(err)
	}
	assertFields(data.Connection, connectionFields)
	var httpRows int
	for _, event := range data.Events {
		if event.Stage != "http" {
			continue
		}
		httpRows++
		assertFields(event.Data, requestFields)
	}
	if httpRows != 2 {
		t.Fatalf("timeline has %d HTTP rows, want 2", httpRows)
	}
}

func TestExpandedRulePageContinuationAndSearch(t *testing.T) {
	var builder router.ConditionSetBuilder
	for i := range rulePageScanLimit + 3 {
		if err := builder.AddDomain(router.KindDomain, fmt.Sprintf("entry-%04d.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	set, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	var first rulePage
	first.readEntries(set, ruleDiagnostics{}, 0, 2)
	if len(first.Rules) != 2 || first.Next == nil || *first.Next != 2 ||
		first.Rules[0].Description != "DOMAIN,entry-0000.test," {
		t.Fatalf("first page: %+v", first)
	}
	var second rulePage
	second.readEntries(set, ruleDiagnostics{}, *first.Next, 2)
	if len(second.Rules) != 2 || second.Rules[0].Index != 2 || second.Rules[0].Description != "DOMAIN,entry-0002.test," {
		t.Fatalf("second page: %+v", second)
	}
	var search rulePage
	search.readEntries(set, ruleDiagnostics{search: "entry-2002.test"}, 0, 2)
	if len(search.Rules) != 0 || search.Next == nil || *search.Next != rulePageScanLimit {
		t.Fatalf("first search page: %+v", search)
	}
	var last rulePage
	last.readEntries(set, ruleDiagnostics{search: "entry-2002.test"}, *search.Next, 2)
	if len(last.Rules) != 1 || last.Rules[0].Description != "DOMAIN,entry-2002.test," || last.Next != nil {
		t.Fatalf("last search page: %+v", last)
	}
}

func TestRuleDiagnosticsListsDirectReferencesAndOpensNestedASN(t *testing.T) {
	const asn = "asn:399358"
	var builder router.ConditionSetBuilder
	if err := builder.Add(router.RuleSpec{Kind: router.KindIPCIDR, Values: []string{"192.0.2.0/24", "2001:db8::/32"}}); err != nil {
		t.Fatal(err)
	}
	child, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	child = child.WithEntryDiagnostics()
	nested := router.RuleSpec{Kind: router.KindRuleSet, Values: []string{asn}, Set: child}
	if err := builder.Add(nested); err != nil {
		t.Fatal(err)
	}
	parent, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, direct := range []bool{false, true} {
		specs := []router.RuleSpec{
			{Kind: router.KindGeoIP, Values: []string{"LAN"}, NoResolve: true, Target: "direct"},
			{Kind: router.KindRuleSet, Values: []string{"anthropic"}, Set: parent, Target: "direct"},
		}
		if direct {
			nested.Target = "direct"
			specs = append(specs, nested)
		}
		rules, err := router.CompileRules(specs)
		if err != nil {
			t.Fatal(err)
		}
		r, err := router.New(rules, router.Options{Outbounds: []string{"direct"}, Final: "direct"})
		if err != nil {
			t.Fatal(err)
		}
		base := &compile.Effective{
			Router: r, Final: "direct", Routing: model.Routing{Mode: "rule"},
			Network:          platform.Network{Mode: "off"},
			Outbounds:        []compile.Outbound{{ID: "direct", Type: "direct", Builtin: true, UDP: true}},
			RuleSetSelectors: map[string]string{asn: asn},
		}
		engine := generation.NewEngine(generation.EngineOptions{HostPacketFlow: true})
		t.Cleanup(engine.Close)
		p := &profileSession{base: base, sets: collectRuleSets(rules), engine: engine}
		if err := p.publish(base, profile.Describe(base), profile.Controls{Mode: "rule"}); err != nil {
			t.Fatal(err)
		}
		index := p.ruleSets()
		want := []ruleSetRow{{ID: "anthropic", Count: 1}}
		if direct {
			want = append(want, ruleSetRow{ID: asn, Selector: asn, Count: 2})
		}
		if !slices.Equal(index, want) {
			t.Fatalf("direct=%v index=%+v want %+v", direct, index, want)
		}
		root, err := p.rules(Operation{})
		if err != nil || len(root.Rules) != len(specs) || !root.Rules[0].BuiltinLAN || len(root.Rules[0].References) != 0 ||
			!slices.Equal(root.Rules[1].References, want[:1]) {
			t.Fatalf("root=%+v err=%v", root, err)
		}
		nestedPage, err := p.rules(Operation{Target: "anthropic"})
		if err != nil || nestedPage.Total != 1 || len(nestedPage.Rules) != 1 ||
			!slices.Equal(nestedPage.Rules[0].References, []ruleSetRow{{ID: asn, Selector: asn, Count: 2}}) {
			t.Fatalf("parent=%+v err=%v", nestedPage, err)
		}
		first, err := p.rules(Operation{Target: asn, Limit: 1})
		if err != nil || len(first.Rules) != 1 || first.Rules[0].Description != "IP-CIDR,192.0.2.0/24," || first.Next == nil || first.Total != 2 {
			t.Fatalf("first ASN page=%+v err=%v", first, err)
		}
		second, err := p.rules(Operation{Target: asn, Offset: *first.Next, Limit: 1})
		if err != nil || len(second.Rules) != 1 || second.Rules[0].Description != "IP-CIDR,2001:db8::/32," || second.Next != nil || second.Total != 2 {
			t.Fatalf("second ASN page=%+v err=%v", second, err)
		}
	}
}
