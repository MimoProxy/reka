//go:build with_gvisor

package packettunnel

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/runtime/generation"
)

func TestPacketTunnelHistoryLimits(t *testing.T) {
	session := newSession()
	t.Cleanup(session.cancel)
	t.Cleanup(session.device.endpoint.Close)
	// Two copies of the JSON string and 128 bytes of overhead use 4 KiB.
	large := strings.Repeat("x", 1982)
	now := time.Now()
	for _, kind := range []history.Kind{history.Connections, history.DNS, history.Logs, history.Requests} {
		for range 70 {
			session.events.Record(kind, history.Scope{}, now, "small", nil)
		}
		if got := session.events.Count(kind); got != 64 {
			t.Fatalf("%s history retained %d small rows, want 64", kind, got)
		}
		for range 70 {
			session.events.Record(kind, history.Scope{}, now, large, nil)
		}
	}
	for kind, want := range map[history.Kind]int{
		history.Connections: 48, history.DNS: 24, history.Logs: 24, history.Requests: 24,
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
