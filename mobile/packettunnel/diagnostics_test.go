//go:build with_gvisor

package packettunnel

import (
	"slices"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/runtime/generation"
)

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
			trace := api.ConnectionTrace{
				Connection: api.Connection{ID: id, Start: start}, EndedAt: start.Add(time.Minute),
				Events: structured, EventsDropped: 5,
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
				return a.T == b.T && a.Kind == b.Kind
			}) || timeline.Trace.EventsDropped != 5 {
				t.Fatalf("unexpected structured timeline: %+v", timeline)
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
