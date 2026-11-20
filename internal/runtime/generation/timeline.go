package generation

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
)

func (e *Engine) ConnectionTimeline(id uint64) (api.ConnectionTimeline, bool) {
	store, scope := e.History()
	trace, found := e.backend.ConnectionTrace(id, scope.ProfileID)
	rows, truncated := store.FlowRows(scope.ProfileID, id)
	if closed := rows[history.Connections]; len(closed) != 0 {
		trace = api.ConnectionTrace{}
		found = json.Unmarshal(closed[0].Data, &trace) == nil
	}
	if !found {
		return api.ConnectionTimeline{}, false
	}
	result := api.ConnectionTimeline{Epoch: store.Epoch(), Live: trace.EndedAt.IsZero(), Trace: trace, Truncated: truncated}
	for _, stage := range []api.TimelineEvent{
		{Stage: "accepted", At: trace.Start},
		{Stage: "sniff-start", At: trace.SniffStartedAt},
		{Stage: "sniff-finish", At: trace.SniffFinishedAt},
		{Stage: "routed", At: trace.RoutedAt},
		{Stage: "dial-start", At: trace.DialStartedAt},
		{Stage: "dial-finish", At: trace.DialFinishedAt},
		{Stage: "closed", At: trace.EndedAt},
	} {
		if !stage.At.IsZero() {
			result.Events = append(result.Events, stage)
		}
	}
	for _, kind := range []history.Kind{history.DNS, history.Requests} {
		stage := "dns"
		if kind == history.Requests {
			stage = "http"
		}
		for _, row := range rows[kind] {
			var summary struct {
				Start time.Time `json:"start"`
			}
			if json.Unmarshal(row.Data, &summary) == nil && !summary.Start.IsZero() {
				result.Events = append(result.Events, api.TimelineEvent{Stage: stage, At: summary.Start, Cursor: row.Cursor, Data: row.Data})
			}
		}
	}
	slices.SortStableFunc(result.Events, func(a, b api.TimelineEvent) int { return a.At.Compare(b.At) })
	return result, true
}
