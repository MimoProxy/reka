//go:build with_gvisor

package packettunnel

import (
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/router"
)

func (s *Session) historyPage(kind history.Kind, op Operation) (history.Page, error) {
	profile := s.historyProfile()
	if kind == history.Logs {
		profile = ""
	}
	limit := op.Limit
	if limit <= 0 || limit > eventRows {
		limit = eventRows
	}
	return s.events.List(kind, profile, history.ListOptions{Before: op.Cursor, Limit: limit, Query: op.Search})
}

func (s *Session) runDiagnostics(op Operation) (any, error) {
	switch op.Action {
	case "profileStart":
		if err := startRuntimeProfile(time.Duration(op.TimeoutMS) * time.Millisecond); err != nil {
			return nil, err
		}
		return true, nil
	case "profileRead":
		return readRuntimeProfile(op.Category, op.Offset)
	case "processSample":
		return s.processSample(), nil
	case "flowLimits":
		var stats sagernet.PacketFlowStats
		if s.tunnel != nil {
			stats = s.tunnel.Stats()
		}
		return FlowLimits{stats, s.device.written.Load(), s.device.dropped.Load()}, nil
	case "connectionHistory":
		return s.historyPage(history.Connections, op)
	case "requestHistory":
		return s.historyPage(history.Requests, op)
	case "requestDetail":
		detail, ok := s.events.Detail(history.Requests, s.historyProfile(), op.Cursor)
		if !ok {
			return nil, errors.New("request details have expired")
		}
		return json.RawMessage(detail), nil
	case "clearHistory":
		kind := history.Kind(op.Category)
		switch kind {
		case history.Connections, history.DNS, history.Requests:
			return s.events.Clear(kind, s.historyProfile()), nil
		case history.Logs:
			return s.events.Clear(kind, ""), nil
		default:
			return nil, errors.New("unknown history category")
		}
	case "closeMany":
		if len(op.IDs) == 0 || len(op.IDs) > maxTCP+maxUDP || slices.Contains(op.IDs, 0) {
			return nil, errors.New("select at least one connection")
		}
		if s.profile == nil {
			return s.backend.CloseConnections(op.IDs), nil
		}
		return s.profile.engine.CloseConnections(op.IDs), nil
	}
	if s.profile == nil {
		return nil, errors.New("the operation requires a profile")
	}
	engine := s.profile.engine
	switch op.Action {
	case "mitmStatus":
		return engine.MITMStatus(), nil
	case "timeline":
		timeline, ok := engine.ConnectionTimeline(op.ID)
		if !ok {
			return nil, errors.New("connection history has expired")
		}
		trimTimelineEvents(&timeline)
		// Keep linked summaries small. DNS and HTTP details can be requested
		// independently through the corresponding history page.
		for i := range timeline.Events {
			event := &timeline.Events[i]
			if len(event.Data) <= 768 {
				continue
			}
			var label struct {
				Name             string          `json:"name,omitempty"`
				Host             string          `json:"host,omitempty"`
				Type             string          `json:"type,omitempty"`
				Status           int             `json:"status_code,omitempty"`
				MITM             json.RawMessage `json:"mitm,omitempty"`
				ConnectionID     json.RawMessage `json:"connection_id,omitempty"`
				MatchedIDs       json.RawMessage `json:"matched_ids,omitempty"`
				BodyPassthroughs json.RawMessage `json:"body_passthroughs,omitempty"`
				ResourceError    json.RawMessage `json:"resource_error,omitempty"`
			}
			if json.Unmarshal(event.Data, &label) == nil {
				event.Data, _ = json.Marshal(label)
			} else {
				event.Data = nil
			}
		}
		return timeline, nil
	case "rules":
		return s.profile.rules(op)
	case "ruleSets":
		return s.profile.ruleSets(), nil
	case "explain":
		target := strings.TrimSpace(op.Target)
		if len(target) == 0 || len(target) > 280 || strings.ContainsAny(target, " /\\?#@\r\n\t") {
			return nil, errors.New("enter a valid domain or IP address")
		}
		if _, _, err := net.SplitHostPort(target); err != nil {
			target = net.JoinHostPort(strings.Trim(target, "[]"), "443")
		}
		explanation, err := engine.Explain(s.ctx, api.ExplainRequest{
			Destination: target, Network: op.Network, Resolve: op.Resolve, Inbound: "tun", InboundType: "tun",
		})
		return explanation, err
	case "temporaryRules":
		return engine.ListTemporaryRules(), nil
	case "addTemporaryRule":
		if len(op.Rule) > 1024 {
			return nil, errors.New("temporary rules are limited to 1024 bytes")
		}
		s.profile.mu.Lock()
		names := s.profile.summary.Names
		s.profile.mu.Unlock()
		return engine.AddNamedTemporaryRule(api.TemporaryRuleRequest{Rule: op.Rule, TTLSeconds: op.TTLSeconds}, names)
	case "removeTemporaryRule":
		return engine.RemoveTemporaryRule(op.Target), nil
	case "queryDNS":
		if op.DNS == nil {
			return nil, errors.New("a DNS question is required")
		}
		return engine.QueryDNS(s.ctx, *op.DNS)
	case "flushDNS":
		return engine.FlushDNSCache(), nil
	case "resetNetwork":
		cleared := engine.ResetNetwork()
		s.logger.Info("Network diagnostics reset")
		return cleared, nil
	case "groupHealth":
		return engine.GroupHealth(op.Target, op.Offset, 64), nil
	case "arena":
		return engine.RunArena(s.ctx, api.ArenaRequest{Outbounds: op.Members, URL: op.URL, TimeoutMS: op.TimeoutMS, Rounds: op.Rounds})
	case "scene":
		return engine.NetworkScene(), nil
	case "setScene":
		return engine.SetNetworkScene(op.Target)
	case "debugStatus":
		return engine.HTTPSDebugStatus(), nil
	case "startDebug":
		if len(op.Members) == 0 || len(op.Members) > 8 {
			return nil, errors.New("enter one to eight authorized targets")
		}
		return engine.StartHTTPSDebug(api.HTTPSDebugRequest{Targets: op.Members, AllowHTTP: true, MaxClients: 4})
	case "stopDebug":
		engine.StopHTTPSDebug()
		return true, nil
	default:
		return nil, errors.New("unknown packet tunnel operation")
	}
}

func trimTimelineEvents(timeline *api.ConnectionTimeline) {
	const httpKeepEachEnd = 4
	const timelineKeepEachEnd = 12
	httpCount := 0
	for _, event := range timeline.Events {
		if event.Stage == "http" {
			httpCount++
		}
	}
	if httpCount > 2*httpKeepEachEnd {
		// Trim HTTP first to leave room for the other rows.
		kept := timeline.Events[:0]
		seen := 0
		for _, event := range timeline.Events {
			if event.Stage == "http" {
				seen++
				if seen > httpKeepEachEnd && seen <= httpCount-httpKeepEachEnd {
					continue
				}
			}
			kept = append(kept, event)
		}
		clear(timeline.Events[len(kept):])
		timeline.Events = kept
		timeline.Truncated = true
	}
	if len(timeline.Events) > 2*timelineKeepEachEnd {
		timeline.Events = slices.Delete(timeline.Events, timelineKeepEachEnd, len(timeline.Events)-timelineKeepEachEnd)
		timeline.Truncated = true
	}
}

type rulePage struct {
	Revision uint64              `json:"revision"`
	Mode     string              `json:"mode"`
	Total    int                 `json:"total"`
	Next     *int                `json:"next,omitempty"`
	Rules    []diagnosticRuleRow `json:"rules"`
}

type ruleSetRow struct {
	ID       string `json:"id"`
	Selector string `json:"selector,omitempty"`
	Count    int    `json:"count"`
}

type diagnosticRuleRow struct {
	api.RuleView
	References []ruleSetRow `json:"references,omitempty"`
	BuiltinLAN bool         `json:"builtinLAN,omitempty"`
}

type ruleDiagnostics struct {
	names     map[string]string
	selectors map[string]string
	search    string
}

func (d ruleDiagnostics) ruleSet(id string, set *router.RuleSet) ruleSetRow {
	count, _ := set.DiagnosticSize()
	return ruleSetRow{ID: id, Selector: d.selectors[id], Count: count}
}

func collectRuleSets(root *router.RuleSet) map[string]*router.RuleSet {
	found := make(map[string]*router.RuleSet)
	seen := make(map[*router.RuleSet]bool)
	var visitSet func(*router.RuleSet)
	visitSet = func(set *router.RuleSet) {
		if set == nil || seen[set] {
			return
		}
		seen[set] = true
		set.VisitReferences(func(id string, child *router.RuleSet) {
			found[id] = child
			visitSet(child)
		})
	}
	visitSet(root)
	return found
}

func (p *profileSession) ruleSets() []ruleSetRow {
	p.mu.Lock()
	base := p.base
	p.mu.Unlock()
	diagnostics := ruleDiagnostics{selectors: base.RuleSetSelectors}
	seen := make(map[string]bool)
	rows := make([]ruleSetRow, 0)
	base.Router.Rules().VisitReferences(func(id string, set *router.RuleSet) {
		if !seen[id] {
			seen[id] = true
			rows = append(rows, diagnostics.ruleSet(id, set))
		}
	})
	slices.SortFunc(rows, func(a, b ruleSetRow) int { return strings.Compare(a.ID, b.ID) })
	return rows
}

func (p *profileSession) rules(op Operation) (rulePage, error) {
	p.mu.Lock()
	effective, revision := p.engine.Effective()
	if effective == nil {
		p.mu.Unlock()
		return rulePage{}, errors.New("the profile is unavailable")
	}
	var set *router.RuleSet
	var descriptions []string
	if op.Target == "" {
		set = effective.RoutingRouter().Rules()
		if set == effective.Router.Rules() {
			descriptions = effective.RuleDescriptions
		}
	} else {
		set = p.sets[op.Target]
	}
	diagnostics := ruleDiagnostics{
		names: p.summary.Names, selectors: effective.RuleSetSelectors,
		search: strings.ToLower(strings.TrimSpace(history.Text(op.Search, 256))),
	}
	p.mu.Unlock()
	if set == nil {
		return rulePage{}, errors.New("rule set is unavailable")
	}
	limit := op.Limit
	if limit <= 0 || limit > 50 {
		limit = 40
	}
	total, expanded := set.DiagnosticSize()
	result := rulePage{Revision: revision, Mode: effective.Routing.Mode, Total: total, Rules: make([]diagnosticRuleRow, 0, limit)}
	if expanded {
		result.readEntries(set, diagnostics, max(0, op.Offset), limit)
		return result, nil
	}
	index := min(max(0, op.Offset), set.Len())
	end := min(set.Len(), index+rulePageScanLimit)
	for index < end && len(result.Rules) < limit {
		var description string
		if index < len(descriptions) {
			description = descriptions[index]
		}
		if row, matches := diagnostics.row(set.Rule(index), index, "", description); matches {
			result.Rules = append(result.Rules, row)
		}
		index++
	}
	if index < set.Len() {
		result.Next = &index
	}
	return result, nil
}

const rulePageScanLimit = 2000

func (page *rulePage) readEntries(set *router.RuleSet, diagnostics ruleDiagnostics, offset, limit int) {
	index := 0
	set.WalkDiagnosticEntries(func(spec router.RuleSpec, context string) bool {
		if index < offset {
			index++
			return true
		}
		if len(page.Rules) == limit || index-offset == rulePageScanLimit {
			page.Next = &index
			return false
		}
		if row, matches := diagnostics.row(spec, index, context, ""); matches {
			page.Rules = append(page.Rules, row)
		}
		index++
		return true
	})
}

func (d ruleDiagnostics) row(rule router.RuleSpec, index int, context, description string) (diagnosticRuleRow, bool) {
	target := d.names[rule.Target]
	if target == "" {
		target = rule.Target
	}
	if description == "" {
		description = rule.String()
	}
	description = history.Text(description, 1536)
	if d.search != "" && !strings.Contains(strings.ToLower(description), d.search) &&
		!strings.Contains(strings.ToLower(target), d.search) && !strings.Contains(strings.ToLower(rule.String()), d.search) {
		return diagnosticRuleRow{}, false
	}
	row := diagnosticRuleRow{RuleView: api.RuleView{
		Index: index, ID: rule.ID, Type: strings.ToUpper(rule.Kind.String()),
		Outbound: target, Description: description, Context: context,
	}}
	var seen map[string]bool
	var visit func(router.RuleSpec)
	visit = func(condition router.RuleSpec) {
		if condition.Kind == router.KindGeoIP {
			row.BuiltinLAN = true
		}
		if condition.Set != nil && len(condition.Values) > 0 {
			id := condition.Values[0]
			if !seen[id] {
				if seen == nil {
					seen = make(map[string]bool)
				}
				seen[id] = true
				row.References = append(row.References, d.ruleSet(id, condition.Set))
			}
		}
		for _, child := range condition.Children {
			visit(child)
		}
	}
	visit(rule)
	return row, true
}

// FlowLimits reports connection limit decisions and the host packet queue.
type FlowLimits struct {
	sagernet.PacketFlowStats
	// HostWritten and HostDropped count packets the stack sent toward the host
	// and those dropped because the host queue was full.
	HostWritten uint64 `json:"hostWritten"`
	HostDropped uint64 `json:"hostDropped"`
}
