//go:build with_gvisor

package packettunnel

import (
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/api"
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
	case "timeline":
		timeline, ok := engine.ConnectionTimeline(op.ID)
		if !ok {
			return nil, errors.New("connection history has expired")
		}
		if len(timeline.Events) > 24 {
			trimmed := append([]api.TimelineEvent(nil), timeline.Events[:12]...)
			timeline.Events = append(trimmed, timeline.Events[len(timeline.Events)-12:]...)
			timeline.Truncated = true
		}
		// Keep linked summaries small. DNS and HTTP details can be requested
		// independently through the corresponding history page.
		for i := range timeline.Events {
			event := &timeline.Events[i]
			if len(event.Data) <= 768 {
				continue
			}
			var label struct {
				Name   string `json:"name,omitempty"`
				Host   string `json:"host,omitempty"`
				Type   string `json:"type,omitempty"`
				Status int    `json:"status_code,omitempty"`
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

type rulePage struct {
	Revision uint64         `json:"revision"`
	Mode     string         `json:"mode"`
	Total    int            `json:"total"`
	Next     *int           `json:"next,omitempty"`
	Rules    []api.RuleView `json:"rules"`
}

type ruleSetRow struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
}

func collectRuleSets(root *router.RuleSet) map[string]*router.RuleSet {
	found := make(map[string]*router.RuleSet)
	seen := make(map[*router.RuleSet]bool)
	var visitSet func(*router.RuleSet)
	var visitRule func(router.RuleSpec)
	visitRule = func(rule router.RuleSpec) {
		if rule.Set != nil && len(rule.Values) > 0 {
			found[rule.Values[0]] = rule.Set
			visitSet(rule.Set)
		}
		for _, child := range rule.Children {
			visitRule(child)
		}
	}
	visitSet = func(set *router.RuleSet) {
		if set == nil || seen[set] {
			return
		}
		seen[set] = true
		for i := range set.Len() {
			visitRule(set.Rule(i))
		}
	}
	visitSet(root)
	return found
}

func (p *profileSession) ruleSets() []ruleSetRow {
	p.mu.Lock()
	sets := p.sets
	p.mu.Unlock()
	rows := make([]ruleSetRow, 0, len(sets))
	for id, set := range sets {
		rows = append(rows, ruleSetRow{ID: id, Count: set.Len()})
	}
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
	if op.Target == "" {
		set = effective.RoutingRouter().Rules()
	} else {
		set = p.sets[op.Target]
	}
	names := p.summary.Names
	p.mu.Unlock()
	if set == nil {
		return rulePage{}, errors.New("rule set is unavailable")
	}
	limit := op.Limit
	if limit <= 0 || limit > 50 {
		limit = 40
	}
	result := rulePage{Revision: revision, Mode: effective.Routing.Mode, Total: set.Len(), Rules: make([]api.RuleView, 0, limit)}
	search := strings.ToLower(strings.TrimSpace(history.Text(op.Search, 256)))
	index := min(max(0, op.Offset), set.Len())
	end := min(set.Len(), index+2000)
	for index < end && len(result.Rules) < limit {
		rule := set.Rule(index)
		kind := strings.ToUpper(rule.Kind.String())
		target := names[rule.Target]
		if target == "" {
			target = rule.Target
		}
		description := history.Text(rule.String(), 1536)
		if search == "" || strings.Contains(strings.ToLower(description), search) || strings.Contains(strings.ToLower(target), search) {
			result.Rules = append(result.Rules, api.RuleView{Index: index, ID: rule.ID, Type: kind, Outbound: target, Description: description})
		}
		index++
	}
	if index < set.Len() {
		result.Next = &index
	}
	return result, nil
}
