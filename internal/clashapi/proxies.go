package clashapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/policy"
)

type proxyView struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"`
	Alive   bool          `json:"alive"`
	UDP     bool          `json:"udp"`
	History []delaySample `json:"history"`
	Icon    string        `json:"icon,omitempty"`
	Now     string        `json:"now,omitempty"`
	All     []string      `json:"all,omitempty"`
}

type delaySample struct {
	Time  time.Time `json:"time"`
	Delay int64     `json:"delay"`
}

type proxyEntry struct {
	id      string
	view    proxyView
	members []string
	chosen  string
}

type projection struct {
	rev, epoch uint64
	profile    string
	byName     map[string]proxyEntry
	names      map[string]string
	providers  map[string]map[string]providerEntry
	configs    map[string]any
	overlay    string
}

var proxyTypes = map[string]string{
	"direct": "Direct", "reject": "Reject", "reject-drop": "RejectDrop", "pass": "Pass",
	"http": "Http", "socks": "Socks5", "shadowsocks": "Shadowsocks", "vmess": "Vmess",
	"vless": "Vless", "trojan": "Trojan", "anytls": "AnyTLS", "hysteria2": "Hysteria2", "tuic": "Tuic", "snell": "Snell", "ssh": "Ssh", "wireguard": "WireGuard",
	"select": "Selector", "url-test": "URLTest", "fallback": "Fallback", "load-balance": "LoadBalance",
}

// currentProjection keeps dashboard polling independent of the size of the
// source documents. The caller has already pinned the active profile.
func (s *Server) currentProjection() *projection {
	state, _ := s.svc.ProfileState("")
	s.viewMu.Lock()
	defer s.viewMu.Unlock()
	if p := s.view; p != nil && p.rev == state.Revision && p.epoch == state.Epoch && p.profile == state.ProfileID {
		return p
	}
	cfg := s.svc.GetConfiguration(false)
	p := &projection{
		rev: cfg.Revision, epoch: cfg.ProfileEpoch, profile: cfg.ProfileID, overlay: cfg.Overlay,
		byName: map[string]proxyEntry{}, names: map[string]string{},
		providers: map[string]map[string]providerEntry{"proxies": {}, "rules": {}},
		configs: map[string]any{"mode": "rule", "port": 0, "socks-port": 0, "mixed-port": 0,
			"allow-lan": false, "log-level": "info", "tun": map[string]bool{"enable": false}},
	}
	s.view = p
	eff := cfg.Effective
	if eff == nil {
		return p
	}
	p.configs["mode"], p.configs["log-level"] = eff.Routing.Mode, eff.LogLevel
	p.configs["tun"] = map[string]bool{"enable": eff.Network.Mode == "tun"}
	for _, l := range eff.Listeners {
		key := map[string]string{"http": "port", "socks": "socks-port", "mixed": "mixed-port"}[l.Type]
		if key != "" && p.configs[key] == 0 {
			p.configs[key] = l.Listen.Port()
		}
		if !l.Listen.Addr().IsLoopback() {
			p.configs["allow-lan"] = true
		}
	}
	// Take built-in names first, then sort IDs so duplicate display names
	// are handled consistently across refreshes.
	auto := map[string]string{}
	for _, group := range eff.AutoGroups {
		auto[group.ID] = group.Type
	}
	nodeEntries := make([]proxyEntry, 0, len(eff.Outbounds)+len(eff.Groups))
	for _, out := range eff.Outbounds {
		name := out.Name
		switch out.ID {
		case "direct", "reject", "reject-drop", "pass":
			name = strings.ToUpper(out.ID)
		}
		nodeEntries = append(nodeEntries, proxyEntry{id: out.ID, view: proxyView{Name: name, Type: proxyTypes[out.Type], Alive: true, UDP: out.UDP}})
	}
	for _, group := range eff.Groups {
		kind := auto[group.ID]
		if kind == "" {
			kind = "select"
		}
		meta := eff.GroupMetadata[group.ID]
		nodeEntries = append(nodeEntries, proxyEntry{id: group.ID, members: group.Members, chosen: group.Selected,
			view: proxyView{Name: meta.Name, Type: proxyTypes[kind], Alive: true, UDP: !eff.GroupUDPDisabled[group.ID], Icon: meta.Icon}})
	}
	slices.SortFunc(nodeEntries, func(a, b proxyEntry) int { return strings.Compare(a.id, b.id) })
	count := map[string]int{}
	for _, item := range nodeEntries {
		count[item.view.Name]++
	}
	for _, item := range nodeEntries {
		name := item.view.Name
		if name == "" {
			name = item.id
		} else if count[name] > 1 && strings.ToUpper(item.id) != name {
			name += " [" + item.id + "]"
		}
		for {
			_, exists := p.byName[name]
			if !exists {
				break
			}
			name += " [" + item.id + "]"
		}
		item.view.Name = name
		p.byName[name], p.names[item.id] = item, name
	}
	s.addProviders(p, cfg)
	return p
}

func (p *projection) display(id string) string {
	if name := p.names[id]; name != "" {
		return name
	}
	return id
}

func (s *Server) proxyViews(p *projection, onlyGroups bool) map[string]proxyView {
	observed := make(map[string]policy.Status)
	checks := make(map[string]policy.Result)
	for _, group := range s.svc.Engine().GroupStatus() {
		observed[group.ID] = group
		for _, result := range group.Results {
			if result.Checked.After(checks[result.Member].Checked) {
				checks[result.Member] = result
			}
		}
	}
	result := make(map[string]proxyView)
	for name, entry := range p.byName {
		if onlyGroups && len(entry.members) == 0 {
			continue
		}
		view := entry.view
		view.History = []delaySample{}
		if sample, ok := checks[entry.id]; ok {
			view.Alive = sample.Alive
			view.History = append(view.History, delaySample{sample.Checked, sample.Delay})
		}
		if len(entry.members) > 0 {
			chosen := entry.chosen
			if status, ok := observed[entry.id]; ok && status.Selected != "" {
				chosen = status.Selected
			}
			if chosen == "" {
				chosen = entry.members[0]
			}
			view.Now = p.display(chosen)
			for _, member := range entry.members {
				view.All = append(view.All, p.display(member))
			}
		}
		result[name] = view
	}
	return result
}

func (s *Server) configs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.currentProjection().configs)
}

func (s *Server) proxies(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"proxies": s.proxyViews(s.currentProjection(), false)})
}

func (s *Server) groups(w http.ResponseWriter, _ *http.Request) {
	views := s.proxyViews(s.currentProjection(), true)
	names := make([]string, 0, len(views))
	for name := range views {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]proxyView, 0, len(names))
	for _, name := range names {
		out = append(out, views[name])
	}
	writeJSON(w, http.StatusOK, map[string]any{"proxies": out})
}

func (s *Server) group(w http.ResponseWriter, r *http.Request) {
	view, ok := s.proxyViews(s.currentProjection(), true)[r.PathValue("name")]
	if !ok {
		writeError(w, http.StatusNotFound, "proxy group not found")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	view, ok := s.proxyViews(s.currentProjection(), false)[r.PathValue("name")]
	if !ok {
		writeError(w, http.StatusNotFound, "proxy not found")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) delay(w http.ResponseWriter, r *http.Request) {
	item, ok := s.currentProjection().byName[r.PathValue("name")]
	if !ok {
		writeError(w, http.StatusNotFound, "proxy not found")
		return
	}
	query := r.URL.Query()
	timeout := 5000
	if raw := query.Get("timeout"); raw != "" {
		timeout, _ = strconv.Atoi(raw)
	}
	if timeout < 100 || timeout > 10000 || query.Get("url") == "" {
		writeError(w, http.StatusBadRequest, "need a probe URL and timeout in 100–10000 ms")
		return
	}
	result, err := s.svc.Engine().ProbeOutbound(r.Context(), api.ProbeRequest{Outbound: item.id, URL: query.Get("url"), TimeoutMS: timeout})
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, "proxy probe failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"delay": result.DelayMS})
}

func (s *Server) selectMember(w http.ResponseWriter, r *http.Request) {
	p := s.currentProjection()
	group, exists := p.byName[r.PathValue("name")]
	if !exists {
		writeError(w, http.StatusNotFound, "proxy group not found")
		return
	}
	if group.view.Type != "Selector" {
		writeError(w, http.StatusBadRequest, "group does not support manual selection")
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "need a member name")
		return
	}
	member, exists := p.byName[body.Name]
	if !exists || !slices.Contains(group.members, member.id) {
		writeError(w, http.StatusBadRequest, "member is not in the group")
		return
	}
	value, _ := json.Marshal(member.id)
	path := model.JoinPath("/groups", group.id, "selected")
	overlay, _, ds := model.ParseOverlay([]byte(p.overlay))
	if ds.HasErrors() {
		writeError(w, http.StatusConflict, "active overlay is invalid")
		return
	}
	encoded, _ := json.Marshal(model.Op{Op: "set", Path: path, Value: value})
	edit := model.Op{Op: "insert", Path: "/patches", Value: encoded}
	for i, op := range overlay.Patches {
		if op.Op == "set" && op.Path == path {
			edit = model.Op{Op: "set", Path: fmt.Sprintf("/patches/#%d/value", i), Value: value}
		}
	}
	result, err := s.svc.Commit(r.Context(), service.CommitRequest{
		ChangeRequest: service.ChangeRequest{BaseRevision: p.rev, OverlayPatch: []model.Op{edit}},
		Source:        "clash-api", Message: "select " + member.id + " in " + group.id,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "selection failed")
		return
	}
	if result.State != "committed" {
		status := http.StatusBadRequest
		if result.Conflict != nil {
			status = http.StatusConflict
		}
		writeError(w, status, "selection could not be committed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
