package clashapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
)

type providerEntry struct {
	source, resource, behavior, vehicle string
}

type providerView struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	VehicleType string      `json:"vehicleType"`
	Behavior    string      `json:"behavior,omitempty"`
	UpdatedAt   *time.Time  `json:"updatedAt,omitempty"`
	Proxies     []proxyView `json:"proxies,omitempty"`
}

func (s *Server) addProviders(p *projection, cfg api.Configuration) {
	sources, _, ds := model.ParseSources([]byte(cfg.Sources))
	if !ds.HasErrors() {
		for _, source := range sources.Sources {
			if source.Subscription == nil {
				continue
			}
			p.providers["proxies"][source.ID] = providerEntry{source: source.ID, vehicle: "HTTP"}
			if source.Lock == nil {
				continue
			}
			for _, lock := range source.Lock.Resources {
				if lock.Kind == "rule" {
					p.providers["rules"][source.ID+"/"+lock.Name] = providerEntry{source: source.ID, behavior: lock.Behavior, vehicle: "Compatible"}
				}
			}
		}
	}
	profile, _, ds := model.ParseProfile([]byte(cfg.Profile))
	if !ds.HasErrors() {
		for _, ruleSet := range profile.RuleSets {
			if ruleSet.Download != nil && ruleSet.Hash != "" {
				p.providers["rules"]["rule-set/"+ruleSet.ID] = providerEntry{resource: ruleSet.ID, behavior: ruleSet.Behavior, vehicle: "HTTP"}
			}
		}
	}
}

func (s *Server) providers(w http.ResponseWriter, r *http.Request, kind string) {
	p := s.currentProjection()
	entries := p.providers[kind]
	updated := map[string]time.Time{}
	for _, status := range statusesOrEmpty(s.svc.ListSubscriptions()) {
		updated[status.SourceID] = status.LastSuccess
	}
	resourceUpdates := map[string]time.Time{}
	if kind == "rules" {
		for _, status := range statusesOrEmpty(s.svc.ListManagedResources()) {
			if status.Kind == "rule-set" {
				resourceUpdates[status.ID] = status.LastSuccess
			}
		}
	}
	all := map[string]providerView{}
	for name, entry := range entries {
		out := providerView{Name: name, VehicleType: entry.vehicle, Behavior: entry.behavior, Type: "Rule"}
		at := updated[entry.source]
		if entry.resource != "" {
			at = resourceUpdates[entry.resource]
		}
		if !at.IsZero() {
			out.UpdatedAt = &at
		}
		all[name] = out
	}
	if kind == "proxies" {
		for name, view := range all {
			view.Type, view.Proxies = "Proxy", []proxyView{}
			all[name] = view
		}
		for _, proxy := range s.proxyViews(p, false) {
			node := p.byName[proxy.Name]
			if len(node.members) != 0 {
				continue
			}
			if source, _, ok := strings.Cut(node.id, "/"); ok {
				if provider, found := all[source]; found {
					provider.Proxies = append(provider.Proxies, proxy)
					all[source] = provider
				}
			}
		}
	}
	if name := r.PathValue("name"); name != "" {
		view, ok := all[name]
		if !ok {
			writeError(w, http.StatusNotFound, "provider not found")
			return
		}
		writeJSON(w, http.StatusOK, view)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": all})
}

func statusesOrEmpty[T any](statuses []T, _ error) []T { return statuses }

func (s *Server) refreshProvider(w http.ResponseWriter, r *http.Request, kind string) {
	entry, ok := s.currentProjection().providers[kind][r.PathValue("name")]
	if !ok {
		writeError(w, http.StatusNotFound, "provider not found")
		return
	}
	var errorCode string
	var err error
	if entry.resource != "" {
		var status api.ManagedResourceStatus
		status, err = s.svc.RefreshManagedResource(r.Context(), api.RefreshManagedResourceRequest{Kind: "rule-set", ID: entry.resource, Wait: true})
		errorCode = status.ErrorCode
	} else {
		var status api.SubscriptionStatus
		status, err = s.svc.RefreshSubscription(r.Context(), entry.source)
		errorCode = status.ErrorCode
	}
	if err != nil || errorCode != "" {
		writeError(w, http.StatusBadGateway, "provider refresh failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
