package service

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/moduleacquire"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/subscription"
)

func moduleSpecHash(def model.Module) string {
	// Enabled affects scheduling, but cannot change the downloaded bundle.
	def.Enabled = nil
	data, _ := json.Marshal(def)
	return resource.Hash(data)
}

func toModuleStatus(status SubscriptionStatus) api.ModuleStatus {
	return api.ModuleStatus{
		ModuleID: status.SourceID, State: status.State, Stale: status.Stale, LastAttempt: status.LastAttempt,
		LastSuccess: status.LastSuccess, NextAttempt: status.NextAttempt, ErrorCode: status.ErrorCode,
		Revision: status.Revision, RootHash: status.RootHash,
	}
}

func (m *RefreshManager) moduleStatus(def model.Module, src model.Source, revision uint64) api.ModuleStatus {
	key := refreshKey{id: def.ID, module: true}
	m.mu.Lock()
	r := m.record(key)
	busy := m.jobs[key] != nil
	m.mu.Unlock()
	status := toModuleStatus(r.Status)
	status.ModuleID = def.ID
	if r.SpecHash != moduleSpecHash(def) {
		status.State, status.Stale = "pending", true
	}
	if moduleacquire.Matches(def, src) {
		aligned := src.Lock.Root == status.RootHash && len(src.Lock.Resources)+1 == len(r.Entries)
		for _, lock := range src.Lock.Resources {
			aligned = aligned && r.Entries[lock.ID].Hash == lock.Hash
		}
		if !aligned {
			status.State, status.Stale = "pending", true
			status.Revision, status.RootHash = revision, src.Lock.Root
		}
	} else {
		status.RootHash = ""
		if status.State == "current" {
			status.State, status.Stale = "pending", true
		}
	}
	if busy {
		status.State = "refreshing"
	}
	return status
}

func (m *RefreshManager) runModulesDue(data []byte) {
	p, _, ds := model.ParseProfile(data)
	if ds.HasErrors() {
		return
	}
	for _, def := range p.Modules {
		if !def.IsEnabled() || def.URL == "" {
			continue
		}
		key := refreshKey{id: def.ID, module: true}
		m.mu.Lock()
		r := m.record(key)
		due := r.SpecHash != moduleSpecHash(def) || !time.Now().Before(r.Status.NextAttempt)
		m.mu.Unlock()
		if due {
			_, _ = m.queueModule(m.ctx, def.ID, false)
		}
	}
}

func (s *Service) RefreshModule(ctx context.Context, id string, wait bool) (api.ModuleStatus, error) {
	_, data, _ := s.Documents()
	p, _, ds := model.ParseProfile(data)
	if ds.HasErrors() {
		return api.ModuleStatus{}, errf(CodeInvalid, "profile is invalid")
	}
	if findModule(p, id) == nil {
		return api.ModuleStatus{}, errf(CodeNotFound, "module not found")
	}
	m, err := s.manager(RefreshOptions{})
	if err != nil {
		return api.ModuleStatus{}, err
	}
	job, err := m.queueModule(ctx, id, true)
	if err != nil {
		return api.ModuleStatus{}, err
	}
	if !wait {
		return api.ModuleStatus{ModuleID: id, State: "refreshing"}, nil
	}
	select {
	case <-ctx.Done():
		return api.ModuleStatus{}, ctx.Err()
	case <-job.done:
		return toModuleStatus(job.result), nil
	}
}

func (m *RefreshManager) queueModule(ctx context.Context, id string, force bool) (*refreshJob, error) {
	return m.queue(ctx, refreshKey{id: id, module: true}, !force, true, func(ctx context.Context, previous refreshRecord) (refreshUpdate, error) {
		return m.refreshModule(ctx, id, force, previous)
	})
}

func (m *RefreshManager) refreshModule(ctx context.Context, id string, force bool, previous refreshRecord) (refreshUpdate, error) {
	_, profile, _, sources, _ := m.svc.LayerDocuments()
	p, byID, err := parseModuleDocuments(profile, sources)
	if err != nil {
		return refreshUpdate{}, &subscription.Error{Code: "module_invalid"}
	}
	def := findModule(p, id)
	if def == nil || !force && (!def.IsEnabled() || def.URL == "") {
		return refreshUpdate{}, &subscription.Error{Code: "module_refresh_unavailable"}
	}
	src := byID[id]
	snapshot, update, err := m.downloadModule(ctx, *def, src, previous, force)
	if err != nil {
		return update, err
	}
	for range 3 {
		if ctx.Err() != nil {
			return update, &subscription.Error{Code: "cancelled"}
		}
		base, profile, _, sources, _ := m.svc.LayerDocuments()
		p, byID, err := parseModuleDocuments(profile, sources)
		if err != nil {
			return update, &subscription.Error{Code: "module_invalid"}
		}
		current := findModule(p, id)
		if current == nil || (!force && !current.IsEnabled()) || moduleSpecHash(*current) != update.specHash || !reflect.DeepEqual(byID[id], src) {
			break
		}
		res, err := m.svc.Commit(ctx, CommitRequest{
			ChangeRequest: ChangeRequest{BaseRevision: base, SourcesPatch: []model.Op{moduleSourceOp(src, id, snapshot)}},
			Source:        "module", Message: "refresh module " + id,
		})
		if err != nil {
			return update, &subscription.Error{Code: "commit_failed"}
		}
		if res.State == store.OpCommitted {
			update.revision = res.Revision
			return update, nil
		}
		if res.Error == nil || res.Error.Code != CodeConflict {
			return update, &subscription.Error{Code: "commit_rejected"}
		}
	}
	return update, &subscription.Error{Code: "refresh_conflict"}
}

func moduleSourceOp(src model.Source, id string, snapshot moduleacquire.Snapshot) model.Op {
	value, _ := json.Marshal(snapshot)
	if src.ID == "" {
		return model.Op{Op: "insert", Path: "/sources", Value: value}
	}
	return model.Op{Op: "set", Path: model.JoinPath("/sources", id), Value: value}
}

func (m *RefreshManager) downloadModule(ctx context.Context, def model.Module, src model.Source, previous refreshRecord, force bool) (moduleacquire.Snapshot, refreshUpdate, error) {
	update := refreshUpdate{specHash: moduleSpecHash(def), manualOnly: def.File != ""}
	result, err := moduleacquire.Acquire(ctx, def, moduleacquire.Options{
		Client: m.client, Blobs: m.blobs, ResolveURL: m.resolve, Previous: src, PreviousEntries: previous.Entries, Force: force,
	})
	update.entries, update.next = result.Entries, result.Next
	return result.Snapshot, update, err
}
