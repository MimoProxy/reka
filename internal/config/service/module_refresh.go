package service

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/subscription"
)

const maxModuleBundleSize = 32 << 20

func moduleSpecHash(def model.Module) string {
	// Enabled affects scheduling, but cannot change the downloaded bundle.
	def.Enabled = nil
	data, _ := json.Marshal(def)
	return resource.Hash(data)
}

func moduleSnapshotMatches(def model.Module, src model.Source) bool {
	return src.Module != nil && src.Module.Format == model.ModuleFormatSurge && src.Lock != nil &&
		src.Module.Request == def.RequestHash() && resource.ValidHash(src.Lock.Root)
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
	if moduleSnapshotMatches(def, src) {
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

type moduleSnapshot struct {
	ID     string               `json:"id"`
	Module model.ModuleSnapshot `json:"module"`
	Lock   model.SourceLock     `json:"lock"`
}

func moduleSourceOp(src model.Source, id string, snapshot moduleSnapshot) model.Op {
	value, _ := json.Marshal(snapshot)
	if src.ID == "" {
		return model.Op{Op: "insert", Path: "/sources", Value: value}
	}
	return model.Op{Op: "set", Path: model.JoinPath("/sources", id), Value: value}
}

func (m *RefreshManager) downloadModule(ctx context.Context, def model.Module, src model.Source, previous refreshRecord, force bool) (moduleSnapshot, refreshUpdate, error) {
	update := refreshUpdate{specHash: moduleSpecHash(def), manualOnly: def.File != ""}
	if model.ValidModule(&def) != nil {
		return moduleSnapshot{}, update, &subscription.Error{Code: "module_invalid"}
	}
	if src.ID != "" && src.Module == nil {
		return moduleSnapshot{}, update, &subscription.Error{Code: "module_source_conflict"}
	}
	validated := make(map[string]subscription.Entry)
	if moduleSnapshotMatches(def, src) {
		if entry := previous.Entries["root"]; entry.Hash == src.Lock.Root {
			validated["root"] = entry
		}
		for _, lock := range src.Lock.Resources {
			if entry := previous.Entries[lock.ID]; entry.Hash == lock.Hash {
				validated[lock.ID] = entry
			}
		}
	}
	interval := def.Interval
	if interval == 0 {
		interval = model.DefaultResourceInterval
	}
	fetcher := subscription.Fetcher{Client: m.client, Blobs: m.blobs, MaxBytes: model.MaxDocumentSize, MaxBundleBytes: maxModuleBundleSize}
	batch := fetcher.Batch(validated, force)
	var body []byte
	var err error
	if def.File != "" {
		body, err = readModuleFile(def.File)
		if err == nil {
			body, err = batch.Inline("root", "module", "", body)
		}
	} else {
		var url string
		url, err = m.resolve(def.URL)
		if err == nil {
			body, err = batch.Fetch(ctx, "root", "module", "", url, nil, interval)
		}
	}
	if err != nil {
		return moduleSnapshot{}, update, err
	}
	meta, urls := module.Inspect(body, def.Arguments)
	if len(urls) > model.MaxModuleResources {
		return moduleSnapshot{}, update, &subscription.Error{Code: "too_many_module_resources"}
	}
	fetcher.MaxBytes = httprewrite.MaxMapLocalSize
	locks := make([]model.ResourceLock, 0, len(urls))
	for _, url := range urls {
		request := resource.Hash([]byte(url))
		id := request[:24]
		if _, err := batch.Fetch(ctx, id, "map-local", "", url, nil, interval); err != nil {
			return moduleSnapshot{}, update, err
		}
		locks = append(locks, model.ResourceLock{ID: id, Kind: "map-local", Request: request, Hash: batch.Entries[id].Hash})
	}
	update.entries = batch.Entries
	if def.URL != "" {
		update.next = time.Now().UTC().Add(time.Duration(interval) * time.Second)
		for _, entry := range batch.Entries {
			if !entry.Next.IsZero() && entry.Next.Before(update.next) {
				update.next = entry.Next
			}
		}
	}
	return moduleSnapshot{
		ID:     def.ID,
		Module: model.ModuleSnapshot{Format: model.ModuleFormatSurge, Request: def.RequestHash(), Name: meta.Name, Desc: meta.Desc},
		Lock:   model.SourceLock{Root: batch.Entries["root"].Hash, Resources: locks},
	}, update, nil
}

func readModuleFile(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, &subscription.Error{Code: "module_file_unavailable"}
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Stat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, &subscription.Error{Code: "module_file_unavailable"}
	}
	f, err := root.OpenFile(name, os.O_RDONLY|moduleFileNonblocking, 0)
	if err != nil {
		return nil, &subscription.Error{Code: "module_file_unavailable"}
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > model.MaxDocumentSize {
		return nil, &subscription.Error{Code: "module_file_invalid"}
	}
	data, err := io.ReadAll(io.LimitReader(f, model.MaxDocumentSize+1))
	if err != nil || len(data) == 0 || len(data) > model.MaxDocumentSize {
		return nil, &subscription.Error{Code: "module_file_invalid"}
	}
	return data, nil
}
