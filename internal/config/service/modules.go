package service

import (
	"context"
	"encoding/json"
	"maps"
	"strconv"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/config/moduleacquire"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/subscription"
)

func parseModuleDocuments(profile, sources []byte) (*model.Profile, map[string]model.Source, error) {
	p, _, pd := model.ParseProfile(profile)
	ss, _, sd := model.ParseSources(sources)
	if pd.HasErrors() || sd.HasErrors() {
		return nil, nil, errf(CodeInvalid, "profile or sources are invalid")
	}
	byID := make(map[string]model.Source, len(ss.Sources))
	for _, src := range ss.Sources {
		byID[src.ID] = src
	}
	return p, byID, nil
}

func findModule(p *model.Profile, id string) *model.Module {
	for i := range p.Modules {
		if p.Modules[i].ID == id {
			return &p.Modules[i]
		}
	}
	return nil
}

func (s *Service) moduleDocuments(base uint64) (*model.Profile, map[string]model.Source, error) {
	rev, profile, _, sources, _ := s.LayerDocuments()
	if rev != base {
		return nil, nil, errf(CodeConflict, "the active revision changed")
	}
	return parseModuleDocuments(profile, sources)
}

func (s *Service) AddModule(ctx context.Context, req api.AddModuleRequest) (Result, error) {
	def := req.Module
	if err := model.ValidModule(&def); err != nil {
		return Result{}, errf(CodeBadRequest, "%v", err)
	}
	profile, sources, err := s.moduleDocuments(req.BaseRevision)
	if err != nil {
		return Result{}, err
	}
	if _, exists := sources[def.ID]; exists || findModule(profile, def.ID) != nil {
		return Result{}, errf(CodeConflict, "a module or source with this ID already exists")
	}
	raw, _ := json.Marshal(def)
	op := model.Op{Op: "insert", Path: "/modules", Value: raw}
	if req.Position != nil {
		pos := *req.Position
		if pos < 0 || pos > len(profile.Modules) {
			return Result{}, errf(CodeBadRequest, "module position is out of range")
		}
		if pos < len(profile.Modules) {
			op.Before = profile.Modules[pos].ID
		}
	}
	return s.commitDownloadedModule(ctx, def, model.Source{}, req.BaseRevision, op)
}

func (s *Service) RemoveModule(ctx context.Context, req api.RemoveModuleRequest) (Result, error) {
	p, sources, err := s.moduleDocuments(req.BaseRevision)
	if err != nil {
		return Result{}, err
	}
	if findModule(p, req.ModuleID) == nil {
		return Result{}, errf(CodeNotFound, "module not found")
	}
	change := ChangeRequest{BaseRevision: req.BaseRevision,
		Patch: []model.Op{{Op: "remove", Path: model.JoinPath("/modules", req.ModuleID)}},
	}
	// Remove markers by descending index even when they have explicit IDs.
	for i := len(p.Rules) - 1; i >= 0; i-- {
		if p.Rules[i].Module == req.ModuleID {
			change.Patch = append(change.Patch, model.Op{Op: "remove", Path: "/rules/#" + strconv.Itoa(i)})
		}
	}
	if sources[req.ModuleID].Module != nil {
		change.SourcesPatch = []model.Op{{Op: "remove", Path: model.JoinPath("/sources", req.ModuleID)}}
	}
	return s.Commit(ctx, CommitRequest{ChangeRequest: change, Source: "module", Message: "remove module " + req.ModuleID})
}

func (s *Service) SetModuleEnabled(ctx context.Context, req api.SetModuleEnabledRequest) (Result, error) {
	if req.Enabled == nil {
		return Result{}, errf(CodeBadRequest, "enabled is required")
	}
	p, sources, err := s.moduleDocuments(req.BaseRevision)
	if err != nil {
		return Result{}, err
	}
	def := findModule(p, req.ModuleID)
	if def == nil {
		return Result{}, errf(CodeNotFound, "module not found")
	}
	def.Enabled = req.Enabled
	value, _ := json.Marshal(*req.Enabled)
	op := model.Op{Op: "set", Path: model.JoinPath("/modules", def.ID, "enabled"), Value: value}
	src := sources[def.ID]
	if def.IsEnabled() && !moduleacquire.Matches(*def, src) {
		return s.commitDownloadedModule(ctx, *def, src, req.BaseRevision, op)
	}
	return s.Commit(ctx, CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: req.BaseRevision, Patch: []model.Op{op}},
		Source: "module", Message: "set enabled state for module " + def.ID})
}

func (s *Service) SetModuleArguments(ctx context.Context, req api.SetModuleArgumentsRequest) (Result, error) {
	p, sources, err := s.moduleDocuments(req.BaseRevision)
	if err != nil {
		return Result{}, err
	}
	def := findModule(p, req.ModuleID)
	if def == nil {
		return Result{}, errf(CodeNotFound, "module not found")
	}
	if req.Arguments == nil {
		req.Arguments = map[string]string{}
	}
	value, _ := json.Marshal(req.Arguments)
	op := model.Op{Op: "set", Path: model.JoinPath("/modules", req.ModuleID, "arguments"), Value: value}
	def.Arguments = req.Arguments
	// New arguments can reference assets that are not locked yet.
	if src := sources[def.ID]; def.IsEnabled() && (!moduleacquire.Matches(*def, src) || !s.moduleResourcesLocked(*def, src)) {
		return s.commitDownloadedModule(ctx, *def, src, req.BaseRevision, op)
	}
	return s.Commit(ctx, CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: req.BaseRevision, Patch: []model.Op{op}},
		Source: "module", Message: "set arguments for module " + req.ModuleID})
}

// commitDownloadedModule reserves the same workers as refreshes and only
// publishes the definition when the matching snapshot is ready to commit.
func (s *Service) commitDownloadedModule(ctx context.Context, def model.Module, src model.Source, base uint64, op model.Op) (Result, error) {
	m, err := s.manager(RefreshOptions{})
	if err != nil {
		return Result{}, err
	}
	def.Arguments = maps.Clone(def.Arguments)
	var result Result
	var commitErr error
	job, err := m.queue(ctx, refreshKey{id: def.ID, module: true}, false, false, func(worker context.Context, previous refreshRecord) (refreshUpdate, error) {
		worker, cancel := context.WithCancel(worker)
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		defer cancel()
		snapshot, update, err := m.downloadModule(worker, def, src, previous, true)
		if err != nil {
			commitErr = errf(CodeInvalid, "module download failed (%s)", subscription.Code(err))
			return update, err
		}
		if err := worker.Err(); err != nil {
			commitErr = err
			return update, &subscription.Error{Code: "cancelled"}
		}
		result, commitErr = s.Commit(worker, CommitRequest{
			ChangeRequest: ChangeRequest{BaseRevision: base, Patch: []model.Op{op}, SourcesPatch: []model.Op{moduleSourceOp(src, def.ID, snapshot)}},
			Source:        "module", Message: "install module " + def.ID,
		})
		update.revision = result.Revision
		switch {
		case commitErr != nil:
			return update, &subscription.Error{Code: "commit_failed"}
		case result.State != store.OpCommitted:
			return update, &subscription.Error{Code: "commit_rejected"}
		default:
			return update, nil
		}
	})
	if err != nil {
		return Result{}, err
	}
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case <-job.done:
		return result, commitErr
	}
}

func (s *Service) ListModules() ([]api.ModuleInfo, error) {
	m, err := s.manager(RefreshOptions{})
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	revision, profile, sources, eff := s.active, s.profile, s.sources, s.eff
	s.mu.Unlock()
	p, byID, err := parseModuleDocuments(profile, sources)
	if err != nil {
		return nil, err
	}
	list := make([]api.ModuleInfo, 0, len(p.Modules))
	for _, def := range p.Modules {
		src := byID[def.ID]
		info := api.ModuleInfo{ID: def.ID, Enabled: def.IsEnabled(), SourceType: "url", Format: def.Format, Status: m.moduleStatus(def, src, revision)}
		if def.File != "" {
			info.SourceType = "file"
		}
		matched := moduleacquire.Matches(def, src)
		if matched {
			info.Format, info.Name, info.Desc = src.Module.Format, src.Module.Name, src.Module.Desc
		}
		if eff != nil {
			if report, ok := eff.Modules[def.ID]; ok {
				info.Format, info.Name, info.Desc, info.Arguments = report.Format, report.Name, report.Desc, report.Arguments
				info.Report = &api.ModuleReportSummary{Partial: report.Partial, CanApply: report.CanApply,
					Rules: report.Rules, Rewrites: report.Rewrites, Hostnames: report.Hostnames,
					Scripts: report.Scripts, ScriptItems: report.ScriptItems}
			}
		}
		// Disabled modules have no effective report, but their locked text can
		// still provide argument declarations for editing.
		if info.Report == nil && matched {
			if body, err := m.blobs.Read(src.Lock.Root); err == nil {
				meta, _ := module.InspectWithOptions(body, module.Options{Format: info.Format, Arguments: def.Arguments})
				info.Arguments = meta.Arguments
			}
		}
		list = append(list, info)
	}
	return list, nil
}

func (s *Service) GetModuleReport(id string) (module.Report, error) {
	s.mu.Lock()
	revision, profile, sources, eff := s.active, s.profile, s.sources, s.eff
	s.mu.Unlock()
	if eff != nil {
		if report, ok := eff.Modules[id]; ok {
			return report, nil
		}
	}
	p, byID, err := parseModuleDocuments(profile, sources)
	if err != nil {
		return module.Report{}, err
	}
	def := findModule(p, id)
	if def == nil {
		return module.Report{}, errf(CodeNotFound, "module not found")
	}
	src := byID[id]
	if !moduleacquire.Matches(*def, src) {
		if m, err := s.manager(RefreshOptions{}); err == nil {
			status := m.moduleStatus(*def, src, revision)
			if status.ErrorCode != "" && (status.State == "failed" || status.State == "stale") {
				return module.Report{}, errf(CodeNotFound, "module refresh failed (%s); refresh the module", status.ErrorCode)
			}
		}
		return module.Report{}, errf(CodeNotFound, "refresh the module to download a snapshot for the declared location and format")
	}
	return module.Report{}, errf(CodeBlocked, "module has no report in the active configuration")
}

func (s *Service) PreviewModule(req api.PreviewModuleRequest) (module.Report, error) {
	if len(req.Data) > model.MaxDocumentSize {
		return module.Report{}, errf(CodeBadRequest, "module text exceeds 16 MiB")
	}
	format := req.Format
	text := []byte(req.Data)
	if format == "" {
		format = module.DetectFormat(req.Filename, text)
	} else if !model.ValidModuleFormat(format) {
		return module.Report{}, errf(CodeBadRequest, "module format must be surge, loon, or stash")
	}
	s.mu.Lock()
	eff := s.eff
	s.mu.Unlock()
	opts := module.Options{Format: format, Arguments: req.Arguments}
	if eff != nil {
		opts.Resolve = eff.ModulePolicyResolver()
	}
	_, report := module.Convert(text, opts)
	return report, nil
}

func (s *Service) moduleResourcesLocked(def model.Module, src model.Source) bool {
	text, err := resource.At(s.store.Root()).Read(src.Lock.Root)
	if err != nil {
		return false
	}
	type resourceKey struct{ kind, request string }
	locked := make(map[resourceKey]bool, len(src.Lock.Resources))
	for _, entry := range src.Lock.Resources {
		locked[resourceKey{entry.Kind, entry.Request}] = true
	}
	_, refs := module.InspectWithOptions(text, module.Options{
		Format: src.Module.Format, Arguments: def.Arguments, ModuleInterval: def.Interval,
	})
	for _, url := range refs.MapLocal {
		if !locked[resourceKey{"map-local", resource.Hash([]byte(url))}] {
			return false
		}
	}
	for _, script := range refs.Scripts {
		if !locked[resourceKey{"script", resource.Hash([]byte(script.URL))}] {
			return false
		}
	}
	return true
}
