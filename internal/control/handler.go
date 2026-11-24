package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	goruntime "runtime"
	"runtime/debug"
	"slices"
	"sync"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/platform"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/secret"
)

// Version is reported in Hello; the build may override it.
var Version = "dev"

// Handler serves control API sessions for one ConfigService.
type Handler struct {
	svc      *service.Service
	mitmCAMu sync.Mutex
}

// NewHandler binds a handler to svc.
func NewHandler(svc *service.Service) *Handler { return &Handler{svc: svc} }

// Session is one client connection's state. send writes one message
// frame; it must be safe for concurrent use.
type Session struct {
	h            *Handler
	send         func([]byte) error
	ctx          context.Context
	stop         context.CancelFunc
	mu           sync.Mutex
	profileID    string
	profileEpoch uint64
	hello        bool
	sub          *service.Subscription
}

// NewSession starts a session that replies through send.
func (h *Handler) NewSession(send func([]byte) error) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{h: h, send: send, ctx: ctx, stop: cancel}
}

// Close ends the session and its subscription.
func (s *Session) Close() {
	s.stop()
	s.mu.Lock()
	if s.sub != nil {
		s.sub.Close()
		s.sub = nil
	}
	s.mu.Unlock()
}

func (s *Session) reply(id uint64, result any, err error) {
	resp := Response{ID: id, Result: result}
	if err != nil {
		var se *service.Error
		if !errors.As(err, &se) {
			se = &service.Error{Code: CodeInternal, Message: err.Error()}
		}
		resp.Result, resp.Error = nil, se
	}
	b, merr := json.Marshal(resp)
	if merr != nil {
		b, _ = json.Marshal(Response{ID: id, Error: &service.Error{Code: CodeInternal, Message: merr.Error()}})
	}
	if len(b) > MaxFrame {
		b, _ = json.Marshal(Response{ID: id, Error: &service.Error{Code: CodeInternal, Message: "response too large; page the request"}})
	}
	_ = s.send(b)
}

// Handle processes one request frame. Requests are answered in order.
func (s *Session) Handle(frame []byte) {
	var req Request
	if err := json.Unmarshal(frame, &req); err != nil {
		s.reply(0, nil, &service.Error{Code: service.CodeBadRequest, Message: "malformed request: " + err.Error()})
		return
	}
	s.mu.Lock()
	hello := s.hello
	s.mu.Unlock()
	if !hello && req.Method != "Hello" {
		s.reply(req.ID, nil, &service.Error{Code: CodeHelloRequired, Message: "send Hello first"})
		return
	}
	result, err := s.dispatch(req)
	s.reply(req.ID, result, err)
}

func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	if len(raw) == 0 {
		return v, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, &service.Error{Code: service.CodeBadRequest, Message: "params: " + err.Error()}
	}
	return v, nil
}

// Methods lists the API methods of this version.
var Methods = []string{
	"ExportProfileArchive", "GetProfileState", "SwitchProfile", "GetProfileSwitchOperation", "InstallProfile", "DeleteInactiveProfile",
	"GetProcessTraffic", "ExportManifest", "ReadResource",
	"ProbeOutbound", "GetTraffic", "QueryDNS", "FlushDNSCache", "ResetNetwork", "GetLogs", "StageResource", "GetRules",
	"GetGroupStatus", "Hello", "GetCapabilities", "GetStatus", "GetConfiguration", "ValidateConfiguration",
	"PlanConfiguration", "CommitConfiguration", "GetOperation", "ListRevisions", "RestoreRevision",
	"ListConnections", "ListConnectionHistory", "ListDNSHistory", "ListRequestHistory", "ClearHistory", "GetRequestDetail", "StartHTTPSDebug", "GetHTTPSDebug", "StopHTTPSDebug", "CloseConnections", "ExplainRoute", "Subscribe", "Unsubscribe",
	"SetSecret", "DeleteSecret", "ListSecrets", "ImportSource", "ConfigureSubscription", "ListSubscriptions", "RefreshSubscription",
	"AddModule", "RemoveModule", "SetModuleEnabled", "SetModuleArguments", "RefreshModule", "ListModules", "GetModuleReport", "PreviewModule",
	"GenerateMITMCA", "ImportMITMCA", "GetMITMCA", "ExportMITMCA", "DeleteMITMCA",
	"InstallManagedResource", "ListManagedResources", "RefreshManagedResource",
	"GetConnectionTimeline", "AddTemporaryRule", "ListTemporaryRules", "RemoveTemporaryRule",
	"RunNodeArena", "GetNetworkScene", "SetNetworkScene", "GetTrafficBudgets",
}

func (s *Session) dispatch(req Request) (result any, err error) {
	defer func() {
		if p := recover(); p != nil {
			if isMITMCAMethod(req.Method) {
				// A panic from a secret store callback may include key material.
				slog.Error("control request panicked", "method", req.Method, "request_id", req.ID)
			} else {
				slog.Error("control request panicked", "method", req.Method, "request_id", req.ID, "panic", p, "stack", string(debug.Stack()))
			}
			result = nil
			err = &service.Error{Code: CodeInternal, Message: "request handler panicked"}
		}
	}()
	svc := s.h.svc
	if req.Method == "SwitchProfile" {
		p, err := decode[api.SwitchProfileRequest](req.Params)
		if err != nil {
			return nil, err
		}
		if req.ProfileID != "" && (req.ProfileID != p.BaseProfile || req.ProfileEpoch != p.BaseEpoch) {
			return nil, &service.Error{Code: service.CodeConflict, Message: "switch context does not match its base profile"}
		}
		result, err := svc.SwitchProfile(s.ctx, p)
		if err == nil && result.State == "committed" {
			s.profileID = result.ProfileID
			s.profileEpoch = result.Epoch
		}
		return result, err
	}
	if req.Method == "DeleteInactiveProfile" {
		p, err := decode[struct {
			ProfileID   string `json:"profile_id"`
			BaseProfile string `json:"base_profile"`
			BaseEpoch   uint64 `json:"base_epoch"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		// Delete has its own writer gate. An explicit active context is mandatory.
		state, err := svc.ProfileState("")
		if err != nil {
			return nil, err
		}
		if p.BaseProfile != state.ProfileID || p.BaseEpoch != state.Epoch {
			return nil, &service.Error{Code: service.CodeConflict, Message: "profile changed"}
		}
		return map[string]bool{"deleted": true}, svc.DeleteInactiveProfile(p.ProfileID, p.BaseProfile, p.BaseEpoch)
	}
	id, epoch := req.ProfileID, req.ProfileEpoch
	if id == "" {
		id, epoch = s.profileID, s.profileEpoch
	}
	if req.Method == "Hello" || req.Method == "GetProfileState" || req.Method == "GetProfileSwitchOperation" {
		id, epoch = "", 0
	}
	release, err := svc.AcquireProfileCall(id, epoch)
	if err != nil {
		return nil, err
	}
	defer release()
	if req.Method == "Hello" {
		state, err := svc.ProfileState("")
		if err != nil {
			return nil, err
		}
		s.profileID, s.profileEpoch = state.ProfileID, state.Epoch
	}
	if isMITMCAMethod(req.Method) {
		return s.h.handleMITMCA(req)
	}
	switch req.Method {
	case "ExportProfileArchive":
		p, err := decode[api.ExportManifestRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.ExportProfileArchive(p)
	case "GetProfileState":
		p, err := decode[struct {
			ProfileID string `json:"profile_id"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.ProfileState(p.ProfileID)
	case "GetProfileSwitchOperation":
		p, err := decode[struct {
			OperationID string `json:"operation_id"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.ProfileSwitchOperation(p.OperationID)
	case "InstallProfile":
		p, err := decode[api.InstallProfileRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.InstallProfile(p)
	case "GetProcessTraffic":
		p, err := decode[struct {
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		value := svc.Engine().ProcessTraffic(p.Offset, p.Limit)
		value.Epoch = svc.Events().Epoch()
		return value, nil
	case "ExportManifest":
		p, err := decode[api.ExportManifestRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.ExportManifest(p)
	case "ReadResource":
		p, err := decode[api.ReadResourceRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.ReadResource(p)
	case "GetLogs":
		p, err := decode[struct {
			Limit int `json:"limit"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		return map[string]any{"events": svc.Events().Recent(service.EventLog, p.Limit)}, nil
	case "GetRules":
		p, err := decode[struct {
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.Engine().RulesPage(p.Offset, p.Limit), nil
	case "StageResource":
		p, err := decode[api.StageResourceRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.StageResource(p)
	case "InstallManagedResource":
		p, err := decode[api.InstallManagedResourceRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.InstallManagedResource(s.ctx, p)
	case "ListManagedResources":
		return svc.ListManagedResources()
	case "RefreshManagedResource":
		p, err := decode[api.RefreshManagedResourceRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.RefreshManagedResource(s.ctx, p)
	case "ProbeOutbound":
		p, err := decode[api.ProbeRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.Engine().ProbeOutbound(s.ctx, p)
	case "RunNodeArena":
		p, err := decode[api.ArenaRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.Engine().RunArena(s.ctx, p)
	case "AddTemporaryRule":
		p, err := decode[api.TemporaryRuleRequest](req.Params)
		if err != nil {
			return nil, err
		}
		rule, err := svc.Engine().AddTemporaryRule(p)
		if err != nil {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: err.Error()}
		}
		return rule, nil
	case "ListTemporaryRules":
		return svc.Engine().ListTemporaryRules(), nil
	case "RemoveTemporaryRule":
		p, err := decode[struct {
			ID string `json:"id"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		if !svc.Engine().RemoveTemporaryRule(p.ID) {
			return nil, &service.Error{Code: service.CodeNotFound, Message: "temporary rule is missing or expired"}
		}
		return map[string]bool{"removed": true}, nil
	case "GetNetworkScene":
		return svc.Engine().NetworkScene(), nil
	case "SetNetworkScene":
		p, err := decode[struct {
			Scene *string `json:"scene"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		if p.Scene == nil {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: "scene is required; use an empty string for automatic matching"}
		}
		status, err := svc.Engine().SetNetworkScene(*p.Scene)
		if err != nil {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: err.Error()}
		}
		return status, nil
	case "GetTrafficBudgets":
		return svc.TrafficBudgets()
	case "GetTraffic":
		value := svc.Engine().Traffic()
		value.Epoch = svc.Events().Epoch()
		return value, nil
	case "QueryDNS":
		p, err := decode[api.DNSQueryRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.Engine().QueryDNS(s.ctx, p)
	case "FlushDNSCache":
		return map[string]any{"cleared": svc.Engine().FlushDNSCache()}, nil
	case "ResetNetwork":
		return map[string]any{"cleared": svc.Engine().ResetNetwork()}, nil
	case "Hello":
		p, err := decode[HelloParams](req.Params)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(p.Versions, APIVersion) {
			return nil, &service.Error{Code: CodeVersion, Message: fmt.Sprintf("server speaks API version %d", APIVersion)}
		}
		s.mu.Lock()
		s.hello = true
		s.mu.Unlock()
		return HelloResult{Version: APIVersion, Server: "reka/" + Version, SchemaVersions: []int{model.SchemaVersion}, Epoch: svc.Events().Epoch()}, nil
	case "GetGroupStatus":
		return svc.Engine().GroupStatus(), nil
	case "GetCapabilities":
		return capabilities(svc), nil
	case "ImportSource":
		p, err := decode[struct {
			Import importer.Request `json:"import"`
			Reveal bool             `json:"reveal"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.PreviewImport(p.Import, p.Reveal), nil
	case "ConfigureSubscription":
		p, err := decode[struct {
			SourceID     string              `json:"source_id"`
			Base         uint64              `json:"base_revision"`
			Subscription *model.Subscription `json:"subscription"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.ConfigureSubscription(s.ctx, p.Base, p.SourceID, p.Subscription)
	case "ListSubscriptions":
		return svc.ListSubscriptions()
	case "RefreshSubscription":
		p, err := decode[struct {
			SourceID string `json:"source_id"`
			Wait     bool   `json:"wait"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		if p.Wait {
			return svc.RefreshSubscription(s.ctx, p.SourceID)
		}
		return svc.QueueSubscription(s.ctx, p.SourceID)
	case "AddModule":
		p, err := decode[api.AddModuleRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.AddModule(s.ctx, p)
	case "RemoveModule":
		p, err := decode[api.RemoveModuleRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.RemoveModule(s.ctx, p)
	case "SetModuleEnabled":
		p, err := decode[api.SetModuleEnabledRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.SetModuleEnabled(s.ctx, p)
	case "SetModuleArguments":
		p, err := decode[api.SetModuleArgumentsRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.SetModuleArguments(s.ctx, p)
	case "RefreshModule":
		p, err := decode[api.RefreshModuleRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.RefreshModule(s.ctx, p.ModuleID, p.Wait)
	case "ListModules":
		return svc.ListModules()
	case "GetModuleReport":
		p, err := decode[api.GetModuleReportRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.GetModuleReport(p.ModuleID)
	case "PreviewModule":
		p, err := decode[api.PreviewModuleRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.PreviewModule(p)
	case "GetStatus":
		return status(svc), nil
	case "GetConfiguration":
		p, err := decode[struct {
			Reveal bool `json:"reveal"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.GetConfiguration(p.Reveal), nil
	case "ValidateConfiguration":
		p, err := decode[service.ChangeRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.Validate(p)
	case "PlanConfiguration":
		p, err := decode[service.ChangeRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.Plan(p)
	case "CommitConfiguration":
		p, err := decode[service.CommitRequest](req.Params)
		if err != nil {
			return nil, err
		}
		if p.Source == "" {
			p.Source = "api"
		}
		return svc.Commit(s.ctx, p)
	case "GetOperation":
		p, err := decode[struct {
			ID string `json:"operation_id"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.GetOperation(p.ID)
	case "ListRevisions":
		revs, err := svc.ListRevisions()
		return map[string]any{"active": svc.ActiveRevision(), "revisions": revs}, err
	case "RestoreRevision":
		p, err := decode[service.RestoreRequest](req.Params)
		if err != nil {
			return nil, err
		}
		return svc.RestoreRevision(s.ctx, p)
	case "ListConnectionHistory", "ListDNSHistory", "ListRequestHistory":
		p, err := decode[history.ListOptions](req.Params)
		if err != nil {
			return nil, err
		}
		kind := history.Connections
		switch req.Method {
		case "ListDNSHistory":
			kind = history.DNS
		case "ListRequestHistory":
			kind = history.Requests
		}
		store, scope := svc.Engine().History()
		page, err := store.List(kind, scope.ProfileID, p)
		if err != nil {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: err.Error()}
		}
		return page, nil
	case "GetConnectionTimeline":
		p, err := decode[api.TimelineRequest](req.Params)
		if err != nil {
			return nil, err
		}
		if p.ID == 0 {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: "connection ID is required"}
		}
		store, _ := svc.Engine().History()
		if p.Epoch != "" && p.Epoch != store.Epoch() {
			return nil, &service.Error{Code: service.CodeNotFound, Message: "connection history belongs to an earlier runtime"}
		}
		timeline, found := svc.Engine().ConnectionTimeline(p.ID)
		if !found {
			return nil, &service.Error{Code: service.CodeNotFound, Message: "connection is missing or its history has expired"}
		}
		return timeline, nil
	case "StartHTTPSDebug":
		p, err := decode[api.HTTPSDebugRequest](req.Params)
		if err != nil {
			return nil, err
		}
		status, err := svc.Engine().StartHTTPSDebug(p)
		if err != nil {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: err.Error()}
		}
		return status, nil
	case "GetHTTPSDebug":
		return svc.Engine().HTTPSDebugStatus(), nil
	case "StopHTTPSDebug":
		svc.Engine().StopHTTPSDebug()
		return api.HTTPSDebugStatus{}, nil
	case "GetRequestDetail":
		p, err := decode[struct {
			Cursor string `json:"cursor"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		store, scope := svc.Engine().History()
		detail, ok := store.Detail(history.Requests, scope.ProfileID, p.Cursor)
		if !ok {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: "no retained request detail for this record"}
		}
		return detail, nil
	case "ClearHistory":
		p, err := decode[struct {
			Kind history.Kind `json:"kind"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		if p.Kind != history.Connections && p.Kind != history.DNS && p.Kind != history.Requests {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: "unknown history kind"}
		}
		store, scope := svc.Engine().History()
		return map[string]int{"cleared": store.Clear(p.Kind, scope.ProfileID)}, nil
	case "ListConnections":
		p, err := decode[struct {
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		if p.Limit <= 0 || p.Limit > 1000 {
			p.Limit = 100
		}
		all := svc.Engine().Connections()
		total := len(all)
		p.Offset = min(max(p.Offset, 0), total)
		end := p.Offset + min(p.Limit, total-p.Offset)
		return map[string]any{"total": total, "offset": p.Offset, "connections": all[p.Offset:end]}, nil
	case "CloseConnections":
		p, err := decode[struct {
			IDs []uint64 `json:"ids"`
			All bool     `json:"all"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		if !p.All && len(p.IDs) == 0 {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: "give ids, or all: true"}
		}
		ids := p.IDs
		if p.All {
			ids = nil
		}
		return map[string]any{"closed": svc.Engine().CloseConnections(ids)}, nil
	case "ExplainRoute":
		p, err := decode[generation.ExplainRequest](req.Params)
		if err != nil {
			return nil, err
		}
		x, err := svc.Engine().Explain(s.ctx, p)
		if err != nil {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: err.Error()}
		}
		return x, nil
	case "Subscribe":
		p, err := decode[struct {
			Types []string `json:"types"`
			Epoch string   `json:"epoch"`
			After uint64   `json:"after"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		s.subscribe(p.Types, p.Epoch, p.After)
		return map[string]any{"subscribed": true, "epoch": svc.Events().Epoch()}, nil
	case "Unsubscribe":
		s.mu.Lock()
		if s.sub != nil {
			s.sub.Close()
			s.sub = nil
		}
		s.mu.Unlock()
		return map[string]any{"subscribed": false}, nil
	case "SetSecret":
		p, err := decode[struct {
			Name  string `json:"name"`
			Value string `json:"value"`
			// Apply recompiles the active configuration so outbounds that
			// reference the secret pick it up. Default true.
			Apply *bool `json:"apply"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		if secret.Reserved(p.Name) {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: "reserved secret; use GenerateMITMCA or ImportMITMCA"}
		}
		if err := secret.ValidName(p.Name); err != nil {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: err.Error()}
		}
		if svc.Secrets() == nil {
			return nil, &service.Error{Code: CodeInternal, Message: "no secret store"}
		}
		if err := svc.Secrets().Set(p.Name, p.Value); err != nil {
			return nil, err
		}
		out := map[string]any{"name": p.Name, "ref": secret.Ref(p.Name)}
		if p.Apply == nil || *p.Apply {
			res, err := svc.Reapply(s.ctx, "secret")
			if err != nil {
				return nil, err
			}
			out["apply"] = res
		}
		return out, nil
	case "DeleteSecret":
		p, err := decode[struct {
			Name string `json:"name"`
		}](req.Params)
		if err != nil {
			return nil, err
		}
		if secret.Reserved(p.Name) {
			return nil, &service.Error{Code: service.CodeBadRequest, Message: "reserved secret; use DeleteMITMCA"}
		}
		if svc.Secrets() == nil {
			return nil, &service.Error{Code: CodeInternal, Message: "no secret store"}
		}
		if err := svc.Secrets().Delete(p.Name); errors.Is(err, secret.ErrNotFound) {
			return nil, &service.Error{Code: service.CodeNotFound, Message: "no secret " + p.Name}
		} else if err != nil {
			return nil, err
		}
		return map[string]any{"deleted": p.Name}, nil
	case "ListSecrets":
		if svc.Secrets() == nil {
			return map[string]any{"names": []string{}}, nil
		}
		names, err := svc.Secrets().List()
		if names == nil {
			names = []string{}
		}
		return map[string]any{"names": names}, err
	}
	return nil, &service.Error{Code: CodeUnknownMethod, Message: "unknown method " + req.Method}
}

func (s *Session) subscribe(types []string, epoch string, after uint64) {
	svc := s.h.svc
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sub != nil {
		s.sub.Close()
	}
	sub := svc.Events().Subscribe(types, epoch, after, func() any {
		st := status(svc)
		return map[string]any{"status": st, "revision": st.Revision}
	})
	s.sub = sub
	go func() {
		for ev := range sub.C {
			ev := ev
			b, err := json.Marshal(Message{Event: &ev})
			if err != nil {
				continue
			}
			if s.send(b) != nil {
				return
			}
		}
	}()
}

// Capabilities describes what this build supports.
type Capabilities struct {
	DHCPDNS             bool               `json:"dhcp_dns"`
	ConditionalSniff    bool               `json:"conditional_sniff"`
	ProcessModes        []string           `json:"process_modes,omitempty"`
	SniffProtocols      []string           `json:"sniff_protocols,omitempty"`
	NetworkModes        []string           `json:"network_modes"`
	TUNStacks           []string           `json:"tun_stacks,omitempty"`
	ConfigurationLayers []string           `json:"configuration_layers"`
	SourceFormats       []string           `json:"source_formats"`
	ImportSupport       []importer.Support `json:"import_support"`
	APIVersion          int                `json:"api_version"`
	SchemaVersion       int                `json:"schema_version"`
	Methods             []string           `json:"methods"`
	OutboundTypes       []string           `json:"outbound_types"`
	ListenerTypes       []string           `json:"listener_types"`
	GroupTypes          []string           `json:"group_types"`
	RuleConditions      []string           `json:"rule_conditions"`
	ShadowsocksMethods  []string           `json:"shadowsocks_methods"`
	TLSFingerprints     []string           `json:"tls_fingerprints"`
	Platform            string             `json:"platform"`
	ProcessLookup       bool               `json:"process_lookup"`
}

func capabilities(svc *service.Service) Capabilities {
	conds := make([]string, 0)
	for _, k := range router.Kinds() {
		conds = append(conds, k.String())
	}
	conds = append(conds, "geosite", "ip-asn")
	modes := []string{"off"}
	var stacks []string
	switch goruntime.GOOS {
	case "darwin", "windows":
		modes = append(modes, "system-proxy", "tun")
		stacks = svc.Engine().TUNStacks()
	case "android":
		modes = append(modes, "tun")
		stacks = svc.Engine().TUNStacks()
	}
	return Capabilities{NetworkModes: modes, TUNStacks: stacks, SniffProtocols: []string{"http", "tls", "quic"}, ProcessModes: []string{"off", "rule", "always"},
		DHCPDNS: platform.DHCPDNSSupported(), ConditionalSniff: true,
		ConfigurationLayers: []string{"default", "source", "profile", "overlay", "local"},
		SourceFormats:       []string{"native", "clash", "links", "surge-module"},
		ImportSupport:       importer.SupportMatrix(),
		APIVersion:          APIVersion,
		SchemaVersion:       model.SchemaVersion,
		Methods:             Methods,
		OutboundTypes:       compile.OutboundTypes(),
		ListenerTypes:       []string{model.ListenerMixed, model.ListenerSOCKS, model.ListenerHTTP},
		GroupTypes:          []string{model.GroupSelect, "url-test", "fallback", "load-balance"},
		RuleConditions:      conds,
		ShadowsocksMethods:  compile.ShadowsocksMethods,
		TLSFingerprints:     compile.Fingerprints,
		Platform:            goruntime.GOOS + "/" + goruntime.GOARCH,
		ProcessLookup:       svc.Engine().ProcessLookup(),
	}
}

func status(svc *service.Service) Status {
	st := Status{Revision: svc.ActiveRevision(), Runtime: svc.Engine().Status(), Goroutines: goruntime.NumGoroutine()}
	st.StartError = svc.StartError()
	return st
}
