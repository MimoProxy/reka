package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/resource"
)

func (s *Service) SwitchProfile(ctx context.Context, req api.SwitchProfileRequest) (api.SwitchProfileResult, error) {
	if s.profiles == nil {
		return api.SwitchProfileResult{}, errf(CodeBlocked, "profile workspace is disabled")
	}
	if err := store.ValidOperationID(req.OperationID); err != nil {
		return api.SwitchProfileResult{}, errf(CodeBadRequest, "an operation ID is required")
	}
	if !profileIDPattern.MatchString(req.ProfileID) {
		return api.SwitchProfileResult{}, errf(CodeBadRequest, "invalid profile ID")
	}
	w := s.profiles
	w.gate.Lock()
	defer w.gate.Unlock()
	if err := w.recoverSwitches(); err != nil {
		return api.SwitchProfileResult{}, err
	}
	body, _ := json.Marshal(req)
	hash := store.Hash(body)
	if data, err := os.ReadFile(w.recordPath(req.OperationID)); err == nil {
		var record profileSwitchRecord
		if json.Unmarshal(data, &record) != nil {
			return record.Result, fmt.Errorf("invalid switch operation")
		}
		if record.Hash != hash {
			return record.Result, errf(CodeOpReused, "switch operation ID reused")
		}
		return record.Result, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return api.SwitchProfileResult{}, err
	}
	s.mu.Lock()
	currentID, currentEpoch, currentRevision := w.cursor.ProfileID, w.cursor.Epoch, s.active
	s.mu.Unlock()
	result := api.SwitchProfileResult{State: store.OpRejected, OperationID: req.OperationID, ProfileID: currentID, Epoch: currentEpoch, Revision: currentRevision}
	defer func() {
		if result.State == store.OpRejected && result.Error != nil {
			_ = w.writeRecord(req.OperationID, profileSwitchRecord{Hash: hash, Epoch: currentEpoch, TargetID: req.ProfileID, Result: result})
		}
	}()
	if req.BaseProfile != currentID || req.BaseEpoch != currentEpoch || req.BaseRevision != currentRevision {
		result.Error = errf(CodeConflict, "profile or revision changed; refresh before switching")
		return result, nil
	}
	if req.ProfileID == currentID {
		result.State = store.OpCommitted
		if err := w.writeRecord(req.OperationID, profileSwitchRecord{Hash: hash, Epoch: currentEpoch, TargetID: req.ProfileID, Result: result}); err != nil {
			return result, err
		}
		return result, nil
	}
	// Cancel and join the old manager before changing stores. It never gets a
	// chance to publish a late response into the destination profile.
	options, wasStarted := s.pauseProfileSubscriptions()
	defer func() {
		if err := s.resumeProfileSubscriptions(options, wasStarted); err != nil {
			s.log.Error("resume profile subscriptions", "err", err)
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != currentRevision {
		result.Error = errf(CodeConflict, "active revision changed while subscriptions stopped; retry the switch")
		result.Revision = s.active
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	target, err := w.acquire(req.ProfileID)
	if err != nil {
		result.Error = errf(CodePrepare, "%v", err)
		return result, nil
	}
	active, err := target.ReadActive()
	if err != nil {
		return result, err
	}
	targetSecrets, err := s.secretsForProfile(target.Root())
	if err != nil {
		return result, err
	}
	opts := compile.Options{Secrets: targetSecrets, ReadResource: resource.At(target.Root()).Read, ProcessLookup: s.engine.ProcessLookup()}
	if active == nil {
		// A new empty profile inherits only this machine's listener/network settings.
		profile := []byte(DefaultProfile)
		if req.InitialProfile != nil {
			profile = []byte(*req.InitialProfile)
		}
		local := append([]byte(nil), s.local...)
		eff, ds := compile.Compile(profile, local, opts)
		if eff == nil {
			result.Error = errf(CodeInvalid, "new profile: %s", ds.Errors())
			return result, nil
		}
		revision := store.Revision{Number: 1, Operation: "initial", Source: "initial", Message: "create independent profile", Created: time.Now().UTC()}
		revision, err = target.WriteRevision(revision, profile, local, nil, nil)
		if err != nil {
			return result, err
		}
		created := store.Active{Revision: 1, Profile: revision.Profile, Local: revision.Local, Sources: revision.Sources, Overlay: revision.Overlay, Operation: "initial", Updated: time.Now().UTC()}
		if err = target.WriteActive(created); err != nil {
			return result, err
		}
		active = &created
	}
	dormant := &Service{store: target}
	if err = dormant.recover(); err != nil {
		return result, err
	}
	_, profile, local, err := target.ReadRevision(active.Revision)
	if err != nil {
		return result, err
	}
	sources, overlay, err := target.ReadLayers(active.Revision)
	if err != nil {
		return result, err
	}
	originalLocal := append([]byte(nil), local...)
	if req.PreserveNetwork {
		mode := "off"
		if s.eff != nil {
			mode = s.eff.Network.Mode
		}
		local, err = profileNetworkMode(local, mode)
		if err != nil {
			result.Error = errf(CodeInvalid, "target local settings: %v", err)
			return result, nil
		}
	}
	opts.Sources, opts.Overlay = sources, overlay
	eff, diags := compile.Compile(profile, local, opts)
	if eff == nil {
		result.Error = errf(CodeInvalid, "target profile is invalid: %s", diags.Errors())
		return result, nil
	}
	prepared, err := s.engine.Prepare(eff)
	if err != nil {
		result.Error = errf(CodePrepare, "target profile could not be prepared: %v", err)
		return result, nil
	}
	if err = ctx.Err(); err != nil {
		s.engine.Abort(prepared)
		return result, err
	}
	after := *active
	newRevision := uint64(0)
	if !bytes.Equal(local, originalLocal) {
		numbers, e := target.RevisionNumbers()
		if e != nil {
			s.engine.Abort(prepared)
			return result, e
		}
		number := active.Revision + 1
		for _, n := range numbers {
			if n >= number {
				number = n + 1
			}
		}
		revision, e := target.WriteRevision(store.Revision{Number: number, Base: active.Revision, Operation: req.OperationID, Source: "profile-switch", Message: "keep current network takeover mode", Created: time.Now().UTC()}, profile, local, sources, overlay)
		if e != nil {
			s.engine.Abort(prepared)
			return result, e
		}
		after = store.Active{Revision: number, Profile: revision.Profile, Local: revision.Local, Sources: revision.Sources, Overlay: revision.Overlay, Operation: req.OperationID, Updated: time.Now().UTC()}
		newRevision = number
	}
	result.State = store.OpPending
	result.ProfileID = req.ProfileID
	result.Epoch = currentEpoch + 1
	result.Revision = after.Revision
	record := profileSwitchRecord{Hash: hash, Epoch: result.Epoch, TargetID: req.ProfileID, Before: active, After: &after, NewRevision: newRevision, Result: result}
	if err = w.writeRecord(req.OperationID, record); err != nil {
		s.engine.Abort(prepared)
		if newRevision != 0 {
			_ = target.DeleteRevision(newRevision)
		}
		return result, err
	}
	if err = s.fail("profile-switch-intent"); err != nil {
		s.engine.Abort(prepared)
		return result, err
	}
	generation, activationErr := s.engine.ActivateProfile(prepared, after.Revision, req.ProfileID)
	cursorAttempted := false
	fail := func(cause error) (api.SwitchProfileResult, error) {
		result.State = store.OpFailed
		result.ProfileID = currentID
		result.Epoch = currentEpoch
		result.Revision = currentRevision
		result.Error = errf(CodeActivate, "profile switch failed: %v", cause)
		if s.eff != nil {
			previous, e := s.engine.Prepare(s.eff)
			if e == nil {
				_, e = s.engine.ActivateProfile(previous, s.active, currentID)
			}
			if e != nil {
				result.Degraded = true
				s.startErr = e
			}
		}
		// A rename can succeed before directory fsync reports an error.
		// Explicitly restore the old workspace pointer on that failure path.
		if cursorAttempted {
			if e := w.writeCursor(w.cursor); e != nil {
				result.Degraded = true
			}
		}
		if e := target.WriteActive(*active); e != nil {
			result.Degraded = true
		}
		if newRevision != 0 {
			if e := target.DeleteRevision(newRevision); e != nil {
				result.Degraded = true
			}
		}
		record.Result = result
		_ = w.writeRecord(req.OperationID, record)
		return result, nil
	}
	if activationErr != nil {
		return fail(activationErr)
	}
	if err = s.fail("profile-switch-activated"); err != nil {
		return result, err
	}
	if err = target.WriteActive(after); err != nil {
		return fail(err)
	}
	cursor := w.cursor
	cursor.ProfileID = req.ProfileID
	cursor.Epoch = result.Epoch
	if err = s.fail("profile-switch-before-pointer"); err != nil {
		return fail(err)
	}
	cursorAttempted = true
	if err = w.writeCursor(cursor); err != nil {
		return fail(err)
	}
	// This durable pointer is the commit decision. Recovery resolves interrupted
	// switch records from its monotonic epoch, without replaying network intent.
	w.cursor = cursor
	s.profileArchives = nil
	s.store = target
	s.opts.StateRoot = target.Root()
	s.opts.Secrets = targetSecrets
	s.active = after.Revision
	s.profile = profile
	s.local = local
	s.sources = sources
	s.overlay = overlay
	s.eff = eff
	s.warnings = diags
	s.startErr = nil
	result.State = store.OpCommitted
	result.Generation = generation
	record.Result = result
	if err = w.writeRecord(req.OperationID, record); err != nil {
		s.log.Error("record committed profile switch", "operation", req.OperationID, "err", err)
	}
	s.events.Publish("profile.switched", result)
	s.events.Publish(EventRuntime, map[string]any{"profile_id": req.ProfileID, "profile_epoch": cursor.Epoch, "revision": s.active, "generation": generation})
	return result, nil
}

func profileNetworkMode(local []byte, mode string) ([]byte, error) {
	parsed, _, ds := model.ParseLocal(local)
	if ds.HasErrors() {
		return nil, ds.Errors()
	}
	if parsed.Network != nil && parsed.Network.Mode == mode {
		return local, nil
	}
	if parsed.Network == nil && mode == "off" {
		return local, nil
	}
	doc, ds := model.LoadDoc(model.DocLocal, local)
	if ds.HasErrors() {
		return nil, ds.Errors()
	}
	value, _ := json.Marshal(mode)
	if parsed.Network == nil {
		value, _ = json.Marshal(map[string]string{"mode": mode})
		if err := doc.Apply(model.Op{Op: "set", Path: "/network", Value: value}); err != nil {
			return nil, err
		}
	} else if err := doc.Apply(model.Op{Op: "set", Path: "/network/mode", Value: value}); err != nil {
		return nil, err
	}
	return doc.Bytes(), nil
}
func (s *Service) pauseProfileSubscriptions() (RefreshOptions, bool) {
	s.refreshMu.Lock()
	manager := s.refresh
	s.refresh = nil
	s.refreshMu.Unlock()
	if manager == nil {
		return RefreshOptions{}, false
	}
	manager.mu.Lock()
	options, started := manager.options, manager.started
	manager.mu.Unlock()
	manager.Close()
	return options, started
}
func (s *Service) resumeProfileSubscriptions(options RefreshOptions, started bool) error {
	if started {
		return s.StartSubscriptions(options)
	}
	return nil
}

// ActiveProfileResourceRoot is used only by the chunked upload endpoint. The
// handler already pins the current context; the destination remains ID-scoped.
func (s *Service) ActiveProfileResourceRoot(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		return s.store.Root(), nil
	}
	if s.profiles == nil {
		return "", errf(CodeBlocked, "profile workspace is disabled")
	}
	target, err := s.profiles.acquire(id)
	if err != nil {
		return "", err
	}
	return target.Root(), nil
}
