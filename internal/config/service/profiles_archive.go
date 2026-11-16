package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/secret"
)

// InstallProfile preserves imported immutable revisions and refresh validators.
// It never replaces an initialized namespace and never activates a generation.
func (s *Service) InstallProfile(req api.InstallProfileRequest) (api.ProfileState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.profiles == nil {
		return api.ProfileState{}, errf(CodeBlocked, "profile workspace is disabled")
	}
	if req.ProfileID == s.profiles.cursor.ProfileID {
		return api.ProfileState{}, errf(CodeBlocked, "cannot install over the active profile")
	}
	target, err := s.profiles.acquire(req.ProfileID)
	if err != nil {
		return api.ProfileState{}, err
	}
	active, err := target.ReadActive()
	if err != nil {
		return api.ProfileState{}, err
	}
	if active != nil {
		return api.ProfileState{}, errf(CodeConflict, "target profile already has independent history; import was not applied")
	}
	data, err := resource.At(s.store.Root()).Read(req.ArchiveHash)
	if err != nil {
		return api.ProfileState{}, errf(CodeInvalid, "profile archive unavailable")
	}
	if err = installProfileArchive(target, data, s.engine.ProcessLookup(), s.secretsForProfile); err != nil {
		return api.ProfileState{}, err
	}
	active, err = target.ReadActive()
	if err != nil || active == nil {
		return api.ProfileState{}, errf(CodeInvalid, "imported active revision unavailable")
	}
	return api.ProfileState{Enabled: true, ProfileID: s.profiles.cursor.ProfileID, Epoch: s.profiles.cursor.Epoch, Revision: s.active, TargetID: req.ProfileID, TargetExists: true, TargetRevision: active.Revision}, nil
}

func InstallInitialProfileArchive(root, hash string, processLookup bool) error {
	target, err := store.Open(root)
	if err != nil {
		return err
	}
	active, err := target.ReadActive()
	if err != nil {
		return err
	}
	if active != nil {
		return errf(CodeConflict, "administrator profile already has independent history; refusing to overwrite it")
	}
	data, err := resource.At(root).Read(hash)
	if err != nil {
		return err
	}
	return installProfileArchive(target, data, processLookup, secret.Default)
}

func installProfileArchive(target *store.Store, data []byte, processLookup bool, secretsFor func(string) (secret.Store, error)) error {
	var err error
	var archive api.ProfileArchive
	if json.Unmarshal(data, &archive) != nil || archive.Version != 1 || len(archive.Revisions) == 0 || len(archive.Revisions) > 2000 || len(archive.Operations) > 10000 || len(archive.Subscriptions) > 1024 {
		return errf(CodeInvalid, "invalid or oversized profile archive")
	}
	inputBytes := 0
	for _, item := range archive.Revisions {
		inputBytes += len(item.Profile) + len(item.Local) + len(item.Sources) + len(item.Overlay)
	}
	for _, raw := range archive.Operations {
		inputBytes += len(raw)
	}
	for _, raw := range archive.Subscriptions {
		inputBytes += len(raw)
	}
	if inputBytes > 96<<20 {
		return errf(CodeInvalid, "profile archive input exceeds 96 MiB")
	}
	var requested store.Active
	if json.Unmarshal(archive.Active, &requested) != nil || requested.Revision == 0 {
		return errf(CodeInvalid, "invalid archive active revision")
	}
	// This namespace has no active history. Discard debris from an interrupted
	// earlier import before writing a fresh, complete archive.
	for _, name := range []string{"operations", "subscriptions"} {
		if err = os.RemoveAll(filepath.Join(target.Root(), name)); err != nil {
			return err
		}
		if err = secureProfileDir(filepath.Join(target.Root(), name)); err != nil {
			return err
		}
	}
	dormant := &Service{store: target}
	if err = dormant.recover(); err != nil {
		return err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.Remove(filepath.Join(target.Root(), "active.json"))
			_ = dormant.recover()
			for _, name := range []string{"operations", "subscriptions"} {
				_ = os.RemoveAll(filepath.Join(target.Root(), name))
				_ = secureProfileDir(filepath.Join(target.Root(), name))
			}
		}
	}()
	var selected *api.ProfileArchiveRevision
	numbers := map[uint64]bool{}
	for index := range archive.Revisions {
		item := &archive.Revisions[index]
		var meta store.Revision
		if json.Unmarshal(item.Meta, &meta) != nil || meta.Number == 0 || meta.Number > requested.Revision || numbers[meta.Number] {
			return errf(CodeInvalid, "invalid archive revision identity")
		}
		numbers[meta.Number] = true
		for _, doc := range []string{item.Profile, item.Local, item.Sources, item.Overlay} {
			if len(doc) > model.MaxDocumentSize {
				return errf(CodeInvalid, "archive document exceeds limit")
			}
		}
		for _, doc := range []struct{ name, text string }{{model.DocProfile, item.Profile}, {model.DocLocal, item.Local}, {model.DocSources, item.Sources}, {model.DocOverlay, item.Overlay}} {
			if _, ds := model.LoadDoc(doc.name, []byte(doc.text)); ds.HasErrors() {
				return errf(CodeInvalid, "archive revision %d has invalid %s", meta.Number, doc.name)
			}
		}
		copied, e := target.WriteRevision(meta, []byte(item.Profile), []byte(item.Local), []byte(item.Sources), []byte(item.Overlay))
		if e != nil {
			return e
		}
		if copied.Profile != meta.Profile || copied.Local != meta.Local || copied.Sources != meta.Sources || copied.Overlay != meta.Overlay {
			return errf(CodeInvalid, "archive revision hashes do not match")
		}
		if meta.Number == requested.Revision {
			if requested.Profile != meta.Profile || requested.Local != meta.Local || requested.Sources != meta.Sources || requested.Overlay != meta.Overlay {
				return errf(CodeInvalid, "archive active hashes do not match")
			}
			selected = item
		}
	}
	if selected == nil {
		return errf(CodeInvalid, "archive active revision is missing")
	}
	secrets, err := secretsFor(target.Root())
	if err != nil {
		return err
	}
	if eff, ds := compile.Compile([]byte(selected.Profile), []byte(selected.Local), compile.Options{Secrets: secrets, ReadResource: resource.At(target.Root()).Read, Sources: []byte(selected.Sources), Overlay: []byte(selected.Overlay), ProcessLookup: processLookup}); eff == nil {
		return errf(CodeInvalid, "archive active configuration cannot run: %s", ds.Errors())
	}
	for _, raw := range archive.Operations {
		var op store.Operation
		if json.Unmarshal(raw, &op) != nil || store.ValidOperationID(op.ID) != nil || op.Revision > requested.Revision {
			return errf(CodeInvalid, "invalid archive operation record")
		}
		if err = target.WriteOperation(op); err != nil {
			return err
		}
	}
	if err = secureProfileDir(filepath.Join(target.Root(), "subscriptions")); err != nil {
		return err
	}
	for id, raw := range archive.Subscriptions {
		var record refreshRecord
		if !profileIDPattern.MatchString(id) || len(raw) > 2<<20 || json.Unmarshal(raw, &record) != nil || record.Status.SourceID != id {
			return errf(CodeInvalid, "invalid subscription cache record")
		}
		// Dead refresh jobs never migrate; durable validators/last-good usage do.
		if record.Status.State == "refreshing" {
			record.Status.State = "pending"
			record.Status.NextAttempt = time.Time{}
		}
		data, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if err = secret.WriteFileAtomic(filepath.Join(target.Root(), "subscriptions", id+".json"), data, 0600); err != nil {
			return err
		}
	}
	if err = target.WriteActive(requested); err != nil {
		return err
	}
	if err = target.Barrier(); err != nil {
		return err
	}
	succeeded = true
	return nil
}

func (s *Service) DeleteInactiveProfile(id, base string, epoch uint64) error {
	if s.profiles == nil {
		return errf(CodeBlocked, "profile workspace is disabled")
	}
	w := s.profiles
	w.gate.Lock()
	defer w.gate.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if base != w.cursor.ProfileID || epoch != w.cursor.Epoch {
		return errf(CodeConflict, "profile changed")
	}
	if err := w.recoverSwitches(); err != nil {
		return err
	}
	if id == w.cursor.ProfileID {
		return errf(CodeBlocked, "cannot delete the active profile")
	}
	if id == w.cursor.RuntimeID || id == w.initialID {
		return errf(CodeBlocked, "this profile owns the current runtime journal; stop the kernel before deleting it")
	}
	root, err := w.path(id)
	if err != nil {
		return err
	}
	if lock := w.locks[id]; lock != nil {
		_ = lock.Close()
		delete(w.locks, id)
	}
	// UUID/id validation and directory ownership were checked by path().
	if err = os.RemoveAll(root); err != nil {
		return fmt.Errorf("delete inactive profile: %w", err)
	}
	return nil
}
