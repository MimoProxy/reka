package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/platform"
	"github.com/MimoProxy/reka/internal/secret"
)

var profileIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

type profileCursor struct {
	ProfileID string `json:"profile_id"`
	RuntimeID string `json:"runtime_profile"`
	Epoch     uint64 `json:"profile_epoch"`
}
type profileSwitchRecord struct {
	Hash        string                  `json:"request_hash"`
	Epoch       uint64                  `json:"epoch"`
	TargetID    string                  `json:"target_id"`
	Before      *store.Active           `json:"before,omitempty"`
	After       *store.Active           `json:"after,omitempty"`
	NewRevision uint64                  `json:"new_revision,omitempty"`
	Result      api.SwitchProfileResult `json:"result"`
}

// ProfileWorkspace authorizes an ID-only namespace at daemon startup. Its lock
// also prevents two kernels from competing for the shared runtime/network journal.
type ProfileWorkspace struct {
	gate      sync.RWMutex
	root      string
	nested    bool
	initialID string
	cursor    profileCursor
	lock      *platform.StateLock
	locks     map[string]*platform.StateLock
}

func OpenProfileWorkspace(root, initialID string, nested, resume bool) (*ProfileWorkspace, error) {
	if !profileIDPattern.MatchString(initialID) {
		return nil, errf(CodeBadRequest, "invalid initial profile ID")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err = secureProfileDir(root); err != nil {
		return nil, err
	}
	lock, err := platform.LockStateRoot(root)
	if err != nil {
		return nil, err
	}
	w := &ProfileWorkspace{root: root, nested: nested, lock: lock, locks: map[string]*platform.StateLock{}}
	fail := func(err error) (*ProfileWorkspace, error) { w.Close(); return nil, err }
	data, err := os.ReadFile(w.cursorPath())
	if err == nil {
		if json.Unmarshal(data, &w.cursor) != nil || !profileIDPattern.MatchString(w.cursor.ProfileID) || !profileIDPattern.MatchString(w.cursor.RuntimeID) || w.cursor.Epoch == 0 {
			return fail(fmt.Errorf("invalid profile workspace cursor"))
		}
		if err = w.recoverSwitches(); err != nil {
			return fail(err)
		}
		if resume {
			selected, e := w.path(w.cursor.ProfileID)
			if e != nil {
				return fail(e)
			}
			if _, e = os.Stat(filepath.Join(selected, "active.json")); e != nil {
				return fail(fmt.Errorf("active profile history is unavailable: %w", e))
			}
		}
		if !resume && w.cursor.ProfileID != initialID {
			w.cursor.ProfileID = initialID
			w.cursor.Epoch++
		}
	} else if errors.Is(err, os.ErrNotExist) {
		w.cursor = profileCursor{ProfileID: initialID, RuntimeID: initialID, Epoch: 1}
	} else {
		return fail(err)
	}
	w.initialID = w.cursor.ProfileID
	if _, err = w.path(w.cursor.RuntimeID); err != nil {
		return fail(err)
	}
	return w, nil
}
func (w *ProfileWorkspace) LockRuntime() error { _, err := w.acquire(w.cursor.RuntimeID); return err }

func (w *ProfileWorkspace) InitialProfileID() string { return w.cursor.ProfileID }

func (w *ProfileWorkspace) StateRoot() (string, error)   { return w.path(w.cursor.ProfileID) }
func (w *ProfileWorkspace) RuntimeRoot() (string, error) { return w.path(w.cursor.RuntimeID) }
func (w *ProfileWorkspace) cursorPath() string {
	return filepath.Join(w.root, "profile-workspace.json")
}
func (w *ProfileWorkspace) recordPath(id string) string {
	return filepath.Join(w.root, "profile-switches", id+".json")
}
func (w *ProfileWorkspace) path(id string) (string, error) {
	if !profileIDPattern.MatchString(id) {
		return "", errf(CodeBadRequest, "invalid profile ID; paths are not accepted")
	}
	parent := filepath.Join(w.root, id)
	if err := secureProfileDir(parent); err != nil {
		return "", err
	}
	if w.nested {
		parent = filepath.Join(parent, "state")
		if err := secureProfileDir(parent); err != nil {
			return "", err
		}
	}
	return parent, nil
}
func secureProfileDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("unsafe profile directory")
	}
	return profileDirectoryOwner(info)
}
func (w *ProfileWorkspace) acquire(id string) (*store.Store, error) {
	root, err := w.path(id)
	if err != nil {
		return nil, err
	}
	if id != w.initialID && w.locks[id] == nil {
		lock, err := platform.LockStateRoot(root)
		if err != nil {
			return nil, err
		}
		w.locks[id] = lock
	}
	return store.Open(root)
}
func (w *ProfileWorkspace) writeCursor(cursor profileCursor) error {
	data, err := json.Marshal(cursor)
	if err != nil {
		return err
	}
	return secret.WriteFileAtomic(w.cursorPath(), data, 0600)
}
func (w *ProfileWorkspace) writeRecord(id string, record profileSwitchRecord) error {
	if err := store.ValidOperationID(id); err != nil {
		return err
	}
	if err := secureProfileDir(filepath.Dir(w.recordPath(id))); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return secret.WriteFileAtomic(w.recordPath(id), data, 0600)
}
func (w *ProfileWorkspace) recoverSwitches() error {
	entries, err := os.ReadDir(filepath.Join(w.root, "profile-switches"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-5]
		if store.ValidOperationID(id) != nil {
			return fmt.Errorf("invalid profile switch record name")
		}
		data, err := os.ReadFile(w.recordPath(id))
		if err != nil {
			return err
		}
		var record profileSwitchRecord
		if json.Unmarshal(data, &record) != nil {
			return fmt.Errorf("invalid profile switch record")
		}
		if record.Result.State != store.OpPending {
			continue
		}
		if w.cursor.Epoch >= record.Epoch {
			record.Result.State = store.OpCommitted
		} else {
			root, err := w.path(record.TargetID)
			if err != nil {
				return err
			}
			target, err := store.Open(root)
			if err != nil {
				return err
			}
			if record.Before != nil {
				if err = target.WriteActive(*record.Before); err != nil {
					return err
				}
			}
			if record.NewRevision != 0 {
				if err = target.DeleteRevision(record.NewRevision); err != nil {
					return err
				}
			}
			record.Result.State = store.OpFailed
			record.Result.Error = errf(CodeActivate, "profile switch did not become durable; previous profile remains active")
		}
		if err = w.writeRecord(id, record); err != nil {
			return err
		}
	}
	return nil
}
func (w *ProfileWorkspace) Close() {
	for _, lock := range w.locks {
		_ = lock.Close()
	}
	if w.lock != nil {
		_ = w.lock.Close()
	}
}

func (s *Service) BindProfiles(w *ProfileWorkspace) error {
	if w == nil {
		return nil
	}
	s.profiles = w
	return w.writeCursor(w.cursor)
}

// AcquireProfileCall pins one control request to its profile/epoch. A late
// request from another profile is rejected even if revision numbers coincide.
func (s *Service) AcquireProfileCall(id string, epoch uint64) (func(), error) {
	if s.profiles == nil {
		return func() {}, nil
	}
	w := s.profiles
	w.gate.RLock()
	if id != "" && (w.cursor.ProfileID != id || w.cursor.Epoch != epoch) {
		w.gate.RUnlock()
		return nil, errf(CodeConflict, "profile changed; reconnect to the active profile")
	}
	return w.gate.RUnlock, nil
}
func (s *Service) ProfileState(target string) (api.ProfileState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.profiles == nil {
		return api.ProfileState{Revision: s.active}, nil
	}
	w := s.profiles
	result := api.ProfileState{Enabled: true, RuntimeID: w.cursor.RuntimeID, ProfileID: w.cursor.ProfileID, Epoch: w.cursor.Epoch, Revision: s.active, TargetID: target}
	if target != "" {
		root, err := w.path(target)
		if err != nil {
			return result, err
		}
		st, err := store.Open(root)
		if err != nil {
			return result, err
		}
		active, err := st.ReadActive()
		if err != nil {
			return result, err
		}
		if active != nil {
			result.TargetExists = true
			result.TargetRevision = active.Revision
		}
	}
	return result, nil
}
func (s *Service) ProfileSwitchOperation(id string) (api.SwitchProfileResult, error) {
	if s.profiles == nil {
		return api.SwitchProfileResult{}, errf(CodeBlocked, "profile workspace is disabled")
	}
	if err := store.ValidOperationID(id); err != nil {
		return api.SwitchProfileResult{}, errf(CodeBadRequest, "invalid operation ID")
	}
	data, err := os.ReadFile(s.profiles.recordPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return api.SwitchProfileResult{}, errf(CodeNotFound, "profile switch operation not found")
	}
	if err != nil {
		return api.SwitchProfileResult{}, err
	}
	var record profileSwitchRecord
	if err = json.Unmarshal(data, &record); err != nil {
		return record.Result, err
	}
	return record.Result, nil
}

func (s *Service) secretsForProfile(root string) (secret.Store, error) {
	if s.opts.ProfileSecrets != nil {
		return s.opts.ProfileSecrets(root)
	}
	return secret.Default(root)
}
