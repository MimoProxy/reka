package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
)

// Settings reads and writes operating-system settings (system DNS, proxy
// endpoints) by key. Both operations must be idempotent: recovery may
// repeat a write that already happened.
type Settings interface {
	Read(key string) (string, error)
	Write(key, value string) error
}

// entry records one setting Reka changed: the value it found and the value
// it installed.
type entry struct {
	Key       string `json:"key"`
	Before    string `json:"before"`
	Installed string `json:"installed"`
}

// Journal is a write-ahead log of the OS settings Reka owns. Each entry is
// written and synced before the setting is changed, so a process that dies
// inside the OS call still knows what to undo. Restoring writes a setting
// back only while it still holds the value Reka installed; a newer change by
// someone else is left alone.
type Journal struct {
	mu      sync.Mutex
	Path    string
	OS      Settings
	entries []entry
}

// save writes the entries atomically and durably.
func (j *Journal) save() error {
	if err := os.MkdirAll(filepath.Dir(j.Path), 0700); err != nil {
		return err
	}
	b, e := json.Marshal(j.entries)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(j.Path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(j.Path+".tmp", j.Path); e != nil {
		return e
	}
	return syncDirectory(filepath.Dir(j.Path))
}

// Recover loads the journal left by a previous run, if any, and restores
// what it lists. Call it before any new takeover.
func (j *Journal) Recover() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	b, err := os.ReadFile(j.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &j.entries); err != nil {
		return fmt.Errorf("invalid network journal: %w", err)
	}
	return j.restore()
}

// Apply sets key to value and takes ownership of it. A setting that already
// has the value is not owned (nothing to undo). A setting owned before must
// still hold Reka's value, or the change is refused as an external edit.
func (j *Journal) Apply(key, value string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	current, err := j.OS.Read(key)
	if err != nil {
		return err
	}
	for _, v := range j.entries {
		if v.Key == key {
			if current != v.Installed {
				return fmt.Errorf("external setting changed: %s", key)
			}
			if value == v.Installed {
				return nil
			}
			return fmt.Errorf("restore %s before changing ownership", key)
		}
	}
	if current == value {
		return nil
	} // No ownership of preexisting settings.
	j.entries = append(j.entries, entry{key, current, value})
	if err = j.save(); err != nil {
		j.entries = j.entries[:len(j.entries)-1]
		return err
	}
	return j.OS.Write(key, value)
}

// Check reports an owned setting that someone else changed.
func (j *Journal) Check() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, v := range j.entries {
		s, err := j.OS.Read(v.Key)
		if err != nil {
			return err
		}
		if s != v.Installed {
			return fmt.Errorf("external setting changed: %s", v.Key)
		}
	}
	return nil
}

// Restore undoes every owned setting, newest first. Settings changed by
// someone else since are kept as they are; settings whose restore failed
// stay in the journal and are reported.
func (j *Journal) Restore() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.restore()
}

func (j *Journal) restore() error {
	old := append([]entry{}, j.entries...)
	var pending []entry
	var errs []error
	for i := len(j.entries) - 1; i >= 0; i-- {
		v := j.entries[i]
		s, err := j.OS.Read(v.Key)
		if err == nil && s == v.Installed {
			err = j.OS.Write(v.Key, v.Before)
		}
		// External changes and already-restored values are deliberately preserved.
		if err != nil {
			pending = append([]entry{v}, pending...)
			errs = append(errs, fmt.Errorf("restore %s: %w", v.Key, err))
		}
	}
	j.entries = pending
	if len(old) > 0 || !reflect.DeepEqual(old, pending) {
		if err := j.save(); err != nil {
			j.entries = old
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
