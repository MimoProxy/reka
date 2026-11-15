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

// Setting operations must be idempotent. The journal is written before each
// mutation, so recovery works even when a process dies inside the OS call.
type Settings interface {
	Read(key string) (string, error)
	Write(key, value string) error
}
type entry struct {
	Key       string `json:"key"`
	Before    string `json:"before"`
	Installed string `json:"installed"`
}
type Journal struct {
	mu      sync.Mutex
	Path    string
	OS      Settings
	entries []entry
}

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
func (j *Journal) Recover() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	b, e := os.ReadFile(j.Path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = json.Unmarshal(b, &j.entries); e != nil {
		return fmt.Errorf("invalid network journal: %w", e)
	}
	return j.restore()
}
func (j *Journal) Apply(key, value string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	current, e := j.OS.Read(key)
	if e != nil {
		return e
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
	if e = j.save(); e != nil {
		j.entries = j.entries[:len(j.entries)-1]
		return e
	}
	return j.OS.Write(key, value)
}
func (j *Journal) Check() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, v := range j.entries {
		s, e := j.OS.Read(v.Key)
		if e != nil {
			return e
		}
		if s != v.Installed {
			return fmt.Errorf("external setting changed: %s", v.Key)
		}
	}
	return nil
}
func (j *Journal) Restore() error { j.mu.Lock(); defer j.mu.Unlock(); return j.restore() }
func (j *Journal) restore() error {
	old := append([]entry{}, j.entries...)
	var pending []entry
	var errs []error
	for i := len(j.entries) - 1; i >= 0; i-- {
		v := j.entries[i]
		s, e := j.OS.Read(v.Key)
		if e == nil && s == v.Installed {
			e = j.OS.Write(v.Key, v.Before)
		}
		// External changes and already-restored values are deliberately preserved.
		if e != nil {
			pending = append([]entry{v}, pending...)
			errs = append(errs, fmt.Errorf("restore %s: %w", v.Key, e))
		}
	}
	j.entries = pending
	if len(old) > 0 || !reflect.DeepEqual(old, pending) {
		if e := j.save(); e != nil {
			j.entries = old
			errs = append(errs, e)
		}
	}
	return errors.Join(errs...)
}
