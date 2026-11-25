package profile

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"reflect"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/config/moduleacquire"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/internal/subscription"
)

type ModuleAcquireRequest struct {
	Module           model.Module `json:"module"`
	PreviousSnapshot string       `json:"previousSnapshot,omitempty"`
	OutputSnapshot   string       `json:"outputSnapshot"`
	// Force checks immediately, still sending the previous HTTP validators.
	Force bool `json:"force,omitempty"`
}

type ModuleAcquireOptions struct {
	Secrets secret.Store
	// Client overrides the same direct, system-resolved transport as Prepare.
	Client *http.Client
}

type ModuleAcquireResult struct {
	Status       string                      `json:"status"` // updated, not-modified, or failed
	ErrorCode    string                      `json:"errorCode,omitempty"`
	Metadata     *module.Metadata            `json:"metadata,omitempty"`
	Hostnames    *ModuleHostnames            `json:"hostnames,omitempty"`
	Added        []string                    `json:"added,omitempty"`
	Removed      []string                    `json:"removed,omitempty"`
	NextCheckMS  int64                       `json:"nextCheckMs,omitempty"`
	ScriptErrors []moduleacquire.ScriptError `json:"scriptErrors,omitempty"`
}

// AcquireModule writes a complete candidate snapshot atomically on success,
// including refreshed validators when its content is unchanged.
func AcquireModule(ctx context.Context, req ModuleAcquireRequest, opts ModuleAcquireOptions) ModuleAcquireResult {
	fail := func(code string) ModuleAcquireResult {
		if ctx.Err() != nil {
			code = "cancelled"
		}
		return ModuleAcquireResult{Status: "failed", ErrorCode: code}
	}
	if ctx.Err() != nil {
		return fail("cancelled")
	}
	if model.ValidModule(&req.Module) != nil {
		return fail("module_invalid")
	}
	if req.OutputSnapshot == "" {
		return fail("module_snapshot_write")
	}
	var old *ModuleSnapshot
	if req.PreviousSnapshot != "" {
		var err error
		old, err = LoadModuleSnapshot(req.PreviousSnapshot)
		if err != nil {
			return fail(subscription.Code(err))
		}
		if old.Source.ID != req.Module.ID {
			return fail("module_snapshot_mismatch")
		}
	}
	dir, err := os.MkdirTemp(filepath.Dir(req.OutputSnapshot), ".reka-module-*")
	if err != nil {
		return fail("module_snapshot_write")
	}
	defer os.RemoveAll(dir)
	blobs, err := resource.Open(dir)
	if err != nil {
		return fail("resource_store_failed")
	}
	client := opts.Client
	if client == nil {
		client = subscription.HTTPClientWithControl(nil, systemLookup)
		defer client.CloseIdleConnections()
	}
	download := moduleacquire.Options{Client: client, Blobs: blobs, Force: req.Force, IncludeScripts: true}
	download.ResolveURL = func(url string) (string, error) {
		name, ref := secret.ParseRef(url)
		if !ref {
			return url, nil
		}
		if opts.Secrets != nil {
			if resolved, err := opts.Secrets.Get(name); err == nil {
				return resolved, nil
			}
		}
		return "", &subscription.Error{Code: "credentials_unavailable"}
	}
	if old != nil && old.Source.Module.Request == req.Module.RequestHash() {
		download.Previous = model.Source{ID: old.Source.ID, Module: &old.Source.Module, Lock: &old.Source.Lock}
		download.PreviousEntries = old.Entries
		if old.Interval == req.Module.Interval && maps.Equal(old.Arguments, req.Module.Arguments) {
			download.PreviousScriptErrors = old.ScriptErrors
		}
		for _, data := range old.Resources {
			if _, err := blobs.Put(data); err != nil {
				return fail("resource_store_failed")
			}
		}
	}
	acquired, err := moduleacquire.Acquire(ctx, req.Module, download)
	if err != nil {
		return fail(subscription.Code(err))
	}
	snapshot := ModuleSnapshot{
		Version: moduleSnapshotVersion, Source: acquired.Snapshot, Entries: acquired.Entries,
		Arguments: req.Module.Arguments, Interval: req.Module.Interval, Resources: make(map[string][]byte),
		ScriptErrors: acquired.ScriptErrors,
	}
	if !acquired.Next.IsZero() {
		snapshot.NextCheckMS = acquired.Next.UnixMilli()
	}
	for _, entry := range acquired.Entries {
		if snapshot.Resources[entry.Hash] != nil {
			continue
		}
		data, err := blobs.Read(entry.Hash)
		if err != nil {
			return fail("resource_store_failed")
		}
		snapshot.Resources[entry.Hash] = data
	}
	hosts := snapshot.hostnames()
	result := ModuleAcquireResult{
		Status: "updated", Metadata: &acquired.Metadata, Hostnames: &hosts, NextCheckMS: snapshot.NextCheckMS,
		ScriptErrors: snapshot.ScriptErrors,
	}
	var previous ModuleHostnames
	if old != nil {
		previous = old.hostnames()
		if reflect.DeepEqual(old.Source, snapshot.Source) && maps.Equal(old.Arguments, snapshot.Arguments) {
			result.Status = "not-modified"
		}
	}
	result.Added, result.Removed = hostnameDiff(previous, hosts)
	data, err := json.Marshal(&snapshot)
	if err != nil || len(data) > maxModuleSnapshotBytes {
		return fail("module_snapshot_too_large")
	}
	if ctx.Err() != nil {
		return fail("cancelled")
	}
	if err := writeAtomic(req.OutputSnapshot, data); err != nil {
		return fail("module_snapshot_write")
	}
	return result
}

func (s *ModuleSnapshot) hostnames() ModuleHostnames {
	result, _ := module.Convert(s.readRoot(), module.Options{
		ID: s.Source.ID, Arguments: s.Arguments, ResourceForKind: s.resourceResolver(),
	})
	return moduleHostnames(result)
}

func hostnameDiff(old, new ModuleHostnames) (added, removed []string) {
	unique := func(hosts ModuleHostnames) ([]string, map[string]bool) {
		list := make([]string, 0, len(hosts.Insert)+len(hosts.Append))
		seen := make(map[string]bool, cap(list))
		for _, names := range [][]string{hosts.Insert, hosts.Append} {
			for _, host := range names {
				if !seen[host] {
					list = append(list, host)
					seen[host] = true
				}
			}
		}
		return list, seen
	}
	previous, oldSet := unique(old)
	current, newSet := unique(new)
	for _, host := range current {
		if !oldSet[host] {
			added = append(added, host)
		}
	}
	for _, host := range previous {
		if !newSet[host] {
			removed = append(removed, host)
		}
	}
	return added, removed
}
