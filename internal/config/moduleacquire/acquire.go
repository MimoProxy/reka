// Package moduleacquire downloads module snapshots without scheduling or
// publishing a configuration revision.
package moduleacquire

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/subscription"
)

// MaxBundleSize bounds the module text and all pinned resources together.
const MaxBundleSize = 32 << 20

// scriptRetryInterval bounds how long a failed script waits for its next
// attempt, matching the cap of the source refresh backoff.
const scriptRetryInterval = 30 * 60

// Snapshot is the pin written to a sources document.
type Snapshot struct {
	ID     string               `json:"id"`
	Module model.ModuleSnapshot `json:"module"`
	Lock   model.SourceLock     `json:"lock"`
}

type Options struct {
	Client               *http.Client
	Blobs                *resource.Store
	ResolveURL           func(string) (string, error)
	Previous             model.Source
	PreviousEntries      map[string]subscription.Entry
	PreviousScriptErrors []ScriptError
	Force                bool
	// IncludeScripts enables script pins for consumers that read script locks.
	IncludeScripts bool
}

type Result struct {
	Snapshot     Snapshot
	Metadata     module.Metadata
	Entries      map[string]subscription.Entry
	Next         time.Time
	ScriptErrors []ScriptError
}

type ScriptError struct {
	Request string    `json:"request"`
	Code    string    `json:"code"`
	Checked time.Time `json:"checked"`
}

// EntryKey keeps script validators independent of Map Local validators when
// both sections refer to the same URL. Existing Map Local keys stay stable.
func EntryKey(lock model.ResourceLock) string {
	switch lock.Kind {
	case "script", module.RuleSetKind, module.DomainSetKind:
		return lock.Kind + "/" + lock.ID
	}
	return lock.ID
}

// Matches reports whether a source pins the declared location and format.
func Matches(def model.Module, src model.Source) bool {
	return def.MatchesSnapshot(src.Module) && src.Lock != nil && resource.ValidHash(src.Lock.Root)
}

// Acquire fetches the root and referenced resources using the
// previous lock to validate cached entries before issuing conditional requests.
// Script failures can leave a usable snapshot for the rest of the module.
func Acquire(ctx context.Context, def model.Module, opts Options) (Result, error) {
	if model.ValidModule(&def) != nil {
		return Result{}, &subscription.Error{Code: "module_invalid"}
	}
	src := opts.Previous
	if src.ID != "" && src.Module == nil {
		return Result{}, &subscription.Error{Code: "module_source_conflict"}
	}
	validated := make(map[string]subscription.Entry)
	previousFailures := make(map[string]ScriptError)
	if Matches(def, src) {
		if entry := opts.PreviousEntries["root"]; entry.Hash == src.Lock.Root {
			validated["root"] = entry
		}
		for _, lock := range src.Lock.Resources {
			key := EntryKey(lock)
			if entry := opts.PreviousEntries[key]; entry.Hash == lock.Hash {
				validated[key] = entry
			}
		}
		if !opts.Force && len(validated) == len(src.Lock.Resources)+1 {
			for _, failure := range opts.PreviousScriptErrors {
				previousFailures[failure.Request] = failure
			}
		}
	}
	interval := def.Interval
	if interval == 0 {
		interval = model.DefaultResourceInterval
	}
	fetcher := subscription.Fetcher{Client: opts.Client, Blobs: opts.Blobs, MaxBytes: model.MaxDocumentSize, MaxBundleBytes: MaxBundleSize}
	fetcher.UserAgent = moduleUserAgent(def.Format, def.URL)
	batch := fetcher.Batch(validated, opts.Force)
	location := def.File
	var body []byte
	var err error
	if def.File != "" {
		body, err = ReadFile(def.File, model.MaxDocumentSize)
		if err == nil {
			body, err = batch.Inline("root", "module", "", body)
		}
	} else {
		url := def.URL
		if opts.ResolveURL != nil {
			url, err = opts.ResolveURL(url)
		}
		if err == nil {
			location = url
			body, err = batch.Fetch(ctx, "root", "module", "", url, nil, interval)
		}
	}
	if err != nil {
		return Result{}, err
	}
	format := def.Format
	if format == "" {
		format = module.DetectFormat(location, body)
	}
	if format == "" {
		format = model.ModuleFormatSurge
	}
	fetcher.UserAgent = moduleUserAgent(format, location)
	meta, refs := module.InspectWithOptions(body, module.Options{Format: format, Arguments: def.Arguments, ModuleInterval: interval})
	if len(refs.MapLocal) > model.MaxModuleResources {
		return Result{}, &subscription.Error{Code: "too_many_module_resources"}
	}
	if !opts.IncludeScripts {
		refs.Scripts = nil
	}
	if len(refs.Scripts) > model.MaxModuleScripts {
		return Result{}, &subscription.Error{Code: "too_many_module_scripts"}
	}
	if len(refs.RuleSets) > model.MaxModuleRuleSets {
		return Result{}, &subscription.Error{Code: "too_many_module_rule_sets"}
	}
	fetcher.MaxBytes = httprewrite.MaxMapLocalSize
	locks := make([]model.ResourceLock, 0, len(refs.MapLocal)+len(refs.RuleSets)+len(refs.Scripts))
	for _, ref := range refs.MapLocal {
		request := resource.Hash([]byte(ref.URL))
		id := request[:24]
		if _, err := batch.Fetch(ctx, id, "map-local", "", ref.URL, nil, ref.Interval); err != nil {
			return Result{}, err
		}
		locks = append(locks, model.ResourceLock{ID: id, Kind: "map-local", Request: request, Hash: batch.Entries[id].Hash})
	}
	fetcher.MaxBytes = model.MaxModuleRuleSetSize
	for _, ref := range refs.RuleSets {
		request := resource.Hash([]byte(ref.URL))
		lock := model.ResourceLock{ID: request[:24], Kind: ref.Kind, Request: request}
		key := EntryKey(lock)
		fetcher.ValidateBody = func(data []byte) error { return ValidateRuleSetBody(ref.Kind, data) }
		if _, err := batch.Fetch(ctx, key, lock.Kind, "", ref.URL, nil, ref.Interval); err != nil {
			return Result{}, err
		}
		lock.Hash = batch.Entries[key].Hash
		locks = append(locks, lock)
	}
	var scriptErrors []ScriptError
	var scriptRetry time.Time
	fetcher.MaxBytes = model.MaxScriptSize
	fetcher.ValidateBody = ValidateScriptBody
	for _, script := range refs.Scripts {
		if ctx.Err() != nil {
			return Result{}, &subscription.Error{Code: "cancelled"}
		}
		request := resource.Hash([]byte(script.URL))
		lock := model.ResourceLock{ID: request[:24], Kind: "script", Request: request}
		key := EntryKey(lock)
		retryAfter := time.Duration(min(script.Interval, scriptRetryInterval)) * time.Second
		if failure, ok := previousFailures[request]; ok && validated[key].Hash == "" {
			retry := failure.Checked.Add(retryAfter)
			if time.Now().UTC().Before(retry) {
				scriptErrors = append(scriptErrors, failure)
				scriptRetry = earliest(scriptRetry, retry)
				continue
			}
		}
		_, err := batch.Fetch(ctx, key, lock.Kind, "", script.URL, nil, script.Interval)
		if ctx.Err() != nil {
			return Result{}, &subscription.Error{Code: "cancelled"}
		}
		if err != nil {
			code := subscription.Code(err)
			if code == "bundle_too_large" || code == "resource_store_failed" {
				return Result{}, err
			}
			checked := time.Now().UTC()
			retained, err := batch.Retain(key, lock.Kind, subscription.RequestDigest(script.URL, nil), code, checked, retryAfter)
			if err != nil {
				return Result{}, err
			}
			if !retained {
				scriptErrors = append(scriptErrors, ScriptError{Request: request, Code: code, Checked: checked})
				scriptRetry = earliest(scriptRetry, checked.Add(retryAfter))
				continue
			}
		}
		entry := batch.Entries[key]
		if entry.RetainedError != "" {
			scriptErrors = append(scriptErrors, ScriptError{Request: request, Code: entry.RetainedError, Checked: entry.Checked})
		}
		lock.Hash = entry.Hash
		locks = append(locks, lock)
	}
	if ctx.Err() != nil {
		return Result{}, &subscription.Error{Code: "cancelled"}
	}
	var next time.Time
	if def.URL != "" {
		next = time.Now().UTC().Add(time.Duration(interval) * time.Second)
		for _, entry := range batch.Entries {
			next = earliest(next, entry.Next)
		}
		next = earliest(next, scriptRetry)
	}
	snapshot := Snapshot{
		ID:     def.ID,
		Module: model.ModuleSnapshot{Format: format, Request: def.RequestHash(), Name: meta.Name, Desc: meta.Desc},
		Lock:   model.SourceLock{Root: batch.Entries["root"].Hash, Resources: locks},
	}
	return Result{Snapshot: snapshot, Metadata: meta, Entries: batch.Entries, Next: next, ScriptErrors: scriptErrors}, nil
}

func earliest(a, b time.Time) time.Time {
	if !b.IsZero() && (a.IsZero() || b.Before(a)) {
		return b
	}
	return a
}

// ReadFile reads a module or snapshot from a regular file, with a size limit.
func ReadFile(path string, maxBytes int) ([]byte, error) {
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
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(maxBytes) {
		return nil, &subscription.Error{Code: "module_file_invalid"}
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil || len(data) == 0 || len(data) > maxBytes {
		return nil, &subscription.Error{Code: "module_file_invalid"}
	}
	return data, nil
}
