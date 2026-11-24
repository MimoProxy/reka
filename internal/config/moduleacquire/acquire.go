// Package moduleacquire downloads Surge module snapshots without scheduling or
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

// MaxBundleSize bounds the module text and its Map Local resources together.
const MaxBundleSize = 32 << 20

// Snapshot is the pin written to a sources document.
type Snapshot struct {
	ID     string               `json:"id"`
	Module model.ModuleSnapshot `json:"module"`
	Lock   model.SourceLock     `json:"lock"`
}

type Options struct {
	Client          *http.Client
	Blobs           *resource.Store
	ResolveURL      func(string) (string, error)
	Previous        model.Source
	PreviousEntries map[string]subscription.Entry
	Force           bool
}

type Result struct {
	Snapshot Snapshot
	Metadata module.Metadata
	Entries  map[string]subscription.Entry
	Next     time.Time
}

// Matches reports whether a source pins the declared location.
func Matches(def model.Module, src model.Source) bool {
	return src.Module != nil && src.Module.Format == model.ModuleFormatSurge && src.Lock != nil &&
		src.Module.Request == def.RequestHash() && resource.ValidHash(src.Lock.Root)
}

// Acquire fetches the root and all referenced Map Local resources using the
// previous lock to validate cached entries before issuing conditional requests.
func Acquire(ctx context.Context, def model.Module, opts Options) (Result, error) {
	if model.ValidModule(&def) != nil {
		return Result{}, &subscription.Error{Code: "module_invalid"}
	}
	src := opts.Previous
	if src.ID != "" && src.Module == nil {
		return Result{}, &subscription.Error{Code: "module_source_conflict"}
	}
	validated := make(map[string]subscription.Entry)
	if Matches(def, src) {
		if entry := opts.PreviousEntries["root"]; entry.Hash == src.Lock.Root {
			validated["root"] = entry
		}
		for _, lock := range src.Lock.Resources {
			if entry := opts.PreviousEntries[lock.ID]; entry.Hash == lock.Hash {
				validated[lock.ID] = entry
			}
		}
	}
	interval := def.Interval
	if interval == 0 {
		interval = model.DefaultResourceInterval
	}
	fetcher := subscription.Fetcher{Client: opts.Client, Blobs: opts.Blobs, MaxBytes: model.MaxDocumentSize, MaxBundleBytes: MaxBundleSize}
	batch := fetcher.Batch(validated, opts.Force)
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
			body, err = batch.Fetch(ctx, "root", "module", "", url, nil, interval)
		}
	}
	if err != nil {
		return Result{}, err
	}
	meta, urls := module.Inspect(body, def.Arguments)
	if len(urls) > model.MaxModuleResources {
		return Result{}, &subscription.Error{Code: "too_many_module_resources"}
	}
	fetcher.MaxBytes = httprewrite.MaxMapLocalSize
	locks := make([]model.ResourceLock, 0, len(urls))
	for _, url := range urls {
		request := resource.Hash([]byte(url))
		id := request[:24]
		if _, err := batch.Fetch(ctx, id, "map-local", "", url, nil, interval); err != nil {
			return Result{}, err
		}
		locks = append(locks, model.ResourceLock{ID: id, Kind: "map-local", Request: request, Hash: batch.Entries[id].Hash})
	}
	var next time.Time
	if def.URL != "" {
		next = time.Now().UTC().Add(time.Duration(interval) * time.Second)
		for _, entry := range batch.Entries {
			if !entry.Next.IsZero() && entry.Next.Before(next) {
				next = entry.Next
			}
		}
	}
	snapshot := Snapshot{
		ID:     def.ID,
		Module: model.ModuleSnapshot{Format: model.ModuleFormatSurge, Request: def.RequestHash(), Name: meta.Name, Desc: meta.Desc},
		Lock:   model.SourceLock{Root: batch.Entries["root"].Hash, Resources: locks},
	}
	return Result{Snapshot: snapshot, Metadata: meta, Entries: batch.Entries, Next: next}, nil
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
