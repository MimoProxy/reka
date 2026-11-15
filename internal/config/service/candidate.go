package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/secret"
)

// Candidate files let users edit the configuration in any editor. The
// service exports the active documents to Dir; when the user saves a
// change, it is committed through the same transaction as API changes.
// An invalid or conflicting file is left alone for the user to fix, with
// the reasons written next to it in <file>.errors, and the active revision
// keeps running. The watcher only triggers commits; it never drives the
// runtime itself.
type Candidate struct {
	Dir      string
	Interval time.Duration // poll interval, default 500ms
	svc      *Service

	files map[string]*candidateFile
}

type candidateFile struct {
	name     string // "profile" or "local"
	path     string
	exported string // hash of what was last written or committed
	base     uint64 // revision exported
	tried    string // hash of the last content that failed
}

const (
	profileFile = "profile.yaml"
	localFile   = "local.yaml"
	sourcesFile = "sources.yaml"
	overlayFile = "overlay.yaml"
)

// NewCandidate prepares candidate files in dir.
func (s *Service) NewCandidate(dir string) *Candidate {
	return &Candidate{Dir: dir, svc: s, files: map[string]*candidateFile{
		"profile": {name: "profile", path: filepath.Join(dir, profileFile)},
		"local":   {name: "local", path: filepath.Join(dir, localFile)},
		"sources": {name: "sources", path: filepath.Join(dir, sourcesFile)},
		"overlay": {name: "overlay", path: filepath.Join(dir, overlayFile)},
	}}
}

func (c *Candidate) export() error {
	rev, profile, local, sources, overlay := c.svc.LayerDocuments()
	for _, f := range c.files {
		content := profile
		switch f.name {
		case "local":
			content = local
		case "sources":
			content = sources
		case "overlay":
			content = overlay
		}
		cur, err := os.ReadFile(f.path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return err
		case f.exported != "" && store.Hash(cur) != f.exported:
			// The user has unsaved-to-kernel edits; do not overwrite them.
			continue
		case f.exported == "" && store.Hash(cur) != store.Hash(content):
			// Edited while the kernel was stopped: keep it and let poll
			// commit it against the active revision.
			f.base = rev
			f.exported = store.Hash(content)
			continue
		}
		if err := secret.WriteFileAtomic(f.path, content, 0o600); err != nil {
			return err
		}
		f.exported, f.base, f.tried = store.Hash(content), rev, ""
		os.Remove(f.path + ".errors")
	}
	return nil
}

// Run exports the documents and watches them until ctx ends.
func (c *Candidate) Run(ctx context.Context) error {
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	if err := c.export(); err != nil {
		return err
	}
	interval := c.Interval
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	sub := c.svc.Events().Subscribe([]string{EventCommitted}, "", 0, nil)
	defer sub.Close()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-sub.C:
			if ev.Type == EventCommitted {
				if err := c.export(); err != nil {
					c.svc.log.Error("export candidate files", "err", err)
				}
			}
		case <-tick.C:
			c.poll(ctx)
		}
	}
}

func (c *Candidate) poll(ctx context.Context) {
	for _, f := range c.files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		h := store.Hash(data)
		if h == f.exported || h == f.tried {
			continue
		}
		// Wait for the editor to finish writing: require two equal reads.
		time.Sleep(50 * time.Millisecond)
		again, err := os.ReadFile(f.path)
		if err != nil || store.Hash(again) != h {
			continue
		}
		text := string(data)
		req := CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: f.base}, Source: "file",
			Message: "edited " + filepath.Base(f.path), OperationID: fmt.Sprintf("file-%s-%d-%s", f.name, f.base, h[:24])}
		switch f.name {
		case "profile":
			req.Profile = &text
		case "local":
			req.Local = &text
		case "sources":
			req.Sources = &text
		case "overlay":
			req.Overlay = &text
		}
		res, err := c.svc.Commit(ctx, req)
		if err != nil {
			c.svc.log.Error("commit candidate file", "file", f.path, "err", err)
			f.tried = h
			continue
		}
		if res.State == store.OpCommitted {
			f.exported, f.tried = h, ""
			f.base = res.Revision
			os.Remove(f.path + ".errors")
			c.svc.log.Info("committed candidate file", "file", f.path, "revision", res.Revision)
			continue
		}
		f.tried = h
		report := candidateReport(f.path, res)
		_ = secret.WriteFileAtomic(f.path+".errors", []byte(report), 0o600)
		c.svc.log.Warn("candidate file not committed; the active revision keeps running", "file", f.path, "reason", describe(res))
		c.svc.events.Publish(EventCandidate, map[string]any{"file": f.path, "result": res})
	}
}

func candidateReport(path string, res Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s was not applied; the active configuration keeps running.\n\n", filepath.Base(path))
	if res.Error != nil {
		fmt.Fprintf(&b, "%s: %s\n", res.Error.Code, res.Error.Message)
	}
	for _, d := range res.Diagnostics {
		fmt.Fprintf(&b, "%s\n", d)
	}
	if res.Conflict != nil {
		fmt.Fprintf(&b, "\nThe configuration changed after this file was exported (now revision %d). Changes since then:\n", res.Conflict.Active)
		for _, ch := range res.Conflict.Changes {
			fmt.Fprintf(&b, "  %s: %v -> %v\n", ch.Path, ch.From, ch.To)
		}
		b.WriteString("Merge them into this file and save it, or delete the file to get a fresh export.\n")
	}
	return b.String()
}
