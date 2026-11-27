package generation

import (
	"cmp"
	"errors"
	"slices"
	"sync"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/script"
)

// scriptPressure counts script runs that memory limits stopped, per script,
// until a host takes the counts. Its size is bounded by the number of
// configured scripts.
type scriptPressure struct {
	mu     sync.Mutex
	counts map[string]*api.ScriptPressureCount
}

type scriptPressureKind int

const (
	scriptSkipped scriptPressureKind = iota
	scriptDiscarded
	scriptOversize
)

func (p *scriptPressure) add(id string, kind scriptPressureKind) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.counts == nil {
		p.counts = make(map[string]*api.ScriptPressureCount)
	}
	count := p.counts[id]
	if count == nil {
		count = &api.ScriptPressureCount{ID: id}
		p.counts[id] = count
	}
	switch kind {
	case scriptSkipped:
		count.Skipped++
	case scriptDiscarded:
		count.Discarded++
	case scriptOversize:
		count.Oversize++
	}
}

// noteError counts a background script run that ended with err.
func (p *scriptPressure) noteError(id string, err error) {
	switch {
	case errors.Is(err, script.ErrLowMemory):
		p.add(id, scriptSkipped)
	case errors.Is(err, script.ErrMemoryExceeded):
		p.add(id, scriptDiscarded)
	}
}

// noteMITM counts an HTTP script run. A low-memory run that reached the
// engine finished over budget; one that did not was skipped.
func (p *scriptPressure) noteMITM(run api.MITMScriptRun, executed bool) {
	switch run.Result {
	case "low-memory":
		if executed {
			p.add(run.ID, scriptDiscarded)
		} else {
			p.add(run.ID, scriptSkipped)
		}
	case "oversize":
		p.add(run.ID, scriptOversize)
	}
}

func (p *scriptPressure) take() map[string]*api.ScriptPressureCount {
	p.mu.Lock()
	defer p.mu.Unlock()
	counts := p.counts
	p.counts = nil
	return counts
}

// TakeScriptPressure returns the script runs memory limits stopped since the
// previous call, with at most limit scripts listed, and starts counting
// again.
func (e *Engine) TakeScriptPressure(limit int) api.ScriptPressure {
	counts := e.scriptPressure.take()
	var report api.ScriptPressure
	if len(counts) == 0 {
		return report
	}
	scripts := make([]api.ScriptPressureCount, 0, len(counts))
	for _, count := range counts {
		report.Skipped += count.Skipped
		report.Discarded += count.Discarded
		report.Oversize += count.Oversize
		scripts = append(scripts, *count)
	}
	slices.SortFunc(scripts, func(a, b api.ScriptPressureCount) int {
		return cmp.Or(cmp.Compare(b.Skipped+b.Discarded+b.Oversize, a.Skipped+a.Discarded+a.Oversize), cmp.Compare(a.ID, b.ID))
	})
	scripts = scripts[:min(max(limit, 0), len(scripts))]
	_, g := e.current()
	e.mu.Lock()
	for i := range scripts {
		if entry := e.backgroundScripts.entries[scripts[i].ID]; entry != nil {
			scripts[i].Name, scripts[i].Module = entry.info.Name, entry.info.Module
		} else if g != nil {
			scripts[i].Name, scripts[i].Module = g.scripts.describe(scripts[i].ID)
		}
	}
	e.mu.Unlock()
	if len(scripts) != 0 {
		report.Scripts = scripts
	}
	return report
}
