// Package scriptbridge runs scripts through a native host.
package scriptbridge

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/script"
)

// Host is implemented by the platform glue. Callbacks can run concurrently.
type Host interface {
	// Start hands a run to the host. Job is JSON and the bodies are raw
	// bytes. Nil means no body. The host must eventually call Done unless
	// Cancel is called first.
	Start(run uint64, job, requestBody, responseBody []byte)
	// Cancel asks the host to stop a run that has not called Done.
	Cancel(run uint64)
	// Reply delivers an asynchronous $httpClient result.
	Reply(run, call uint64, response, body []byte)
	// Purge releases rebuildable host state.
	Purge()
}

// Options controls preflight and post-run memory checks.
type Options struct {
	Footprint func() uint64 // Nil disables memory checks.
	// SkipAbove is the highest footprint a run may be expected to reach. A
	// run is skipped when the current footprint plus RunCost of its body
	// bytes exceeds it.
	SkipAbove uint64
	// RunCost estimates the memory a run adds for the given request and
	// response body bytes. Nil counts as zero.
	RunCost      func(bodyBytes int) uint64
	DiscardAbove uint64
	// Reclaim returns free memory to the system. Before a run is skipped or
	// its result discarded, the bridge reclaims once and checks again, so
	// memory the runtime holds but does not use cannot stop a run. Calls
	// are at least ReclaimInterval apart. Nil disables it.
	Reclaim         func()
	ReclaimInterval time.Duration
}

// Bridge implements script.Engine using a native host.
type Bridge struct {
	host Host
	opts Options

	mu   sync.Mutex
	next uint64
	runs map[uint64]*runState

	// Runs that find the footprint too high wait here while one reclaims.
	reclaimMu   sync.Mutex
	reclaimedAt time.Time
	now         func() time.Time
}

type runState struct {
	ctx    context.Context
	cancel context.CancelFunc
	job    *script.Job
	done   chan completion

	httpPending int
	callReply   pendingCallReply
}

type completion struct {
	data         []byte
	body         []byte
	responseBody []byte
}

var _ script.Engine = (*Bridge)(nil)

// New returns an engine backed by host.
func New(host Host, opts Options) *Bridge {
	return &Bridge{host: host, opts: opts, runs: make(map[uint64]*runState), now: time.Now}
}

// Run hands the script to the host and waits for completion or cancellation.
func (b *Bridge) Run(ctx context.Context, job *script.Job) (script.Done, error) {
	normalized := *job
	normalized.Limits = job.Limits.WithDefaults()
	job = &normalized
	metadata, requestBody, responseBody, err := marshalJob(job)
	if err != nil {
		return script.Done{}, err
	}
	if b.opts.Footprint != nil {
		var cost uint64
		if b.opts.RunCost != nil {
			cost = b.opts.RunCost(len(requestBody) + len(responseBody))
		}
		if b.overBudget(cost, b.opts.SkipAbove) {
			return script.Done{}, script.ErrLowMemory
		}
	}
	if ctx.Err() != nil {
		return script.Done{}, runContextError(ctx)
	}

	r := &runState{job: job, done: make(chan completion, 1)}
	r.ctx, r.cancel = context.WithCancel(ctx)
	defer r.cancel()

	b.mu.Lock()
	if b.next == ^uint64(0) {
		b.mu.Unlock()
		return script.Done{}, errors.New("script run IDs exhausted")
	}
	b.next++
	run := b.next
	b.runs[run] = r
	b.mu.Unlock()
	b.host.Start(run, metadata, requestBody, responseBody)

	var result completion
	select {
	case result = <-r.done:
	case <-ctx.Done():
		b.mu.Lock()
		_, active := b.runs[run]
		delete(b.runs, run)
		r.callReply = pendingCallReply{}
		b.mu.Unlock()
		if active {
			r.cancel()
			b.host.Cancel(run)
			return script.Done{}, runContextError(ctx)
		}
		// Done had already claimed the result when the deadline fired.
		result = <-r.done
	}
	if b.opts.Footprint != nil && b.overBudget(0, b.opts.DiscardAbove) {
		b.host.Purge()
		return script.Done{}, script.ErrMemoryExceeded
	}
	return result.decode()
}

// overBudget reports whether the footprint plus extra exceeds limit, even
// after reclaiming free memory.
func (b *Bridge) overBudget(extra, limit uint64) bool {
	if b.opts.Footprint()+extra <= limit {
		return false
	}
	if b.opts.Reclaim == nil {
		return true
	}
	b.reclaim()
	return b.opts.Footprint()+extra > limit
}

// reclaim runs Reclaim unless it ran within ReclaimInterval. Callers check
// the footprint again either way, since a recent reclaim by another run
// may already have freed the memory.
func (b *Bridge) reclaim() {
	b.reclaimMu.Lock()
	defer b.reclaimMu.Unlock()
	if !b.reclaimedAt.IsZero() && b.now().Sub(b.reclaimedAt) < b.opts.ReclaimInterval {
		return
	}
	b.opts.Reclaim()
	b.reclaimedAt = b.now()
}

func runContextError(ctx context.Context) error {
	if ctx.Err() == context.DeadlineExceeded {
		return script.ErrTimeout
	}
	return ctx.Err()
}

// Purge releases rebuildable host state.
func (b *Bridge) Purge() { b.host.Purge() }

// Done accepts the first completion for a live run. The caller can release
// the buffers as soon as Done returns.
func (b *Bridge) Done(run uint64, done, body, responseBody []byte) bool {
	b.mu.Lock()
	r := b.liveRunLocked(run)
	if r != nil {
		delete(b.runs, run)
		r.callReply = pendingCallReply{}
	}
	b.mu.Unlock()
	if r == nil {
		return false
	}
	r.cancel()
	r.done <- completion{bytes.Clone(done), bytes.Clone(body), bytes.Clone(responseBody)}
	return true
}

// Source returns a copy of the source for a live run.
func (b *Bridge) Source(run uint64) ([]byte, bool) {
	source, ok := b.liveSource(run)
	if !ok {
		return nil, false
	}
	return []byte(source), true
}

// WriteSource copies the live source directly into output. A short buffer
// returns the negative required capacity. An unavailable source returns zero.
func (b *Bridge) WriteSource(run uint64, output []byte) int32 {
	source, ok := b.liveSource(run)
	if !ok || len(source) > math.MaxInt32 {
		return 0
	}
	if len(source) > len(output) {
		return -int32(len(source))
	}
	return int32(copy(output, source))
}

func (b *Bridge) liveSource(run uint64) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.liveRunLocked(run)
	if r == nil {
		return "", false
	}
	return r.job.Script.Source, true
}

func (b *Bridge) liveRunLocked(run uint64) *runState {
	r := b.runs[run]
	if r == nil || r.ctx.Err() != nil {
		return nil
	}
	return r
}
