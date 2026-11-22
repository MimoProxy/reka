// Package runtime holds Reka's running state: immutable snapshots published
// through an atomic pointer, and the retirement of resources a commit drops,
// using the lease protocol from internal/lease.
package runtime

import (
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/lease"
)

// Resource is something a snapshot hands out to connections: an outbound
// instance, a resolver, a listener. Close is called once, after the
// resource is retired and drained (or the drain timed out).
type Resource interface {
	Lease() *lease.Lease
	Close() error
}

// Snapshot is one immutable generation of running resources, keyed by
// stable ID. Never modify a published snapshot.
type Snapshot[R Resource] struct {
	Generation uint64
	Resources  map[string]R
	// Value is published together with Resources, for state that has no
	// lifecycle of its own (a compiled router, for example). It is shared,
	// never copied, so it must be immutable too.
	Value any
}

// Options tunes retirement.
type Options struct {
	// DrainTimeout bounds how long a retired resource waits for its leases
	// before it is closed anyway. Default 30s.
	DrainTimeout time.Duration
	// MaxRetiring rejects a commit that would leave more resources
	// draining than this. Zero means no limit.
	MaxRetiring int
	// AllowLargeReplacement applies MaxRetiring to the existing backlog
	// when a single replacement batch exceeds that limit.
	AllowLargeReplacement bool
	// OnClosed, if set, is called after each retired resource is closed.
	// forced is the number of leases still held when it was closed.
	OnClosed func(id string, generation uint64, forced int64, err error)
}

const defaultDrainTimeout = 30 * time.Second

var (
	// ErrTooManyRetiring is returned by Commit when MaxRetiring would be
	// exceeded. The active snapshot is unchanged.
	ErrTooManyRetiring = errors.New("runtime: too many resources still draining")
	// ErrStaleResource means pick returned a resource that is retired but
	// still present in the current snapshot, which only a caller bug can
	// cause.
	ErrStaleResource = errors.New("runtime: picked a retired resource from the current snapshot")
	errClosed        = errors.New("runtime: closed")
)

// Runtime publishes snapshots and retires the resources each commit drops.
//
// Protocol: a connection loads the current snapshot, picks a resource and
// takes a lease on it with one atomic add (lease.Lease.Acquire). Commit publishes the new
// snapshot first and only then retires dropped resources, so if Acquire
// fails the connection reloads and is guaranteed a newer snapshot. A
// resource is closed only after it is retired and drained, so no lease is
// ever taken on a closed resource.
type Runtime[R Resource] struct {
	opts     Options
	current  atomic.Pointer[Snapshot[R]]
	commitMu sync.Mutex
	closed   bool

	retiring atomic.Int64
	forced   atomic.Int64
	retries  atomic.Int64
	wg       sync.WaitGroup
}

// New publishes generation 1 with the given resources.
func New[R Resource](initial map[string]R, opts Options) *Runtime[R] {
	return NewValue(initial, nil, opts)
}

// NewValue is New with a snapshot Value.
func NewValue[R Resource](initial map[string]R, value any, opts Options) *Runtime[R] {
	if opts.DrainTimeout <= 0 {
		opts.DrainTimeout = defaultDrainTimeout
	}
	r := &Runtime[R]{opts: opts}
	r.current.Store(&Snapshot[R]{Generation: 1, Resources: maps.Clone(initial), Value: value})
	return r
}

// Current returns the active snapshot. Use Acquire to take a resource from
// it; reading a resource from a snapshot without a lease is only safe for
// inspection.
func (r *Runtime[R]) Current() *Snapshot[R] { return r.current.Load() }

// Acquire picks a resource from the current snapshot and leases it. pick
// returns false when there is nothing to lease (for example a reject rule);
// Acquire then returns ok=false and a nil error. release must be called
// exactly once when the connection ends.
func (r *Runtime[R]) Acquire(pick func(*Snapshot[R]) (R, bool)) (generation uint64, res R, release func(), ok bool, err error) {
	for {
		snap := r.current.Load()
		res, found := pick(snap)
		if !found {
			var zero R
			return snap.Generation, zero, nil, false, nil
		}
		l := res.Lease()
		if l.Acquire() {
			var once sync.Once
			return snap.Generation, res, func() { once.Do(l.Release) }, true, nil
		}
		// Retired after we loaded snap. Commit publishes before retiring,
		// so a newer snapshot must exist; otherwise pick is buggy.
		if r.current.Load() == snap {
			var zero R
			return snap.Generation, zero, nil, false, ErrStaleResource
		}
		r.retries.Add(1)
	}
}

// Commit publishes next as a new generation. Resources in the old snapshot
// that next no longer contains (compared by identity, not ID) are retired:
// they stop accepting leases, drain, and are closed in the background.
// Resources kept in next are shared with the old generation.
func (r *Runtime[R]) Commit(next map[string]R) (uint64, error) {
	return r.commit(next, nil, false)
}

// CommitValue is Commit that also replaces the snapshot Value.
func (r *Runtime[R]) CommitValue(next map[string]R, value any) (uint64, error) {
	return r.commit(next, value, true)
}

// RetiringLimit returns the limit for a batch that retires replacing resources.
func (r *Runtime[R]) RetiringLimit(replacing int) int {
	limit := r.opts.MaxRetiring
	if r.opts.AllowLargeReplacement && limit > 0 && replacing > limit {
		limit += replacing
	}
	return limit
}

// WouldRetire reports how many resources committing next would retire, and
// whether that stays within the retirement limit. It lets a caller refuse a commit
// before doing expensive preparation; Commit checks again.
func (r *Runtime[R]) WouldRetire(next map[string]R) (int, bool) {
	r.commitMu.Lock()
	defer r.commitMu.Unlock()
	n := len(r.dropped(r.current.Load(), next))
	max := r.RetiringLimit(n)
	return n, max <= 0 || int(r.retiring.Load())+n <= max
}

type dropped[R Resource] struct {
	id  string
	res R
}

func (r *Runtime[R]) dropped(old *Snapshot[R], next map[string]R) []dropped[R] {
	kept := make(map[any]struct{}, len(next))
	for _, res := range next {
		kept[any(res)] = struct{}{}
	}
	var drop []dropped[R]
	for id, res := range old.Resources {
		if _, ok := kept[any(res)]; !ok {
			drop = append(drop, dropped[R]{id, res})
		}
	}
	return drop
}

func (r *Runtime[R]) commit(next map[string]R, value any, setValue bool) (uint64, error) {
	r.commitMu.Lock()
	defer r.commitMu.Unlock()
	if r.closed {
		return 0, errClosed
	}
	old := r.current.Load()
	for id, res := range next {
		if res.Lease().Retired() {
			return old.Generation, fmt.Errorf("runtime: resource %q is already retired", id)
		}
	}
	drop := r.dropped(old, next)
	if !setValue {
		value = old.Value
	}
	if max := r.RetiringLimit(len(drop)); max > 0 && int(r.retiring.Load())+len(drop) > max {
		return old.Generation, ErrTooManyRetiring
	}

	snap := &Snapshot[R]{Generation: old.Generation + 1, Resources: maps.Clone(next), Value: value}
	r.current.Store(snap) // publish before retiring; see Acquire
	for _, d := range drop {
		r.retire(d.id, old.Generation, d.res)
	}
	return snap.Generation, nil
}

func (r *Runtime[R]) retire(id string, generation uint64, res R) {
	r.retiring.Add(1)
	r.wg.Add(1)
	l := res.Lease()
	l.Retire()
	go func() {
		defer r.wg.Done()
		timer := time.NewTimer(r.opts.DrainTimeout)
		defer timer.Stop()
		// After Drained no real lease can exist: Retire has stopped new ones.
		// Active may still briefly count an Acquire that is about to undo
		// itself, so it is read only when the drain timed out.
		var forced int64
		select {
		case <-l.Drained():
		case <-timer.C:
			forced = l.Active()
		}
		r.forced.Add(forced)
		err := res.Close()
		r.retiring.Add(-1)
		if r.opts.OnClosed != nil {
			r.opts.OnClosed(id, generation, forced, err)
		}
	}()
}

// Stats is a point-in-time view for tests and diagnostics.
type Stats struct {
	Generation uint64
	// Retiring counts resources retired but not yet closed: draining, or
	// still in use by connections. A number that keeps growing is a leak.
	Retiring int64
	// Forced counts leases still held when a drain timed out.
	Forced int64
	// Retries counts Acquire calls that raced a commit and reloaded.
	Retries int64
}

func (r *Runtime[R]) Stats() Stats {
	return Stats{
		Generation: r.current.Load().Generation,
		Retiring:   r.retiring.Load(),
		Forced:     r.forced.Load(),
		Retries:    r.retries.Load(),
	}
}

// Close retires every resource in the current snapshot and waits until all
// retired resources are closed. Later commits fail.
func (r *Runtime[R]) Close() {
	r.commitMu.Lock()
	if !r.closed {
		r.closed = true
		old := r.current.Load()
		r.current.Store(&Snapshot[R]{Generation: old.Generation + 1, Value: old.Value})
		for id, res := range old.Resources {
			r.retire(id, old.Generation, res)
		}
	}
	r.commitMu.Unlock()
	r.wg.Wait()
}
