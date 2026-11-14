// Package lease counts the connections using a resource and lets the
// resource be retired without cutting them. It is a leaf package shared by
// internal/runtime and internal/backend/sagernet.
package lease

import (
	"sync"
	"sync/atomic"
)

// retiredBit marks a Lease as retired. The low bits count active leases.
// Keeping both in one word means a single atomic add both takes a lease and
// observes whether retirement was already decided, so no lease is ever
// kept on a resource retired before it.
const retiredBit = int64(1) << 62

// Lease counts the connections using one resource and tracks whether the
// resource has been retired. The zero value is not usable; use NewLease.
type Lease struct {
	state   atomic.Int64
	drained chan struct{}
	once    sync.Once
}

func New() *Lease {
	return &Lease{drained: make(chan struct{})}
}

// Acquire takes one lease. It fails once Retire has been called; the caller
// then loads the current snapshot again, which no longer contains this
// resource.
//
// It increments first and checks second, so it never loops: if the lease
// turned out to be retired, the increment is undone. Retire may observe
// that transient count; the undo then reports the drain instead.
func (l *Lease) Acquire() bool {
	if l.state.Add(1)&retiredBit == 0 {
		return true
	}
	l.Release()
	return false
}

// Release gives back one lease taken by Acquire.
func (l *Lease) Release() {
	s := l.state.Add(-1)
	if s&^retiredBit < 0 {
		panic("lease: lease released more times than acquired")
	}
	if s == retiredBit {
		l.markDrained()
	}
}

// Retire stops new leases. Drained is closed once the existing ones are
// released (immediately if there are none). Retire is idempotent.
func (l *Lease) Retire() {
	if old := l.state.Or(retiredBit); old&^retiredBit == 0 {
		l.markDrained()
	}
}

func (l *Lease) markDrained() {
	l.once.Do(func() { close(l.drained) })
}

// Drained is closed when the lease is retired and no lease is held.
func (l *Lease) Drained() <-chan struct{} { return l.drained }

// Active reports how many leases are held. On a retired lease it may
// briefly include an Acquire that is failing and about to undo itself;
// use Drained, not Active() == 0, to learn that all leases are gone.
func (l *Lease) Active() int64 { return l.state.Load() &^ retiredBit }

// Retired reports whether Retire has been called.
func (l *Lease) Retired() bool { return l.state.Load()&retiredBit != 0 }
