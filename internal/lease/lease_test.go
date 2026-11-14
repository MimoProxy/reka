package lease

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetireWithoutLeasesDrainsAtOnce(t *testing.T) {
	l := New()
	l.Retire()
	select {
	case <-l.Drained():
	default:
		t.Fatal("not drained")
	}
	if l.Acquire() {
		t.Fatal("acquired a retired lease")
	}
	l.Retire() // idempotent
}

func TestDrainWaitsForRelease(t *testing.T) {
	l := New()
	if !l.Acquire() || !l.Acquire() {
		t.Fatal("acquire failed")
	}
	l.Retire()
	l.Release()
	select {
	case <-l.Drained():
		t.Fatal("drained with a lease still held")
	default:
	}
	l.Release()
	select {
	case <-l.Drained():
	case <-time.After(time.Second):
		t.Fatal("not drained after last release")
	}
	if l.Active() != 0 || !l.Retired() {
		t.Fatalf("active=%d retired=%v", l.Active(), l.Retired())
	}
}

func TestReleaseUnderflowPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	New().Release()
}

// TestNoAcquireAfterRetire hammers Acquire/Release from many goroutines
// while Retire runs. Once Retire has returned, no Acquire may succeed, and
// Drained must close exactly when the last lease is released.
func TestNoAcquireAfterRetire(t *testing.T) {
	for round := range 200 {
		l := New()
		var (
			retired    atomic.Bool
			violations atomic.Int64
			wg         sync.WaitGroup
			stop       = make(chan struct{})
		)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					wasRetired := retired.Load()
					if l.Acquire() {
						if wasRetired {
							violations.Add(1)
						}
						select {
						case <-l.Drained():
							violations.Add(1) // drained while we hold a lease
						default:
						}
						l.Release()
					}
				}
			}()
		}
		time.Sleep(time.Duration(round%5) * 100 * time.Microsecond)
		l.Retire()
		retired.Store(true)
		time.Sleep(200 * time.Microsecond)
		close(stop)
		wg.Wait()
		select {
		case <-l.Drained():
		case <-time.After(time.Second):
			t.Fatalf("round %d: not drained, active=%d", round, l.Active())
		}
		if v := violations.Load(); v != 0 {
			t.Fatalf("round %d: %d violations", round, v)
		}
	}
}
