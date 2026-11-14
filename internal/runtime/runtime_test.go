package runtime

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/lease"
)

// fakeResource records misuse: any use after Close, and double Close.
type fakeResource struct {
	name       string
	lease      *lease.Lease
	closed     atomic.Bool
	closes     atomic.Int64
	violations *atomic.Int64
}

func newFake(name string, violations *atomic.Int64) *fakeResource {
	return &fakeResource{name: name, lease: lease.New(), violations: violations}
}

func (f *fakeResource) Lease() *lease.Lease { return f.lease }

func (f *fakeResource) Close() error {
	if f.closes.Add(1) > 1 {
		f.violations.Add(1)
	}
	f.closed.Store(true)
	return nil
}

func (f *fakeResource) use() {
	if f.closed.Load() {
		f.violations.Add(1)
	}
}

func pickKey(key string) func(*Snapshot[*fakeResource]) (*fakeResource, bool) {
	return func(s *Snapshot[*fakeResource]) (*fakeResource, bool) {
		r, ok := s.Resources[key]
		return r, ok
	}
}

// TestConcurrentCommitAndAcquire is the main protocol check: many connections
// lease resources while commits keep replacing them. No resource may be
// used after it is closed, closed twice, or force-closed, and every retired
// resource must eventually close.
func TestConcurrentCommitAndAcquire(t *testing.T) {
	const keys = 4
	var violations atomic.Int64
	var all sync.Map // every resource ever published
	var serial atomic.Int64
	mk := func(key string) *fakeResource {
		f := newFake(fmt.Sprintf("%s#%d", key, serial.Add(1)), &violations)
		all.Store(f, struct{}{})
		return f
	}
	initial := map[string]*fakeResource{}
	for i := range keys {
		k := fmt.Sprint("k", i)
		initial[k] = mk(k)
	}
	rt := New(initial, Options{DrainTimeout: 10 * time.Second})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var acquired, rejected atomic.Int64
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				key := fmt.Sprint("k", rand.IntN(keys+1)) // k4 never exists
				_, res, release, ok, err := rt.Acquire(pickKey(key))
				if err != nil {
					t.Error(err)
					return
				}
				if !ok {
					rejected.Add(1)
					continue
				}
				acquired.Add(1)
				res.use()
				if rand.IntN(4) == 0 {
					time.Sleep(time.Duration(rand.IntN(200)) * time.Microsecond)
				}
				res.use()
				release()
			}
		}()
	}

	var commits int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cur := rt.Current()
		next := make(map[string]*fakeResource, keys)
		for k, r := range cur.Resources {
			if rand.IntN(2) == 0 {
				next[k] = mk(k) // replace
			} else {
				next[k] = r // keep
			}
		}
		if _, err := rt.Commit(next); err != nil {
			t.Fatal(err)
		}
		commits++
		time.Sleep(time.Duration(rand.IntN(100)) * time.Microsecond)
	}
	close(stop)
	wg.Wait()
	rt.Close()

	st := rt.Stats()
	t.Logf("commits=%d generation=%d acquired=%d rejected=%d acquire-retries=%d",
		commits, st.Generation, acquired.Load(), rejected.Load(), st.Retries)
	if v := violations.Load(); v != 0 {
		t.Fatalf("%d use-after-close or double-close violations", v)
	}
	if st.Forced != 0 {
		t.Fatalf("%d leases force-closed", st.Forced)
	}
	if st.Retiring != 0 {
		t.Fatalf("%d resources still retiring after Close", st.Retiring)
	}
	unclosed := 0
	all.Range(func(k, _ any) bool {
		f := k.(*fakeResource)
		if f.closes.Load() != 1 {
			unclosed++
		}
		return true
	})
	if unclosed != 0 {
		t.Fatalf("%d resources not closed exactly once", unclosed)
	}
	if st.Retries == 0 {
		t.Log("note: no Acquire raced a commit this run; the retry path was not exercised")
	}
}

func TestKeptResourceIsShared(t *testing.T) {
	var v atomic.Int64
	a, b := newFake("a", &v), newFake("b", &v)
	rt := New(map[string]*fakeResource{"a": a, "b": b}, Options{})
	b2 := newFake("b2", &v)
	if _, err := rt.Commit(map[string]*fakeResource{"a": a, "b": b2}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return b.closed.Load() })
	if a.closed.Load() || a.lease.Retired() {
		t.Fatal("kept resource was retired")
	}
	rt.Close()
}

func TestDrainTimeoutForcesClose(t *testing.T) {
	var v atomic.Int64
	a := newFake("a", &v)
	var closedID string
	var closedForced int64
	done := make(chan struct{})
	rt := New(map[string]*fakeResource{"a": a}, Options{
		DrainTimeout: 50 * time.Millisecond,
		OnClosed: func(id string, _ uint64, forced int64, _ error) {
			closedID, closedForced = id, forced
			close(done)
		},
	})
	_, _, release, ok, _ := rt.Acquire(pickKey("a"))
	if !ok {
		t.Fatal("acquire failed")
	}
	defer release()
	if _, err := rt.Commit(nil); err != nil {
		t.Fatal(err)
	}
	if a.closed.Load() {
		t.Fatal("closed before drain timeout")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("not closed after drain timeout")
	}
	if closedID != "a" || closedForced != 1 || rt.Stats().Forced != 1 {
		t.Fatalf("closed %q forced=%d stats=%+v", closedID, closedForced, rt.Stats())
	}
}

func TestMaxRetiringRejectsCommit(t *testing.T) {
	var v atomic.Int64
	rt := New(map[string]*fakeResource{"a": newFake("a", &v)}, Options{MaxRetiring: 1, DrainTimeout: time.Minute})
	defer rt.Close()
	hold := func() func() {
		_, _, release, ok, _ := rt.Acquire(pickKey("a"))
		if !ok {
			t.Fatal("acquire failed")
		}
		return release
	}
	r1 := hold()
	if _, err := rt.Commit(map[string]*fakeResource{"a": newFake("a2", &v)}); err != nil {
		t.Fatal(err)
	}
	r2 := hold()
	gen := rt.Current().Generation
	_, err := rt.Commit(map[string]*fakeResource{"a": newFake("a3", &v)})
	if !errors.Is(err, ErrTooManyRetiring) {
		t.Fatalf("err = %v, want ErrTooManyRetiring", err)
	}
	if rt.Current().Generation != gen {
		t.Fatal("rejected commit changed the snapshot")
	}
	r1()
	waitFor(t, func() bool { return rt.Stats().Retiring == 0 })
	if _, err := rt.Commit(map[string]*fakeResource{"a": newFake("a3", &v)}); err != nil {
		t.Fatalf("commit after drain: %v", err)
	}
	r2()
}

func TestCommitRejectsRetiredResource(t *testing.T) {
	var v atomic.Int64
	a := newFake("a", &v)
	rt := New(map[string]*fakeResource{"a": a}, Options{})
	defer rt.Close()
	if _, err := rt.Commit(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Commit(map[string]*fakeResource{"a": a}); err == nil {
		t.Fatal("re-published a retired resource")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(time.Millisecond)
	}
}

// Benchmarks compare the atomic lease with the RWMutex protocol the
// architecture first proposed (lock, load snapshot, count, unlock).

func BenchmarkAcquireAtomic(b *testing.B) {
	var v atomic.Int64
	rt := New(map[string]*fakeResource{"a": newFake("a", &v)}, Options{})
	pick := pickKey("a")
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, release, _, _ := rt.Acquire(pick)
			release()
		}
	})
}

type rwRuntime struct {
	mu      sync.RWMutex
	current atomic.Pointer[Snapshot[*fakeResource]]
	active  sync.Map // *fakeResource -> *atomic.Int64
}

func (r *rwRuntime) acquire(key string) func() {
	r.mu.RLock()
	res := r.current.Load().Resources[key]
	c, _ := r.active.LoadOrStore(res, new(atomic.Int64))
	c.(*atomic.Int64).Add(1)
	r.mu.RUnlock()
	return func() { c.(*atomic.Int64).Add(-1) }
}

func BenchmarkAcquireRWMutex(b *testing.B) {
	var v atomic.Int64
	r := &rwRuntime{}
	r.current.Store(&Snapshot[*fakeResource]{Generation: 1, Resources: map[string]*fakeResource{"a": newFake("a", &v)}})
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.acquire("a")()
		}
	})
}
