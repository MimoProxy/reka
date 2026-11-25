package gojaengine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MimoProxy/reka/internal/script"
	"github.com/dop251/goja"
)

func TestProgramCache(t *testing.T) {
	const first = `$done({body: "a"})`
	const second = `$done({body: "b"})`
	const third = `$done({body: "c"})`
	newHost := func(t *testing.T, engine *Engine, cacheBytes int64, concurrency int) (*script.Host, *atomic.Int32) {
		t.Helper()
		var calls atomic.Int32
		engine.cache.compile = func(name, source string) (*goja.Program, error) {
			calls.Add(1)
			return compile(name, source)
		}
		host := script.NewHost(engine, script.Limits{CacheBytes: cacheBytes, Concurrency: concurrency}, script.Environment{})
		t.Cleanup(host.Close)
		return host, &calls
	}
	run := func(t *testing.T, h *script.Host, key, source, want string) {
		t.Helper()
		spec := script.Script{Key: key, Name: "cache", Source: source, Kind: script.KindHTTPRequest}
		got, err := h.Run(context.Background(), &spec, &script.Input{}, script.Services{})
		if err != nil {
			t.Error(err)
			return
		}
		if string(got.Body) != want {
			t.Errorf("body = %q, want %q", got.Body, want)
		}
	}
	t.Run("source reuse and purge", func(t *testing.T) {
		host, calls := newHost(t, New(), 0, 0)
		run(t, host, "", first, "a")
		run(t, host, "", first, "a")
		if got := calls.Load(); got != 1 {
			t.Fatalf("compilations = %d, want 1", got)
		}
		host.Purge()
		run(t, host, "", first, "a")
		if got := calls.Load(); got != 2 {
			t.Fatalf("compilations after purge = %d, want 2", got)
		}
	})
	t.Run("least recently used", func(t *testing.T) {
		host, calls := newHost(t, New(), 2*int64(len(first))*10, 0)
		run(t, host, "", first, "a")
		run(t, host, "", second, "b")
		run(t, host, "", first, "a")
		run(t, host, "", third, "c")
		run(t, host, "", first, "a")
		if got := calls.Load(); got != 3 {
			t.Fatalf("compilations after hitting recently used entry = %d, want 3", got)
		}
		run(t, host, "", second, "b")
		if got := calls.Load(); got != 4 {
			t.Fatalf("compilations after hitting evicted entry = %d, want 4", got)
		}
	})
	t.Run("over budget", func(t *testing.T) {
		host, calls := newHost(t, New(), int64(len(first))*10-1, 0)
		run(t, host, "", first, "a")
		run(t, host, "", first, "a")
		if got := calls.Load(); got != 2 {
			t.Fatalf("compilations = %d, want 2", got)
		}
	})
	t.Run("explicit key with new source", func(t *testing.T) {
		host, calls := newHost(t, New(), 0, 0)
		run(t, host, "script.js", first, "a")
		run(t, host, "script.js", second, "b")
		run(t, host, "script.js", second, "b")
		if got := calls.Load(); got != 2 {
			t.Fatalf("compilations = %d, want 2", got)
		}
	})
	t.Run("empty source", func(t *testing.T) {
		host, calls := newHost(t, New(), 0, 0)
		spec := script.Script{Kind: script.KindHTTPRequest}
		for range 2 {
			_, err := host.Run(context.Background(), &spec, &script.Input{}, script.Services{})
			if !errors.Is(err, script.ErrNoDone) {
				t.Fatalf("empty script error = %v, want ErrNoDone", err)
			}
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("compilations = %d, want 1", got)
		}
	})
	t.Run("concurrent runs share compilation", func(t *testing.T) {
		const sessions = 16
		host, calls := newHost(t, New(), 0, sessions)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range sessions {
			wg.Go(func() {
				<-start
				run(t, host, "", first, "a")
			})
		}
		close(start)
		wg.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("compilations = %d, want 1", got)
		}
	})
}

func TestCheck(t *testing.T) {
	if err := Check("valid.js", `throw new Error("never executed")`); err != nil {
		t.Fatal(err)
	}
	if err := Check("invalid.js", `let = ;`); err == nil {
		t.Fatal("expected a syntax error")
	}
}
