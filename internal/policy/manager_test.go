package policy

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthSelectionBoundedAndManual(t *testing.T) {
	var active, maxActive atomic.Int32
	probe := func(ctx context.Context, id, url string) error {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := maxActive.Load()
			if old >= n || maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		delay := 20 * time.Millisecond
		if id == "fast" {
			delay = time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if id == "dead" {
			return errors.New("down")
		}
		return nil
	}
	groups := []Group{{ID: "auto", Type: "url-test", Members: []string{"slow", "fast", "dead"}}, {ID: "fallback", Type: "fallback", Members: []string{"dead", "slow", "fast"}}, {ID: "balance", Type: "load-balance", Strategy: "round-robin", Members: []string{"fast", "slow"}}, {ID: "manual", Type: "url-test", Selected: "slow", Members: []string{"slow", "fast"}}}
	m := New(groups, probe)
	m.Start()
	defer m.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		complete := true
		for _, s := range m.Statuses() {
			for _, r := range s.Results {
				complete = complete && !r.Checked.IsZero()
			}
		}
		if complete && m.Choose("auto", "x", "") == "fast" && m.Choose("fallback", "x", "") == "slow" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if m.Choose("auto", "x", "") != "fast" || m.Choose("fallback", "x", "") != "slow" || m.Choose("manual", "x", "") != "slow" {
		t.Fatal(m.Statuses())
	}
	a, b := m.Choose("balance", "x", ""), m.Choose("balance", "x", "")
	if a == b {
		t.Fatal("round robin not rotating")
	}
	if maxActive.Load() > 4 {
		t.Fatal(maxActive.Load())
	}
	if m.Choose("parent", "x", "hand-picked") != "hand-picked" {
		t.Fatal("manual parent overwritten")
	}
}

func TestURLTestPinKeepsHealthOnPinAndUnpin(t *testing.T) {
	group := Group{ID: "auto", Type: "url-test", Members: []string{"slow", "fast"}}
	m := New([]Group{group}, nil)
	checked := time.Now()
	fast := Result{Member: "fast", Alive: true, Delay: 10, Checked: checked}
	state := m.states[group.ID]
	state.results["fast"] = fast
	state.selected = "fast"
	state.last = checked
	state.used = true

	for _, tc := range []struct {
		pin  string
		want string
	}{
		{pin: "slow", want: "slow"},
		{pin: "", want: "fast"},
	} {
		group.Selected = tc.pin
		updated := New([]Group{group}, nil)
		updated.Inherit(m)
		status := updated.Statuses()[0]
		if status.Results[1] != fast || updated.states[group.ID].last != checked || !updated.states[group.ID].used {
			t.Fatalf("health state was lost with pin %q: %+v", tc.pin, status)
		}
		if status.Selected != tc.want || updated.Peek(group.ID, "host.test", "") != tc.want || updated.Choose(group.ID, "host.test", "") != tc.want {
			t.Fatalf("selection with pin %q = %+v, want %q", tc.pin, status, tc.want)
		}
		m = updated
	}
}

func TestLazyHealthCheckCancellation(t *testing.T) {
	var calls atomic.Int32
	m := New([]Group{{ID: "lazy", Type: "url-test", Lazy: true, Members: []string{"one"}}}, func(ctx context.Context, _, _ string) error { calls.Add(1); <-ctx.Done(); return ctx.Err() })
	m.Start()
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("lazy group probed while unused")
	}
	m.Choose("lazy", "x", "")
	m.mu.Lock()
	s := m.states["lazy"]
	s.last = time.Time{}
	m.mu.Unlock()
	time.Sleep(1100 * time.Millisecond)
	start := time.Now()
	m.Close()
	if time.Since(start) > time.Second || calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}

func TestConsistentHashingOnlyMovesToAddedMember(t *testing.T) {
	create := func(members []string) *Manager {
		m := New([]Group{{ID: "balance", Type: "load-balance", Members: members}}, nil)
		s := m.states["balance"]
		s.last = time.Now()
		for _, member := range members {
			s.results[member] = Result{Member: member, Alive: true, Checked: time.Now()}
		}
		return m
	}
	before, after := create([]string{"a", "b"}), create([]string{"a", "b", "c"})
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("host-%d.test", i)
		a, b := before.Choose("balance", key, ""), after.Choose("balance", key, "")
		if a != b && b != "c" {
			t.Fatal("hashing remapped existing members", key, a, b)
		}
	}
}
