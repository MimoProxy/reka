package dns

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"
)

func TestFakePoolBatchesWritesAndFlushesOnClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewFakePool(8)
		defer pool.Close()
		path := filepath.Join(t.TempDir(), "fake-ip.json")
		if err := pool.UseFile(path); err != nil {
			t.Fatal(err)
		}
		prefix := netip.MustParsePrefix("198.18.0.0/29")
		first := allocateFakeIP(t, pool, 1, "first.test", prefix)
		time.Sleep(fakeIPSaveInterval / 2)
		second := allocateFakeIP(t, pool, 1, "second.test", prefix)
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("state written before the batch interval: %v", err)
		}
		time.Sleep(fakeIPSaveInterval / 2)
		synctest.Wait()
		initial, err := readFakeIPState(path)
		if err != nil || len(initial.Mappings) != 2 {
			t.Fatalf("first batch saved %d mappings: %v", len(initial.Mappings), err)
		}

		third := allocateFakeIP(t, pool, 1, "third.test", prefix)
		fourth := allocateFakeIP(t, pool, 1, "fourth.test", prefix)
		time.Sleep(fakeIPSaveInterval / 2)
		pending, err := readFakeIPState(path)
		if err != nil || len(pending.Mappings) != 2 {
			t.Fatalf("second batch written early: %d mappings, %v", len(pending.Mappings), err)
		}
		pool.Close()
		flushed, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(fakeIPSaveInterval)
		synctest.Wait()
		current, err := os.Stat(path)
		if err != nil || !os.SameFile(flushed, current) {
			t.Fatalf("a timer wrote state after close: %v", err)
		}

		restored := NewFakePool(8)
		defer restored.Close()
		if err := restored.UseFile(path); err != nil {
			t.Fatal(err)
		}
		if got := restored.Size(); got != 4 {
			t.Fatalf("restored %d mappings, want 4", got)
		}
		checkFakeMapping(t, restored, first, "first.test")
		checkFakeMapping(t, restored, second, "second.test")
		checkFakeMapping(t, restored, third, "third.test")
		checkFakeMapping(t, restored, fourth, "fourth.test")
	})
}

func TestFakePoolRestoresCursorAndRecency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-ip.json")
	pool := NewFakePool(2)
	defer pool.Close()
	if err := pool.UseFile(path); err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	allocateFakeIP(t, pool, 1, "evicted.test", prefix)
	used := allocateFakeIP(t, pool, 1, "used.test", prefix)
	idle := allocateFakeIP(t, pool, 1, "idle.test", prefix)
	checkFakeMapping(t, pool, used, "used.test")
	pool.Close()

	restored := NewFakePool(2)
	defer restored.Close()
	if err := restored.UseFile(path); err != nil {
		t.Fatal(err)
	}
	if got := allocateFakeIP(t, restored, 1, "new.test", prefix); got != idle.Next() {
		t.Fatalf("allocation after restore = %s, want %s", got, idle.Next())
	}
	checkFakeMapping(t, restored, idle, "")
	checkFakeMapping(t, restored, used, "used.test")
}

func TestFakePoolRestoresExpiredVersionOneMappings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-ip.json")
	const legacy = `{"version":1,"mappings":[
		{"ip":"198.18.0.1","domain":"first.test","generation":17,"expires":"2000-01-01T00:00:00Z"},
		{"ip":"198.18.0.2","domain":"second.test","generation":18,"expires":"2000-01-01T00:00:00Z"}
	],"ranges":["198.18.0.0/29"]}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	bounded := NewFakePool(1)
	if err := bounded.UseFile(path); err == nil || bounded.Size() != 0 {
		t.Fatalf("oversized state loaded %d mappings: %v", bounded.Size(), err)
	}

	pool := NewFakePool(2)
	defer pool.Close()
	if err := pool.UseFile(path); err != nil {
		t.Fatal(err)
	}
	first := netip.MustParseAddr("198.18.0.1")
	checkFakeMapping(t, pool, first, "first.test")
	checkFakeMapping(t, pool, netip.MustParseAddr("198.18.0.2"), "second.test")
	if !pool.Contains(netip.MustParseAddr("198.18.0.3")) {
		t.Fatal("legacy range history was lost")
	}
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	if got := allocateFakeIP(t, pool, 17, "first.test", prefix); got != first {
		t.Fatalf("saved generation allocated %s, want %s", got, first)
	}
}

func TestFakePoolWriteFailureKeepsMappings(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewFakePool(2)
		defer pool.Close()
		path := filepath.Join(t.TempDir(), "fake-ip.json")
		if err := pool.UseFile(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		prefix := netip.MustParsePrefix("198.18.0.0/29")
		first := allocateFakeIP(t, pool, 1, "first.test", prefix)
		time.Sleep(fakeIPSaveInterval)
		synctest.Wait()
		checkFakeMapping(t, pool, first, "first.test")
		allocateFakeIP(t, pool, 1, "second.test", prefix)
		time.Sleep(fakeIPSaveInterval)
		synctest.Wait()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		pool.Close()
		saved, err := readFakeIPState(path)
		if err != nil || len(saved.Mappings) != 2 {
			t.Fatalf("close saved %d mappings after a write failure: %v", len(saved.Mappings), err)
		}
	})
}
