package dns

import (
	"net/netip"
	"testing"
)

func allocateFakeIP(t *testing.T, pool *FakePool, generation uint64, domain string, prefix netip.Prefix) netip.Addr {
	t.Helper()
	ip, err := pool.Allocate(generation, domain, prefix)
	if err != nil {
		t.Fatalf("allocate %q: %v", domain, err)
	}
	return ip
}

func checkFakeMapping(t *testing.T, pool *FakePool, ip netip.Addr, want string) {
	t.Helper()
	domain, release, ok := pool.Acquire(ip)
	if ok {
		release()
	}
	if domain != want || ok != (want != "") {
		t.Fatalf("acquire %s = %q, %t, want %q", ip, domain, ok, want)
	}
}

func TestFakePoolKeepsGenerationsAndRanges(t *testing.T) {
	pool := NewFakePool(8)
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	ip := allocateFakeIP(t, pool, 1, "mapping.test", prefix)
	if got := allocateFakeIP(t, pool, 1, "mapping.test", prefix); got != ip {
		t.Fatalf("same generation allocated %s, want %s", got, ip)
	}
	if got := allocateFakeIP(t, pool, 2, "mapping.test", prefix); got == ip {
		t.Fatalf("new generation reused the mapping at %s", ip)
	}
	ipv6 := netip.MustParsePrefix("fc00::/126")
	if got := allocateFakeIP(t, pool, 1, "mapping.test", ipv6); !ipv6.Contains(got) {
		t.Fatalf("IPv6 range allocated %s", got)
	}
	if got := allocateFakeIP(t, pool, 1, "mapping.test", prefix); got != ip {
		t.Fatalf("different range replaced the original mapping at %s", ip)
	}
	checkFakeMapping(t, pool, ip, "mapping.test")
}

func TestFakePoolEvictsLeastRecentlyUsedUnreferencedMapping(t *testing.T) {
	pool := NewFakePool(3)
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	pinned := allocateFakeIP(t, pool, 1, "pinned.test", prefix)
	_, releasePinned, ok := pool.Acquire(pinned)
	if !ok {
		t.Fatal("could not lease the oldest mapping")
	}
	defer releasePinned()
	used := allocateFakeIP(t, pool, 1, "used.test", prefix)
	idle := allocateFakeIP(t, pool, 1, "idle.test", prefix)
	if hit := allocateFakeIP(t, pool, 1, "used.test", prefix); hit != used {
		t.Fatalf("allocate hit returned %s, want %s", hit, used)
	}
	added := allocateFakeIP(t, pool, 1, "added.test", prefix)
	if added != idle.Next() {
		t.Fatalf("allocation gave %s after evicting %s, want %s", added, idle, idle.Next())
	}
	checkFakeMapping(t, pool, idle, "")
	for ip, want := range map[netip.Addr]string{used: "used.test", added: "added.test"} {
		domain, release, ok := pool.Acquire(ip)
		if !ok || domain != want {
			t.Fatalf("acquire %s = %q, %t", ip, domain, ok)
		}
		defer release()
	}
	if _, err := pool.Allocate(1, "full.test", prefix); err == nil || err.Error() != "fake IP pool full or invalid" {
		t.Fatalf("all mappings leased: %v", err)
	}
	releasePinned()
	if got := allocateFakeIP(t, pool, 1, "new.test", prefix); got != added.Next() {
		t.Fatalf("allocation after releasing a lease = %s, want %s", got, added.Next())
	}
	checkFakeMapping(t, pool, pinned, "")
	if got := pool.Size(); got != 3 {
		t.Fatalf("pool size = %d, want 3", got)
	}
}

func TestFakePoolPeekLeavesLeasesAndRecencyAlone(t *testing.T) {
	pool := NewFakePool(2)
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	peeked := allocateFakeIP(t, pool, 1, "peeked.test", prefix)
	recent := allocateFakeIP(t, pool, 1, "recent.test", prefix)
	if domain, ok := pool.Peek(peeked); !ok || domain != "peeked.test" {
		t.Fatalf("peek %s = %q, %t", peeked, domain, ok)
	}
	if domain, ok := pool.Peek(peeked.Next().Next()); ok || domain != "" {
		t.Fatalf("peek unmapped address = %q, %t", domain, ok)
	}
	// Peeking took no lease and kept the peeked mapping least recent, so it
	// is the one a new allocation evicts.
	allocateFakeIP(t, pool, 1, "new.test", prefix)
	if _, ok := pool.Peek(peeked); ok {
		t.Fatal("peeked mapping survived eviction")
	}
	checkFakeMapping(t, pool, recent, "recent.test")
	pool.Close()
	if _, ok := pool.Peek(recent); ok {
		t.Fatal("peek succeeded on a closed pool")
	}
}

func TestFakePoolAcquireUpdatesRecency(t *testing.T) {
	pool := NewFakePool(2)
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	used := allocateFakeIP(t, pool, 1, "used.test", prefix)
	idle := allocateFakeIP(t, pool, 1, "idle.test", prefix)
	checkFakeMapping(t, pool, used, "used.test")
	allocateFakeIP(t, pool, 1, "new.test", prefix)
	checkFakeMapping(t, pool, idle, "")
	checkFakeMapping(t, pool, used, "used.test")
}

func TestFakePoolCanEvictWithinASaturatedRange(t *testing.T) {
	pool := NewFakePool(8)
	other := allocateFakeIP(t, pool, 1, "other.test", netip.MustParsePrefix("198.19.0.0/29"))
	prefix := netip.MustParsePrefix("198.18.0.0/30")
	oldest := allocateFakeIP(t, pool, 1, "oldest.test", prefix)
	allocateFakeIP(t, pool, 1, "middle.test", prefix)
	allocateFakeIP(t, pool, 1, "newest.test", prefix)
	if got := allocateFakeIP(t, pool, 1, "replacement.test", prefix); got != oldest {
		t.Fatalf("saturated range reused %s, want %s", got, oldest)
	}
	checkFakeMapping(t, pool, oldest, "replacement.test")
	checkFakeMapping(t, pool, other, "other.test")
}
