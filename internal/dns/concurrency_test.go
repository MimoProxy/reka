package dns

import (
	"context"
	"errors"
	D "github.com/miekg/dns"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQueriesCoalesceWithoutSharingCancellationOrResponse(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	s := service(t, Config{Nameservers: []string{"192.0.2.1"}}, func(ctx context.Context, _ Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return answer(q, "192.0.2.1"), nil
		}
	})
	defer s.Retire()
	leader, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.Exchange(leader, query("merge.test"), "normal", false); done <- err }()
	<-entered
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := range 32 {
		wg.Go(func() {
			q := query("merge.test")
			q.Id = uint16(i + 100)
			m, err := s.Exchange(context.Background(), q, "normal", false)
			if err == nil && (m.Id != q.Id || len(m.Answer) != 1) {
				err = errors.New("response identity lost")
			}
			if m != nil {
				m.Answer[0].Header().Ttl = 0
			}
			errs <- err
		})
	}
	cancel()
	if !errors.Is(<-done, context.Canceled) {
		t.Fatal("leader was not cancelled")
	}
	<-entered
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream queries = %d", calls.Load())
	}
	m, err := s.Exchange(context.Background(), query("merge.test"), "normal", false)
	if err != nil || m.Answer[0].Header().Ttl == 0 {
		t.Fatal("response alias leaked", m, err)
	}
}

func TestUpstreamRaceBoundsAndCancelsLosers(t *testing.T) {
	var active, peak, cancelled atomic.Int32
	s := service(t, Config{Nameservers: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}, Concurrency: 2}, func(ctx context.Context, ep Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		if ep.Host == "192.0.2.1" {
			<-ctx.Done()
			cancelled.Add(1)
			return nil, ctx.Err()
		}
		return answer(q, ep.Host), nil
	})
	defer s.Retire()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := s.Exchange(ctx, query("race.test"), "normal", false); err != nil {
		t.Fatal(err)
	}
	if peak.Load() > 2 || active.Load() != 0 {
		t.Fatal("unbounded or unjoined upstreams", peak.Load(), active.Load())
	}
	// The loser may have been cancelled before it entered Exchange at all.
	_ = cancelled.Load()
}

func TestStaleRefreshFlushAndRetirement(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	s := service(t, Config{Nameservers: []string{"192.0.2.1"}, StaleTTL: 60}, func(ctx context.Context, _ Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		n := calls.Add(1)
		if n > 1 {
			entered <- struct{}{}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
			}
		}
		return answer(q, "192.0.2.1"), nil
	})
	defer s.Retire()
	q := query("stale.test")
	if _, err := s.Exchange(context.Background(), q, "normal", false); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for key, e := range s.cache {
		e.at = time.Now().Add(-3 * time.Second)
		e.until = time.Now().Add(-time.Second)
		s.cache[key] = e
	}
	s.mu.Unlock()
	for range 20 {
		m, err := s.Exchange(context.Background(), q, "normal", false)
		if err != nil || m.Answer[0].Header().Ttl != 0 {
			t.Fatal(m, err)
		}
	}
	<-entered
	if calls.Load() != 2 {
		t.Fatal("duplicate background refreshes", calls.Load())
	}
	if s.FlushCache() != 1 {
		t.Fatal("flush failed")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		flights, cache := len(s.flights), len(s.cache)
		s.mu.Unlock()
		if flights == 0 {
			if cache != 0 {
				t.Fatal("flushed cache repopulated by old refresh")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh stuck")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := s.Exchange(context.Background(), q, "normal", false); err != nil {
		t.Fatal(err)
	}
	s.Retire()
	if calls.Load() != 3 {
		t.Fatal(calls.Load())
	}
}
