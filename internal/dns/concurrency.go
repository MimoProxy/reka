package dns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/history"
	D "github.com/miekg/dns"
)

type queryFlight struct {
	outcome resolutionHistory
	done    chan struct{}
	msg     *D.Msg
	err     error
}

func agedReply(entry cached, q *D.Msg, now time.Time, stale bool) *D.Msg {
	m := entry.msg.Copy()
	m.Id = q.Id
	m.Question = append([]D.Question(nil), q.Question...)
	age := uint32(max(0, now.Sub(entry.at)/time.Second))
	for _, section := range [][]D.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != D.TypeOPT {
				if stale || rr.Header().Ttl <= age {
					rr.Header().Ttl = 0
				} else {
					rr.Header().Ttl -= age
				}
			}
		}
	}
	return m
}

func (s *Service) cachedExchange(ctx context.Context, q *D.Msg, scope, key string, id uint64, outcome *resolutionHistory) (*D.Msg, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		now := time.Now()
		s.mu.Lock()
		entry, exists := s.cache[key]
		fresh := exists && now.Before(entry.until)
		stale := exists && !fresh && !entry.noStale && s.cfg.StaleTTL > 0 && now.Before(entry.until.Add(time.Duration(s.cfg.StaleTTL)*time.Second))
		if fresh || stale {
			s.hits.Add(1)
			outcome.ResultSource = "cache"
			if stale {
				outcome.ResultSource = "stale"
			}
			_, refreshing := s.flights[key]
			if stale && !refreshing && !s.retired {
				s.refreshLocked(ctx, q.Copy(), scope, key, id)
			}
			s.mu.Unlock()
			return agedReply(entry, q, now, stale), nil
		}
		if exists {
			delete(s.cache, key)
		}
		if flight := s.flights[key]; flight != nil {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-flight.done:
			}
			// A cancelled leader cannot cancel other callers. A surviving waiter
			// retries with its own context and retained transport dependencies.
			if errors.Is(flight.err, context.Canceled) || errors.Is(flight.err, context.DeadlineExceeded) {
				continue
			}
			*outcome = flight.outcome
			outcome.Coalesced = true
			if flight.msg != nil {
				m := flight.msg.Copy()
				m.Id = q.Id
				m.Question = append([]D.Question(nil), q.Question...)
				return m, flight.err
			}
			return nil, flight.err
		}
		if len(s.flights) >= 128 {
			s.mu.Unlock()
			return nil, errors.New("too many distinct DNS queries")
		}
		flight := &queryFlight{done: make(chan struct{})}
		s.flights[key] = flight
		epoch := s.cacheEpoch
		s.mu.Unlock()
		s.misses.Add(1)
		m, err := s.resolve(ctx, q, scope, outcome)
		outcome.UpstreamQueryID = id
		s.finishFlight(key, flight, epoch, m, err, *outcome)
		return m, err
	}
}

// Called with mu held. The background job owns its own resource pins and a
// bounded slot; it never borrows pins after the requesting flow has closed.
func (s *Service) refreshLocked(caller context.Context, q *D.Msg, scope, key string, parent uint64) {
	if len(s.flights) >= 128 {
		return
	}
	select {
	case s.refreshSlots <- struct{}{}:
	default:
		return
	}
	ctx := context.WithoutCancel(caller)
	release := func() {}
	if s.opts.Background != nil {
		var err error
		ctx, release, err = s.opts.Background(ctx)
		if err != nil {
			<-s.refreshSlots
			return
		}
	}
	ctx = history.WithDNSOrigin(history.WithFlow(ctx, 0), history.DNSOrigin{Kind: "refresh"})
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	stop := context.AfterFunc(s.background, cancel)
	flight := &queryFlight{done: make(chan struct{})}
	s.flights[key] = flight
	epoch := s.cacheEpoch
	id, start := queryID.Add(1), time.Now()
	go func() {
		defer func() { stop(); cancel(); release(); <-s.refreshSlots }()
		var outcome resolutionHistory
		m, err := s.resolve(ctx, q, scope, &outcome)
		outcome.UpstreamQueryID = id
		s.finishFlight(key, flight, epoch, m, err, outcome)
		s.record(ctx, id, parent, start, scope, q, m, outcome, err)
	}()
}

func (s *Service) finishFlight(key string, flight *queryFlight, epoch uint64, m *D.Msg, err error, outcome resolutionHistory) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m != nil {
		flight.msg = m.Copy()
	}
	flight.err = err
	flight.outcome = outcome
	if err == nil && m != nil && epoch == s.cacheEpoch {
		ttl := uint32(3600)
		hasTTL := false
		for _, section := range [][]D.RR{m.Answer, m.Ns} {
			for _, rr := range section {
				v := rr.Header().Ttl
				if soa, ok := rr.(*D.SOA); ok {
					v = min(v, soa.Minttl)
				}
				ttl = min(ttl, v)
				hasTTL = true
			}
		}
		if hasTTL && ttl > 0 && (m.Rcode == D.RcodeSuccess || m.Rcode == D.RcodeNameError) && !m.Truncated {
			if len(s.cache) >= s.cfg.CacheSize {
				for k := range s.cache {
					delete(s.cache, k)
					break
				}
			}
			now := time.Now()
			dhcp := outcome.Upstream != nil && outcome.Upstream.Transport == "dhcp"
			s.cache[key] = cached{msg: m.Copy(), at: now, until: now.Add(time.Duration(ttl) * time.Second), noStale: dhcp}
		}
	}
	if s.flights[key] == flight {
		delete(s.flights, key)
	}
	close(flight.done)
}

// Retire stops refreshes and releases idle upstream connections, while old
// pinned flows may still make bounded foreground queries through this policy.
func (s *Service) Retire() {
	s.mu.Lock()
	already := s.retired
	s.retired = true
	s.mu.Unlock()
	if already {
		return
	}
	s.stopBackground()
	if s.opts.Retire != nil {
		s.opts.Retire()
	}
}

func (s *Service) query(ctx context.Context, servers []string, q *D.Msg, scope string, outcome *resolutionHistory) (*D.Msg, error) {
	if len(servers) == 0 {
		return nil, errors.New("no DNS upstream")
	}
	limit := s.cfg.Concurrency
	if limit == 0 {
		limit = 4
	}
	limit = min(limit, len(servers))
	if limit == 1 {
		return s.queryOne(ctx, servers, q, scope, outcome)
	}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	type result struct {
		outcome resolutionHistory
		m       *D.Msg
		err     error
	}
	results := make(chan result, len(servers))
	jobs := make(chan string, len(servers))
	for _, server := range servers {
		jobs <- server
	}
	close(jobs)
	for range limit {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for raw := range jobs {
				if ctx.Err() != nil {
					return
				}
				var selected resolutionHistory
				m, err := s.queryOne(ctx, []string{raw}, q.Copy(), scope, &selected)
				if err == nil && m != nil && m.Rcode != D.RcodeSuccess && m.Rcode != D.RcodeNameError {
					err = fmt.Errorf("DNS upstream rcode %s", D.RcodeToString[m.Rcode])
				}
				results <- result{selected, m, err}
			}
		}()
	}
	var last error
	for range servers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-results:
			*outcome = r.outcome
			if r.err == nil && r.m != nil {
				return r.m, nil
			}
			last = r.err
		}
	}
	if last == nil {
		last = errors.New("empty DNS response")
	}
	return nil, last
}
