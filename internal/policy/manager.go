// Package policy holds observed health and automatic selections, never config.
package policy

import (
	"context"
	"hash/fnv"
	"reflect"
	"slices"
	"sync"
	"time"
)

type Group struct {
	ID, Type, Selected, Strategy string
	URL                          string `json:"-"`
	ExpectedStatus               string `json:"expected-status,omitempty"`
	Members                      []string
	Interval, Timeout, Tolerance int
	Lazy                         bool
}
type Result struct {
	Member  string    `json:"member"`
	Alive   bool      `json:"alive"`
	Delay   int64     `json:"delay_ms"`
	Checked time.Time `json:"checked"`
}
type Status struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Selected string   `json:"selected"`
	Results  []Result `json:"results"`
}
type Probe func(context.Context, string, string) error
type state struct {
	group    Group
	results  map[string]Result
	selected string
	used     bool
	last     time.Time
	round    uint64
	running  bool
}
type Manager struct {
	mu     sync.Mutex
	states map[string]*state
	probe  Probe
	cancel context.CancelFunc
	wg     sync.WaitGroup
	sem    chan struct{}
}

func New(groups []Group, probe Probe) *Manager {
	return NewWithConcurrency(groups, probe, 4)
}

func NewWithConcurrency(groups []Group, probe Probe, concurrency int) *Manager {
	m := &Manager{states: map[string]*state{}, probe: probe, sem: make(chan struct{}, max(1, concurrency))}
	for _, g := range groups {
		if g.Type == "select" {
			continue
		}
		if g.Interval == 0 {
			g.Interval = 300
		}
		if g.Timeout == 0 {
			g.Timeout = 5000
		}
		m.states[g.ID] = &state{group: g, results: map[string]Result{}}
	}
	return m
}
func (m *Manager) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		m.schedule(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.schedule(ctx)
			}
		}
	}()
}
func (m *Manager) schedule(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.states {
		if s.running || s.group.Lazy && !s.used || time.Since(s.last) < time.Duration(s.group.Interval)*time.Second {
			continue
		}
		s.running = true
		m.wg.Add(1)
		go m.check(ctx, s)
	}
}
func (m *Manager) check(ctx context.Context, s *state) {
	defer m.wg.Done()
	results := make([]Result, len(s.group.Members))
	var wg sync.WaitGroup
	jobs := make(chan int)
	for range min(cap(m.sem), len(s.group.Members)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				member := s.group.Members[i]
				select {
				case m.sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				q, cancel := context.WithTimeout(ctx, time.Duration(s.group.Timeout)*time.Millisecond)
				start := time.Now()
				err := m.probe(context.WithValue(q, expectedStatusKey{}, s.group.ExpectedStatus), member, s.group.URL)
				cancel()
				<-m.sem
				results[i] = Result{member, err == nil, time.Since(start).Milliseconds(), time.Now().UTC()}
			}
		}()
	}
	for i := range s.group.Members {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			m.mu.Lock()
			s.running = false
			m.mu.Unlock()
			return
		}
	}
	close(jobs)
	wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() == nil {
		for _, r := range results {
			if r.Member != "" {
				s.results[r.Member] = r
			}
		}
		s.last = time.Now()
		best := ""
		var delay int64
		for _, member := range s.group.Members {
			r := s.results[member]
			if r.Alive && (best == "" || r.Delay < delay) {
				best, delay = member, r.Delay
			}
			if s.group.Type == "fallback" && r.Alive {
				break
			}
		}
		if old := s.results[s.selected]; s.group.Type == "url-test" && old.Alive && best != "" && old.Delay <= delay+int64(s.group.Tolerance) {
			best = s.selected
		}
		if best == "" && len(s.group.Members) > 0 {
			best = s.group.Members[0]
		}
		s.selected = best
	}
	s.running = false
}
func (m *Manager) Choose(id, key, fallback string) string { return m.choose(id, key, fallback, true) }
func (m *Manager) Peek(id, key, fallback string) string   { return m.choose(id, key, fallback, false) }
func (m *Manager) choose(id, key string, fallback string, touch bool) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.states[id]
	if s == nil {
		return fallback
	}
	if touch {
		s.used = true
	}
	if s.group.Selected != "" {
		return s.group.Selected
	}
	if s.last.IsZero() {
		if len(s.group.Members) > 0 {
			return s.group.Members[0]
		}
		return ""
	}
	if s.group.Type != "load-balance" {
		return s.selected
	}
	var alive []string
	for _, member := range s.group.Members {
		if s.results[member].Alive {
			alive = append(alive, member)
		}
	}
	if len(alive) == 0 {
		if len(s.group.Members) > 0 {
			return s.group.Members[0]
		}
		return ""
	}
	if s.group.Strategy == "round-robin" {
		v := alive[s.round%uint64(len(alive))]
		if touch {
			s.round++
		}
		return v
	}
	best := ""
	var score uint64
	for _, member := range alive {
		h := fnv.New64a()
		h.Write([]byte(key))
		h.Write([]byte{0})
		h.Write([]byte(member))
		v := h.Sum64()
		if best == "" || v > score {
			best, score = member, v
		}
	}
	return best
}
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Status
	for id, s := range m.states {
		status := Status{ID: id, Type: s.group.Type, Selected: s.selected}
		if s.group.Selected != "" {
			status.Selected = s.group.Selected
		}
		for _, member := range s.group.Members {
			r := s.results[member]
			r.Member = member
			status.Results = append(status.Results, r)
		}
		out = append(out, status)
	}
	slices.SortFunc(out, func(a, b Status) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return out
}

func (m *Manager) Results(id string, offset, limit int) []Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.states[id]
	if state == nil || limit <= 0 {
		return []Result{}
	}
	members := state.group.Members
	offset = min(max(0, offset), len(members))
	batch := members[offset : offset+min(limit, len(members)-offset)]
	results := make([]Result, 0, len(batch))
	for _, member := range batch {
		result := state.results[member]
		result.Member = member
		results = append(results, result)
	}
	return results
}
func (m *Manager) Close() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

func (m *Manager) MarkUsed(member string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.states {
		if slices.Contains(s.group.Members, member) {
			s.used = true
		}
	}
}

// Inherit keeps observations across revisions with unchanged health settings.
func (m *Manager) Inherit(old *Manager) {
	if old == nil {
		return
	}
	old.mu.Lock()
	defer old.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.states {
		previous := old.states[id]
		if previous == nil {
			continue
		}
		previousGroup := previous.group
		if s.group.Type == "url-test" {
			// A selection override leaves the probes and their schedule valid.
			previousGroup.Selected = s.group.Selected
		}
		if !reflect.DeepEqual(previousGroup, s.group) {
			continue
		}
		for key, result := range previous.results {
			s.results[key] = result
		}
		s.selected = previous.selected
		s.last = previous.last
		s.round = previous.round
		s.used = previous.used
	}
}
