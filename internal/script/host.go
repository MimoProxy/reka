package script

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
	"unicode/utf8"
)

// Host applies execution limits and interprets script results. A host can run
// multiple sessions concurrently.
type Host struct {
	engine Engine
	limits Limits
	env    Environment
	slots  chan struct{}
	now    func() time.Time

	breakerMu sync.Mutex
	breakers  map[string]*breakerState
}

type breakerState struct {
	failures  int
	running   int
	openUntil time.Time
	probing   bool
}

var liveHosts = struct {
	sync.Mutex
	hosts map[*Host]struct{}
}{hosts: make(map[*Host]struct{})}

// NewHost returns a host registered for PurgeAll. Call Close when the host is
// no longer in use.
func NewHost(engine Engine, limits Limits, env Environment) *Host {
	limits = limits.WithDefaults()
	h := &Host{
		engine:   engine,
		limits:   limits,
		env:      env.withDefaults(),
		slots:    make(chan struct{}, limits.Concurrency),
		now:      time.Now,
		breakers: make(map[string]*breakerState),
	}
	liveHosts.Lock()
	liveHosts.hosts[h] = struct{}{}
	liveHosts.Unlock()
	return h
}

// Close unregisters the host from memory pressure handling.
func (h *Host) Close() {
	liveHosts.Lock()
	delete(liveHosts.hosts, h)
	liveHosts.Unlock()
}

// PurgeAll discards rebuildable engine state for all registered hosts.
func PurgeAll() {
	liveHosts.Lock()
	hosts := make([]*Host, 0, len(liveHosts.hosts))
	for h := range liveHosts.hosts {
		hosts = append(hosts, h)
	}
	liveHosts.Unlock()
	for _, h := range hosts {
		h.Purge()
	}
}

// Purge discards the engine's rebuildable state.
func (h *Host) Purge() {
	if h.engine != nil {
		h.engine.Purge()
	}
}

// Run executes a script within its session deadline, including time queued for
// a concurrency slot. Callers must keep s and in unchanged until Run returns.
// An error leaves the HTTP exchange unchanged.
func (h *Host) Run(ctx context.Context, s *Script, in *Input, svc Services) (Result, error) {
	return h.run(ctx, s, in, svc, nil)
}

// RunWithSource is like Run but loads the source after acquiring an execution
// slot. The script must have a locked Key understood by readSource.
func (h *Host) RunWithSource(ctx context.Context, s *Script, in *Input, svc Services, readSource func(string) ([]byte, error)) (Result, error) {
	if s == nil || s.Key == "" || readSource == nil {
		return Result{}, errors.New("lazy script run requires a locked key and source reader")
	}
	return h.run(ctx, s, in, svc, readSource)
}

func (h *Host) run(ctx context.Context, s *Script, in *Input, svc Services, readSource func(string) ([]byte, error)) (Result, error) {
	if err := h.validate(ctx, s, in); err != nil {
		return Result{}, err
	}
	if s.Kind.IsHTTP() {
		maxSize := h.limits.HardMaxSize
		if s.MaxSize > 0 {
			maxSize = min(maxSize, s.MaxSize)
		}
		if int64(len(in.Request.Body)) > maxSize || in.Response != nil && int64(len(in.Response.Body)) > maxSize {
			return Result{}, ErrBodyTooLarge
		}
	}
	key := s.CacheKey()
	if h.circuitOpen(key) {
		return Result{}, ErrCircuitOpen
	}
	budget := s.Timeout
	if budget <= 0 {
		budget = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	case <-ctx.Done():
		return Result{}, ErrBusy
	}
	if ctx.Err() != nil {
		return Result{}, ErrBusy
	}
	if readSource != nil {
		source, err := readSource(key)
		if err != nil {
			return Result{}, err
		}
		if err := ctx.Err(); err != nil {
			if err == context.DeadlineExceeded {
				err = ErrTimeout
			}
			return Result{}, err
		}
		spec := *s
		spec.Source = string(source)
		s = &spec
	}
	// Another execution may have opened the circuit while this run waited.
	// Only an execution can change breaker state.
	state := h.beginRun(key)
	if state == nil {
		return Result{}, ErrCircuitOpen
	}
	start := time.Now()
	done, err := h.engine.Run(ctx, &Job{Script: s, Input: in, Env: h.env, Services: svc, Limits: h.limits})
	duration := time.Since(start)
	if err == nil && !done.Called {
		err = ErrNoDone
	}
	h.finishRun(key, state, err)
	if err != nil {
		return Result{Duration: duration}, err
	}
	result := interpret(s, done)
	result.Duration = duration
	return result, nil
}

func (h *Host) validate(ctx context.Context, s *Script, in *Input) error {
	if ctx == nil || h.engine == nil || s == nil || in == nil {
		return errors.New("script run requires a context, engine, script and input")
	}
	switch s.Kind {
	case KindHTTPRequest, KindCron, KindGeneric, KindEvent:
	case KindHTTPResponse:
		if in.Response == nil {
			return errors.New("http-response script requires a response")
		}
	default:
		return fmt.Errorf("unsupported script kind %q", s.Kind)
	}
	switch s.Dialect {
	case "", DialectSurge, DialectLoon, DialectStash:
		return nil
	default:
		return fmt.Errorf("unsupported script dialect %q", s.Dialect)
	}
}

func interpret(s *Script, done Done) Result {
	if !s.Kind.IsHTTP() {
		if len(done.Value) > maxDoneValue {
			return Result{Value: doneValuePreview(done.Value), ValueTruncated: true}
		}
		return Result{Value: done.Value}
	}
	request := s.Kind == KindHTTPRequest
	// Loon and Stash document no-argument aborts for request scripts. For
	// response scripts, infer pass-through since their manuals are silent.
	if done.Abort || request && !done.HasValue && (s.Dialect == DialectLoon || s.Dialect == DialectStash) {
		return Result{Action: ActionAbort}
	}
	if request && done.Response != nil {
		response := *done.Response
		if response.Status == 0 {
			response.Status = http.StatusOK
		}
		return Result{Action: ActionRespond, Response: &response}
	}
	var result Result
	if request && done.URL != nil {
		result.Action, result.URL = ActionModify, done.URL
	}
	if !request && done.Status != nil {
		result.Action, result.Status = ActionModify, *done.Status
	}
	if done.HeadersSet {
		result.Action, result.Headers, result.HeadersSet = ActionModify, done.Headers, true
	}
	if done.BodySet {
		result.Action, result.Body, result.BodySet = ActionModify, done.Body, true
	}
	return result
}

func doneValuePreview(value json.RawMessage) json.RawMessage {
	encode := func(end int) []byte {
		for end > 0 && !utf8.RuneStart(value[end]) {
			end--
		}
		encoded, _ := json.Marshal(string(value[:end]))
		return encoded
	}
	// Encode the prefix as a string so a partial JSON object or array stays valid.
	end := sort.Search(maxDoneValue-1, func(n int) bool {
		return len(encode(n)) > maxDoneValue
	}) - 1
	return encode(end)
}

func (h *Host) blocked(state *breakerState) bool {
	return state != nil && (state.probing || !state.openUntil.IsZero() && h.now().Before(state.openUntil))
}

func (h *Host) circuitOpen(key string) bool {
	h.breakerMu.Lock()
	defer h.breakerMu.Unlock()
	return h.blocked(h.breakers[key])
}

func (h *Host) beginRun(key string) *breakerState {
	h.breakerMu.Lock()
	defer h.breakerMu.Unlock()
	state := h.breakers[key]
	if h.blocked(state) {
		return nil
	}
	if state == nil {
		state = &breakerState{}
		h.breakers[key] = state
	}
	if state.openUntil.IsZero() {
		state.running++
	} else {
		state.probing = true
	}
	return state
}

func (h *Host) finishRun(key string, state *breakerState, err error) {
	h.breakerMu.Lock()
	defer h.breakerMu.Unlock()
	if h.breakers[key] != state {
		// This execution was admitted before the current cooldown or trial.
		return
	}
	failed := err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, ErrLowMemory)
	if state.probing {
		state.probing = false
		switch {
		case err == nil:
			delete(h.breakers, key)
		case failed:
			state.openUntil = h.now().Add(h.limits.BreakerCooldown)
		}
		return
	}
	state.running--
	switch {
	case err == nil:
		state.failures = 0
	case failed:
		state.failures++
	}
	if state.failures >= h.limits.BreakerFailures {
		h.breakers[key] = &breakerState{openUntil: h.now().Add(h.limits.BreakerCooldown)}
	} else if state.failures == 0 && state.running == 0 {
		delete(h.breakers, key)
	}
}
