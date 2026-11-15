package service

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/config/importer"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/internal/subscription"
)

type RefreshOptions struct {
	Client       *http.Client
	Protect      func(int) error
	PollInterval time.Duration
	JobTimeout   time.Duration
	Concurrency  int
}
type refreshRecord struct {
	Status   SubscriptionStatus            `json:"status"`
	SpecHash string                        `json:"spec_hash"`
	Failures int                           `json:"failures"`
	Entries  map[string]subscription.Entry `json:"entries"`
}
type refreshJob struct {
	done   chan struct{}
	result SubscriptionStatus
}
type RefreshManager struct {
	svc              *Service
	options          RefreshOptions
	client           *http.Client
	blobs            *resource.Store
	dir              string
	ctx              context.Context
	cancel           context.CancelFunc
	mu               sync.Mutex
	jobs             map[string]*refreshJob
	records          map[string]refreshRecord
	slots            chan struct{}
	started, closing bool
	wg               sync.WaitGroup
	once             sync.Once
}

func (s *Service) manager(opts RefreshOptions) (*RefreshManager, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if s.closed {
		return nil, errf(CodeBlocked, "kernel is stopping")
	}
	if s.refresh != nil {
		m := s.refresh
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.started && len(m.jobs) == 0 {
			if opts.Client != nil || opts.Protect != nil {
				m.client.CloseIdleConnections()
				m.client = opts.Client
				if m.client == nil {
					m.client = subscription.HTTPClient(opts.Protect)
				}
				m.options.Protect = opts.Protect
			}
			if opts.PollInterval > 0 {
				m.options.PollInterval = opts.PollInterval
			}
			if opts.JobTimeout > 0 {
				m.options.JobTimeout = opts.JobTimeout
			}
			if opts.Concurrency > 0 && opts.Concurrency != cap(m.slots) {
				return nil, errf(CodeBlocked, "subscription concurrency must be configured at initialization")
			}
		} else if opts.Protect != nil && m.options.Protect == nil {
			return nil, errf(CodeBlocked, "subscription transport must be configured before workers start")
		}
		return m, nil
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.Concurrency > 4 {
		opts.Concurrency = 4
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = time.Second
	}
	if opts.JobTimeout <= 0 {
		opts.JobTimeout = time.Minute
	}
	client := opts.Client
	if client == nil {
		client = subscription.HTTPClient(opts.Protect)
	}
	blobs, err := resource.Open(s.store.Root())
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(s.store.Root(), "subscriptions")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.refresh = &RefreshManager{
		svc:     s,
		options: opts,
		client:  client,
		blobs:   blobs,
		dir:     dir,
		ctx:     ctx,
		cancel:  cancel,
		jobs:    map[string]*refreshJob{},
		records: map[string]refreshRecord{},
		slots:   make(chan struct{}, opts.Concurrency),
	}
	return s.refresh, nil
}
func (s *Service) StartSubscriptions(opts RefreshOptions) error {
	m, err := s.manager(opts)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started || m.closing {
		return nil
	}
	m.started = true
	m.wg.Add(1)
	go m.loop()
	return nil
}
func (m *RefreshManager) Close() {
	m.once.Do(func() {
		m.mu.Lock()
		m.closing = true
		m.cancel()
		m.mu.Unlock()
		m.wg.Wait()
		m.client.CloseIdleConnections()
	})
}
func (m *RefreshManager) loop() {
	defer m.wg.Done()
	events := m.svc.Events().Subscribe([]string{EventCommitted}, "", 0, nil)
	defer events.Close()
	ticker := time.NewTicker(m.options.PollInterval)
	defer ticker.Stop()
	for {
		m.runDue()
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
		case <-events.C:
		}
	}
}
func (m *RefreshManager) runDue() {
	_, _, _, sources, _ := m.svc.LayerDocuments()
	config, _, ds := model.ParseSources(sources)
	if ds.HasErrors() {
		return
	}
	for _, src := range config.Sources {
		if src.Subscription == nil || src.Subscription.Paused {
			continue
		}
		m.mu.Lock()
		r := m.record(src.ID)
		due := r.SpecHash != specHash(src.Subscription) || !time.Now().Before(r.Status.NextAttempt)
		m.mu.Unlock()
		if due {
			_, _ = m.trigger(m.ctx, src.ID, false, true)
		}
	}
}
func specHash(spec *model.Subscription) string {
	b, _ := json.Marshal(spec)
	return resource.Hash(b)
}
func (m *RefreshManager) record(id string) refreshRecord {
	if r, ok := m.records[id]; ok {
		return r
	}
	r := refreshRecord{Status: SubscriptionStatus{SourceID: id, State: "pending"}, Entries: map[string]subscription.Entry{}}
	path := filepath.Join(m.dir, id+".json")
	if info, err := os.Stat(path); err == nil && info.Size() < 2<<20 {
		if data, e := os.ReadFile(path); e == nil {
			_ = json.Unmarshal(data, &r)
		}
	}
	if r.Entries == nil {
		r.Entries = map[string]subscription.Entry{}
	}
	m.records[id] = r
	return r
}
func (m *RefreshManager) save(id string, r refreshRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return secret.WriteFileAtomic(filepath.Join(m.dir, id+".json"), data, 0600)
}
func sourceFrom(data []byte, id string) (*model.Source, *model.Doc, error) {
	config, _, ds := model.ParseSources(data)
	if ds.HasErrors() {
		return nil, nil, errf(CodeInvalid, "sources are invalid")
	}
	doc, _ := model.LoadDoc(model.DocSources, data)
	for _, src := range config.Sources {
		if src.ID == id {
			copy := src
			return &copy, doc, nil
		}
	}
	return nil, nil, errf(CodeNotFound, "subscription source not found")
}
func (s *Service) ListSubscriptions() ([]SubscriptionStatus, error) {
	m, err := s.manager(RefreshOptions{})
	if err != nil {
		return nil, err
	}
	revision, _, _, data, _ := s.LayerDocuments()
	config, _, ds := model.ParseSources(data)
	if ds.HasErrors() {
		return nil, errf(CodeInvalid, "sources are invalid")
	}
	statuses := []SubscriptionStatus{}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, src := range config.Sources {
		if src.Subscription == nil {
			continue
		}
		r := m.record(src.ID)
		status := r.Status
		status.SourceID = src.ID
		if r.SpecHash != specHash(src.Subscription) {
			status.State, status.Stale = "pending", true
		}
		if src.Lock != nil {
			aligned := src.Lock.Root == status.RootHash
			for _, lock := range src.Lock.Resources {
				entry := r.Entries[lock.ID]
				aligned = aligned && entry.Hash == lock.Hash && entry.Request == lock.Request
			}
			if !aligned {
				status.State, status.Stale = "pending", true
				status.Revision = revision
				status.RootHash = src.Lock.Root
			}
		}
		if src.Subscription.Paused {
			status.State = "paused"
		}
		if m.jobs[src.ID] != nil {
			status.State = "refreshing"
		}
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].SourceID < statuses[j].SourceID })
	return statuses, nil
}
func (s *Service) RefreshSubscription(ctx context.Context, id string) (SubscriptionStatus, error) {
	m, err := s.manager(RefreshOptions{})
	if err != nil {
		return SubscriptionStatus{}, err
	}
	job, err := m.trigger(ctx, id, true, false)
	if err != nil {
		return SubscriptionStatus{}, err
	}
	select {
	case <-ctx.Done():
		return SubscriptionStatus{}, ctx.Err()
	case <-job.done:
		return job.result, nil
	}
}
func (m *RefreshManager) trigger(ctx context.Context, id string, force, try bool) (*refreshJob, error) {
	_, _, _, data, _ := m.svc.LayerDocuments()
	src, _, err := sourceFrom(data, id)
	if err != nil {
		return nil, err
	}
	if src.Subscription == nil {
		return nil, errf(CodeNotFound, "source has no subscription")
	}
	m.mu.Lock()
	if j := m.jobs[id]; j != nil {
		m.mu.Unlock()
		return j, nil
	}
	m.mu.Unlock()
	if try {
		select {
		case m.slots <- struct{}{}:
		default:
			return nil, errf(CodeBlocked, "refresh workers are busy")
		}
	} else {
		select {
		case m.slots <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-m.ctx.Done():
			return nil, errf(CodeBlocked, "kernel is stopping")
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		<-m.slots
		return nil, errf(CodeBlocked, "kernel is stopping")
	}
	if j := m.jobs[id]; j != nil {
		<-m.slots
		return j, nil
	}
	job := &refreshJob{done: make(chan struct{})}
	m.jobs[id] = job
	m.wg.Add(1)
	go m.work(id, force, job)
	return job, nil
}
func (m *RefreshManager) work(id string, force bool, job *refreshJob) {
	defer m.wg.Done()
	defer func() { <-m.slots }()
	m.mu.Lock()
	previous := m.record(id)
	m.mu.Unlock()
	status := previous.Status
	status.SourceID = id
	status.LastAttempt = time.Now().UTC()
	status.State = "refreshing"
	ctx, cancel := context.WithTimeout(m.ctx, m.options.JobTimeout)
	defer cancel()
	next, entries, hash, revision, err := m.refreshSource(ctx, id, force, previous)
	record := previous
	record.Status = status
	if err == nil {
		record.SpecHash = hash
		record.Entries = entries
		record.Failures = 0
		record.Status.State = "current"
		record.Status.Stale = false
		record.Status.ErrorCode = ""
		record.Status.Revision = revision
		record.Status.RootHash = entries["root"].Hash
		record.Status.LastSuccess = time.Now().UTC()
		record.Status.NextAttempt = next
	} else {
		record.Failures++
		record.Status.Stale = true
		record.Status.State = "stale"
		if record.Status.LastSuccess.IsZero() {
			record.Status.State = "failed"
		}
		record.Status.ErrorCode = subscription.Code(err)
		delay := 30 * time.Second
		for i := 1; i < record.Failures && delay < 30*time.Minute; i++ {
			delay *= 2
		}
		if delay > 30*time.Minute {
			delay = 30 * time.Minute
		}
		record.Status.NextAttempt = time.Now().UTC().Add(delay)
		// A failed new specification must back off too, rather than retrying
		// every scheduler tick. Do not alter the old good body/validators.
		if hash != "" {
			record.SpecHash = hash
		}
	}
	m.mu.Lock()
	m.records[id] = record
	if err := m.save(id, record); err != nil {
		record.Status.ErrorCode = "state_store_failed"
		m.records[id] = record
	}
	job.result = record.Status
	delete(m.jobs, id)
	close(job.done)
	m.mu.Unlock()
	m.svc.Events().Publish("subscription.updated", record.Status)
}
func (m *RefreshManager) resolve(value string) (string, error) {
	if name, ok := secret.ParseRef(value); ok {
		if m.svc.Secrets() == nil {
			return "", &subscription.Error{Code: "credentials_unavailable"}
		}
		v, err := m.svc.Secrets().Get(name)
		if err != nil {
			return "", &subscription.Error{Code: "credentials_unavailable"}
		}
		return v, nil
	}
	return value, nil
}
func (m *RefreshManager) refreshSource(ctx context.Context, id string, force bool, previous refreshRecord) (time.Time, map[string]subscription.Entry, string, uint64, error) {
	_, _, _, sourceData, _ := m.svc.LayerDocuments()
	src, doc, err := sourceFrom(sourceData, id)
	if err != nil {
		return time.Time{}, nil, "", 0, err
	}
	if src.Subscription == nil {
		return time.Time{}, nil, "", 0, &subscription.Error{Code: "subscription_removed"}
	}
	spec := src.Subscription
	fingerprint := specHash(spec)
	fail := func(code string) (time.Time, map[string]subscription.Entry, string, uint64, error) {
		return time.Time{}, nil, fingerprint, 0, &subscription.Error{Code: code}
	}
	original := resource.Hash(model.Format(doc.Get(model.JoinPath("/sources", id))))
	if err := model.ValidSubscription(spec); err != nil {
		return fail("subscription_invalid")
	}
	rawURL, err := m.resolve(spec.URL)
	if err != nil {
		return fail("credentials_unavailable")
	}
	headers := http.Header{}
	for _, header := range spec.Headers {
		v, e := m.resolve(header.Value)
		if e != nil {
			return fail("credentials_unavailable")
		}
		headers.Add(header.Name, v)
	}
	// A validator is usable only for a body locked in the active revision.
	validPrevious := map[string]subscription.Entry{}
	if src.Lock != nil {
		for _, lock := range src.Lock.Resources {
			entry := previous.Entries[lock.ID]
			if entry.Hash == lock.Hash && entry.Request == lock.Request {
				validPrevious[lock.ID] = entry
			}
		}
	}
	interval := spec.Interval
	if interval == 0 {
		interval = 3600
	}
	fetcher := &subscription.Fetcher{Client: m.client, Blobs: m.blobs}
	batch := fetcher.Batch(validPrevious, force)
	root, err := batch.Fetch(ctx, "root", "subscription", "", rawURL, headers, interval)
	if err != nil {
		return fail(subscription.Code(err))
	}
	request := importer.Request{SourceID: id, Format: spec.Format, Data: string(root), NodesOnly: spec.NodesOnly, AllowPartial: spec.AllowPartial}
	providers, err := importer.Providers(request)
	if err != nil {
		return fail(err.Error())
	}
	payloads := map[string][]byte{}
	for _, p := range providers {
		var data []byte
		if p.Type == "inline" {
			data, err = batch.Inline(p.ID, p.Kind, p.Name, p.Inline)
		} else {
			data, err = batch.Fetch(ctx, p.ID, p.Kind, p.Name, p.URL, http.Header(p.Headers), p.Interval)
		}
		if err != nil {
			return fail(subscription.Code(err))
		}
		if err := importer.ValidateProvider(p, data); err != nil {
			if p.Kind == "rule" {
				return fail("rule_resource_invalid")
			}
			return fail(err.Error())
		}
		payloads[p.ID] = data
		for i := range batch.Locks {
			if batch.Locks[i].ID == p.ID {
				batch.Locks[i].Format = p.Format
				batch.Locks[i].Behavior = p.Behavior
			}
		}
	}
	geo := map[string][]byte{}
	if !spec.NodesOnly {
		for _, a := range spec.Geodata {
			url, e := m.resolve(a.URL)
			if e != nil {
				return fail("credentials_unavailable")
			}
			data, e := batch.Fetch(ctx, a.ID, "geodata", a.ID, url, nil, interval)
			if e != nil {
				return fail(subscription.Code(e))
			}
			geo[a.ID] = data
		}
	}
	imported := importer.ImportBundle(request, payloads, geo)
	if !imported.Report.CanApply {
		return fail("conversion_rejected")
	}
	var source map[string]json.RawMessage
	if err := json.Unmarshal(imported.Source, &source); err != nil {
		return fail("conversion_rejected")
	}
	var definition any
	if err := doc.Get(model.JoinPath("/sources", id, "subscription")).Decode(&definition); err != nil {
		return fail("subscription_invalid")
	}
	source["subscription"], _ = json.Marshal(definition)
	source["lock"], _ = json.Marshal(model.SourceLock{Root: batch.Entries["root"].Hash, Resources: batch.Locks})
	encoded, _ := json.Marshal(source)
	var committed Result
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return fail("cancelled")
		}
		base, _, _, current, _ := m.svc.LayerDocuments()
		_, currentDoc, e := sourceFrom(current, id)
		if e != nil {
			return fail("refresh_conflict")
		}
		if resource.Hash(model.Format(currentDoc.Get(model.JoinPath("/sources", id)))) != original {
			return fail("refresh_conflict")
		}
		committed, e = m.svc.Commit(ctx, CommitRequest{
			ChangeRequest: ChangeRequest{BaseRevision: base, SourcesPatch: []model.Op{{Op: "set", Path: model.JoinPath("/sources", id), Value: encoded}}},
			Source:        "subscription",
			Message:       "refresh source " + id,
		})
		if e != nil {
			return fail("commit_failed")
		}
		if committed.State == store.OpCommitted {
			break
		}
		if committed.Error == nil || committed.Error.Code != CodeConflict {
			return fail("commit_rejected")
		}
	}
	if committed.State != store.OpCommitted {
		return fail("refresh_conflict")
	}
	next := time.Now().UTC().Add(time.Duration(interval) * time.Second)
	for _, entry := range batch.Entries {
		if !entry.Next.IsZero() && entry.Next.Before(next) {
			next = entry.Next
		}
	}
	return next, batch.Entries, fingerprint, committed.Revision, nil
}

// ConfigureSubscription versions the definition without fetching or discarding
// an existing materialized snapshot. Nil removes only the refresh definition.
func (s *Service) ConfigureSubscription(ctx context.Context, base uint64, id string, spec *model.Subscription) (Result, error) {
	// Restore only masked fields whose stored identity is unchanged.
	if spec != nil {
		copy := *spec
		copy.Geodata = append([]model.GeoAsset{}, spec.Geodata...)
		copy.Headers = append([]model.SubscriptionHeader{}, spec.Headers...)
		spec = &copy
		_, _, _, current, _ := s.LayerDocuments()
		existing, _, _ := sourceFrom(current, id)
		if spec.URL == model.Mask {
			if existing == nil || existing.Subscription == nil {
				return Result{}, errf(CodeBadRequest, "masked URL has no stored value")
			}
			spec.URL = existing.Subscription.URL
		}
		for i, a := range spec.Geodata {
			if a.URL == model.Mask {
				found := false
				if existing != nil && existing.Subscription != nil {
					for _, old := range existing.Subscription.Geodata {
						if old.ID == a.ID {
							spec.Geodata[i].URL = old.URL
							found = true
							break
						}
					}
				}
				if !found {
					return Result{}, errf(CodeBadRequest, "masked geodata URL has no stored value")
				}
			}
		}
		for i, h := range spec.Headers {
			if h.Value == model.Mask {
				found := false
				if existing != nil && existing.Subscription != nil {
					for _, old := range existing.Subscription.Headers {
						if strings.EqualFold(old.Name, h.Name) {
							spec.Headers[i].Value = old.Value
							found = true
							break
						}
					}
				}
				if !found {
					return Result{}, errf(CodeBadRequest, "masked header has no stored value")
				}
			}
		}
	}
	// Reuse native ID validation without making any network request.
	if spec != nil {
		if err := model.ValidSubscription(spec); err != nil {
			return Result{}, errf(CodeInvalid, "%s", err)
		}
	}
	_, _, _, data, _ := s.LayerDocuments()
	doc, ds := model.LoadDoc(model.DocSources, data)
	if ds.HasErrors() {
		return Result{}, errf(CodeInvalid, "sources are invalid")
	}
	path := model.JoinPath("/sources", id)
	ops := []model.Op{}
	if spec == nil {
		ops = append(ops, model.Op{Op: "remove", Path: path + "/subscription"})
	} else {
		headers := []map[string]string{}
		for _, h := range spec.Headers {
			headers = append(headers, map[string]string{"name": h.Name, "value": h.Value})
		}
		value := map[string]any{
			"url":           spec.URL,
			"format":        spec.Format,
			"interval":      spec.Interval,
			"nodes-only":    spec.NodesOnly,
			"allow-partial": spec.AllowPartial,
			"paused":        spec.Paused,
			"headers":       headers,
			"geodata":       spec.Geodata,
		}
		if doc.Get(path) == nil {
			encoded, _ := json.Marshal(map[string]any{"id": id, "subscription": value})
			ops = append(ops, model.Op{Op: "insert", Path: "/sources", Value: encoded})
		} else {
			encoded, _ := json.Marshal(value)
			ops = append(ops, model.Op{Op: "set", Path: path + "/subscription", Value: encoded})
		}
	}
	return s.Commit(ctx, CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: base, SourcesPatch: ops}, Source: "subscription-config"})
}

func (s *Service) QueueSubscription(ctx context.Context, id string) (SubscriptionStatus, error) {
	m, err := s.manager(RefreshOptions{})
	if err != nil {
		return SubscriptionStatus{}, err
	}
	if _, err := m.trigger(ctx, id, true, false); err != nil {
		return SubscriptionStatus{}, err
	}
	return SubscriptionStatus{SourceID: id, State: "refreshing"}, nil
}
