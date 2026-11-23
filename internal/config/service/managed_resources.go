package service

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/rulesdata"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/internal/subscription"
)

type managedKey struct{ kind, id string }

func (k managedKey) collection() string {
	switch k.kind {
	case "rule-set":
		return "/rule-sets"
	case "geodata":
		return "/geodata"
	default:
		return ""
	}
}

type managedDefinition struct {
	key              managedKey
	format, behavior string
	code, hash       string
	download         model.ResourceDownload
	revision         uint64
}

func (d managedDefinition) status() api.ManagedResourceStatus {
	return api.ManagedResourceStatus{Kind: d.key.kind, ID: d.key.id, Format: d.format, Behavior: d.behavior,
		Automatic: d.download.Automatic, Hash: d.hash, Revision: d.revision, State: "pending"}
}

// The request identity excludes the active hash and the current revision.
// Validators are additionally checked against the active hash.
func (d managedDefinition) specHash() string {
	raw, _ := json.Marshal([]any{d.format, d.behavior, d.code, d.download})
	return resource.Hash(raw)
}

type managedRecord struct {
	SpecHash string                    `json:"spec_hash"`
	Entry    subscription.Entry        `json:"entry"`
	Status   api.ManagedResourceStatus `json:"status"`
}

type managedJob struct {
	done   chan struct{}
	status api.ManagedResourceStatus
}

type managedRefresh struct {
	slot        chan struct{}
	revision    uint64
	definitions []managedDefinition
	loaded      bool
	jobs        map[managedKey]*managedJob
	records     map[managedKey]managedRecord
}

func newManagedRefresh() managedRefresh {
	return managedRefresh{slot: make(chan struct{}, 1), jobs: make(map[managedKey]*managedJob), records: make(map[managedKey]managedRecord)}
}

func (m *RefreshManager) managedDefinitions() []managedDefinition {
	rev, data, _ := m.svc.Documents()
	m.mu.Lock()
	if m.managed.loaded && rev <= m.managed.revision {
		defer m.mu.Unlock()
		return m.managed.definitions
	}
	m.mu.Unlock()

	p, _, ds := model.ParseProfile(data)
	var defs []managedDefinition
	if !ds.HasErrors() {
		for _, r := range p.RuleSets {
			if r.Download != nil && r.Hash != "" {
				defs = append(defs, managedDefinition{managedKey{"rule-set", r.ID}, r.Format, r.Behavior, r.Code, r.Hash, *r.Download, rev})
			}
		}
		for _, db := range p.Geodata {
			if db.Download != nil && db.Hash != "" {
				defs = append(defs, managedDefinition{managedKey{"geodata", db.ID}, db.Format, "", "", db.Hash, *db.Download, rev})
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.managed.loaded || rev > m.managed.revision {
		m.managed.revision, m.managed.definitions, m.managed.loaded = rev, defs, true
	}
	return m.managed.definitions
}

func (m *RefreshManager) managedDefinition(key managedKey) (managedDefinition, bool) {
	for _, def := range m.managedDefinitions() {
		if def.key == key {
			return def, true
		}
	}
	return managedDefinition{}, false
}

func (m *RefreshManager) managedRecordPath(key managedKey) string {
	id := resource.Hash([]byte(key.kind + "/" + key.id))
	return filepath.Join(m.dir, "managed-resources", id+".json")
}

// readManagedRecord is called with m.mu held.
func (m *RefreshManager) readManagedRecord(def managedDefinition) managedRecord {
	r, ok := m.managed.records[def.key]
	if !ok {
		path := m.managedRecordPath(def.key)
		if info, err := os.Stat(path); err == nil && info.Size() <= 64<<10 {
			if raw, err := os.ReadFile(path); err == nil {
				_ = json.Unmarshal(raw, &r)
			}
		}
		m.managed.records[def.key] = r
	}
	if r.SpecHash != def.specHash() || r.Status.Hash != def.hash {
		return managedRecord{Status: def.status()}
	}
	r.Status.Revision = def.revision
	return r
}

func (m *RefreshManager) runManagedDue() {
	now := time.Now()
	for _, def := range m.managedDefinitions() {
		if !def.download.Automatic {
			continue
		}
		m.mu.Lock()
		r := m.readManagedRecord(def)
		m.mu.Unlock()
		if !now.Before(r.Status.NextAttempt) {
			_, _ = m.queueManaged(def)
			return
		}
	}
}

func (s *Service) ListManagedResources() ([]api.ManagedResourceStatus, error) {
	m, err := s.manager(RefreshOptions{})
	if err != nil {
		return nil, err
	}
	defs := m.managedDefinitions()
	statuses := make([]api.ManagedResourceStatus, 0, len(defs))
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, def := range defs {
		status := m.readManagedRecord(def).Status
		if m.managed.jobs[def.key] != nil {
			status.State = "refreshing"
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func (s *Service) RefreshManagedResource(ctx context.Context, req api.RefreshManagedResourceRequest) (api.ManagedResourceStatus, error) {
	m, err := s.manager(RefreshOptions{})
	if err != nil {
		return api.ManagedResourceStatus{}, err
	}
	def, ok := m.managedDefinition(managedKey{req.Kind, req.ID})
	if !ok {
		return api.ManagedResourceStatus{}, errf(CodeNotFound, "managed resource not found")
	}
	job, err := m.queueManaged(def)
	if err != nil {
		return api.ManagedResourceStatus{}, err
	}
	if !req.Wait {
		status := def.status()
		status.State = "refreshing"
		return status, nil
	}
	select {
	case <-ctx.Done():
		return api.ManagedResourceStatus{}, ctx.Err()
	case <-job.done:
		return job.status, nil
	}
}

// reserveManaged is called with m.mu held and shares a single download slot
// between first installs and scheduled checks (a database can be 128 MiB).
func (m *RefreshManager) reserveManaged() error {
	if m.closing {
		return errf(CodeBlocked, "kernel is stopping")
	}
	select {
	case m.managed.slot <- struct{}{}:
		m.wg.Add(1)
		return nil
	default:
		return errf(CodeBlocked, "a managed resource update is already running")
	}
}

func (m *RefreshManager) queueManaged(def managedDefinition) (*managedJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if job := m.managed.jobs[def.key]; job != nil {
		return job, nil
	}
	if err := m.reserveManaged(); err != nil {
		return nil, err
	}
	job := &managedJob{done: make(chan struct{})}
	m.managed.jobs[def.key] = job
	previous := m.readManagedRecord(def)
	go m.updateManaged(def, previous, job)
	return job, nil
}

func (m *RefreshManager) doneManaged() {
	<-m.managed.slot
	m.wg.Done()
}

func (m *RefreshManager) updateManaged(def managedDefinition, record managedRecord, job *managedJob) {
	defer m.wg.Done()
	ctx, cancel := context.WithTimeout(m.ctx, m.options.JobTimeout)
	defer cancel()
	record.SpecHash = def.specHash()
	record.Status.LastAttempt = time.Now().UTC()
	entry, err := m.fetchManaged(ctx, def, record.Entry)
	if err == nil {
		record.Status.Revision, err = m.applyManaged(ctx, def, entry.Hash)
	}
	if err != nil {
		record.Status.State = "stale"
		record.Status.ErrorCode = subscription.Code(err)
		record.Status.NextAttempt = time.Now().UTC().Add(time.Minute)
	} else {
		record.Entry = entry
		record.Status.Hash = entry.Hash
		record.Status.State = "ready"
		record.Status.ErrorCode = ""
		record.Status.LastSuccess = time.Now().UTC()
		record.Status.NextAttempt = entry.Next
	}
	m.mu.Lock()
	m.saveManaged(def.key, &record)
	job.status = record.Status
	delete(m.managed.jobs, def.key)
	<-m.managed.slot
	close(job.done)
	m.mu.Unlock()
	m.svc.Events().Publish("resource.updated", record.Status)
}

// saveManaged is called with m.mu held.
func (m *RefreshManager) saveManaged(key managedKey, record *managedRecord) {
	raw, err := json.Marshal(record)
	if err == nil {
		path := m.managedRecordPath(key)
		if err = os.MkdirAll(filepath.Dir(path), 0700); err == nil {
			err = secret.WriteFileAtomic(path, raw, 0600)
		}
	}
	if err != nil && record.Status.ErrorCode == "" {
		record.Status.ErrorCode = "state_store_failed"
	}
	m.managed.records[key] = *record
}

func (m *RefreshManager) fetchManaged(ctx context.Context, def managedDefinition, old subscription.Entry) (subscription.Entry, error) {
	raw, err := m.resolve(def.download.URL)
	if err != nil {
		return subscription.Entry{}, err
	}
	u, parseErr := url.Parse(raw)
	if parseErr != nil || u.User != nil {
		return subscription.Entry{}, &subscription.Error{Code: "invalid_url"}
	}
	f := &subscription.Fetcher{Client: m.client, Blobs: m.blobs, ValidateBody: func(data []byte) error {
		var err error
		if def.key.kind == "geodata" {
			err = rulesdata.ValidateDatabase(def.key.id, def.format, data)
		} else {
			_, err = rulesdata.Decode(def.behavior, def.format, def.code, data)
		}
		if err != nil {
			if code := rulesdata.SRSCompatibilityCode(err); code != "" {
				return &subscription.Error{Code: code}
			}
			return &subscription.Error{Code: "resource_invalid"}
		}
		return nil
	}}
	// The previous body is usable only if its hash is pinned in this profile.
	if old.Hash != def.hash {
		old = subscription.Entry{}
	}
	batch := f.Batch(map[string]subscription.Entry{"body": old}, true)
	_, err = batch.Fetch(ctx, "body", "rule", "", raw, nil, def.download.Interval)
	return batch.Entries["body"], err
}

func (m *RefreshManager) applyManaged(ctx context.Context, def managedDefinition, hash string) (uint64, error) {
	for range 3 {
		if err := ctx.Err(); err != nil {
			return def.revision, err
		}
		current, exists := m.managedDefinition(def.key)
		if !exists || current.hash != def.hash || current.specHash() != def.specHash() {
			break
		}
		if current.hash == hash {
			return current.revision, nil
		}
		value, _ := json.Marshal(hash)
		res, err := m.svc.Commit(ctx, CommitRequest{
			ChangeRequest: ChangeRequest{BaseRevision: current.revision, Patch: []model.Op{{
				Op: "set", Path: model.JoinPath(def.key.collection(), def.key.id, "hash"), Value: value,
			}}},
			Source: "resource", Message: "refresh " + def.key.kind + " " + def.key.id,
		})
		switch {
		case err != nil:
			return current.revision, &subscription.Error{Code: "commit_failed"}
		case res.State == store.OpCommitted:
			return res.Revision, nil
		case res.Error == nil || res.Error.Code != CodeConflict:
			return current.revision, &subscription.Error{Code: "commit_rejected"}
		}
	}
	return def.revision, &subscription.Error{Code: "refresh_conflict"}
}

// InstallManagedResource fetches the first immutable version before adding a
// definition. A failed fetch or concurrent edit cannot create an empty set.
func (s *Service) InstallManagedResource(ctx context.Context, req api.InstallManagedResourceRequest) (Result, error) {
	key := managedKey{req.Kind, req.ID}
	if key.collection() == "" || req.ID == "" || len(req.ID) > 128 || req.Format == "" ||
		(req.Kind == "rule-set") != (req.Behavior != "") {
		return Result{}, errf(CodeBadRequest, "need kind, resource ID, format, and behavior for rule sets")
	}
	switch req.Kind {
	case "geodata":
		if req.Format == "srs" {
			if !model.IsSRSGeodataID(req.ID) {
				return Result{}, errf(CodeBadRequest, "SRS database ID must be a lowercase geoip:code or geosite:code")
			}
		} else if req.ID != "geoip" && req.ID != "geosite" && req.ID != "asn" {
			return Result{}, errf(CodeBadRequest, "geodata ID must be geoip, geosite or asn")
		}
	case "rule-set":
		if req.Behavior != "domain" && req.Behavior != "ipcidr" && req.Behavior != "classical" {
			return Result{}, errf(CodeBadRequest, "rule set behavior must be domain, ipcidr or classical")
		}
	}
	if req.Interval == 0 {
		req.Interval = model.DefaultResourceInterval
	}
	d := model.ResourceDownload{URL: req.URL, Interval: req.Interval, Automatic: req.Automatic}
	if err := model.ValidResourceDownload(d); err != nil {
		return Result{}, errf(CodeBadRequest, "%v", err)
	}
	rev, profile, _ := s.Documents()
	if req.BaseRevision != rev {
		return Result{}, errf(CodeConflict, "the active revision changed")
	}
	doc, _ := model.LoadDoc(model.DocProfile, profile)
	if doc.Get(model.JoinPath(key.collection(), key.id)) != nil {
		return Result{}, errf(CodeConflict, "resource already exists")
	}
	m, err := s.manager(RefreshOptions{})
	if err != nil {
		return Result{}, err
	}
	m.mu.Lock()
	err = m.reserveManaged()
	m.mu.Unlock()
	if err != nil {
		return Result{}, err
	}
	defer m.doneManaged()
	ctx, cancel := context.WithTimeout(ctx, m.options.JobTimeout)
	stop := context.AfterFunc(m.ctx, cancel)
	defer cancel()
	defer stop()
	def := managedDefinition{key: key, format: req.Format, behavior: req.Behavior, download: d, revision: rev}
	attempt := time.Now().UTC()
	entry, err := m.fetchManaged(ctx, def, subscription.Entry{})
	if err != nil {
		return Result{}, errf(CodeInvalid, "resource download failed (%s)", subscription.Code(err))
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	value := map[string]any{"id": key.id, "format": def.format, "hash": entry.Hash,
		"download": map[string]any{"url": d.URL, "interval": d.Interval, "automatic": d.Automatic}}
	if def.behavior != "" {
		value["behavior"] = def.behavior
	}
	raw, _ := json.Marshal(value)
	res, err := s.Commit(ctx, CommitRequest{
		ChangeRequest: ChangeRequest{BaseRevision: rev, Patch: []model.Op{{Op: "insert", Path: key.collection(), Value: raw}}},
		Source:        "resource", Message: "install " + key.kind + " " + key.id,
	})
	if err == nil && res.State == store.OpCommitted {
		def.hash, def.revision = entry.Hash, res.Revision
		status := def.status()
		status.State, status.LastAttempt, status.LastSuccess, status.NextAttempt = "ready", attempt, time.Now().UTC(), entry.Next
		record := managedRecord{SpecHash: def.specHash(), Entry: entry, Status: status}
		m.mu.Lock()
		m.saveManaged(key, &record)
		m.mu.Unlock()
		s.Events().Publish("resource.updated", record.Status)
	}
	return res, err
}
