// Package service is the ConfigService: the only writer of configuration.
// Files, the CLI, the control API and the Android binding all commit
// through it, and a commit is reported successful only after the runtime
// has switched and the new revision is durable as the active one.
//
// Commit steps (each persistence and switch point can be crash-tested
// through Options.FailPoint):
//
//  1. Check the base revision and the operation ID; build the candidate.
//  2. Compile (no side effects); reject on error diagnostics.
//  3. Prepare: build new instances, bind new listeners.
//  4. Write the immutable revision           ("revision-written")
//  5. Write the operation intent             ("intent-written")
//  6. Switch the runtime                     ("activated")
//  7. Write active.json                      ("active-written")
//  8. Mark the operation committed           ("op-committed")
//
// After a crash, Open restores the revision named by active.json: an
// operation whose intent names that revision is marked committed, any
// other pending operation failed, and revisions that never became active
// are removed.
package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/store"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/secret"
)

// Options configure a Service.
type Options struct {
	StateRoot string
	Secrets   secret.Store
	Engine    *generation.Engine
	Logger    *slog.Logger
	// InitialProfile and InitialLocal become revision 1 when the state
	// root is empty. Without them revision 1 is an empty profile.
	InitialProfile []byte
	InitialLocal   []byte
	// FailPoint, for tests, is called at each persistence and switch
	// point; a non-nil error aborts the commit on the spot, as a crash
	// would, leaving disk and runtime as they are.
	FailPoint func(point string) error
}

// DefaultProfile is revision 1 of an empty state root.
const DefaultProfile = "schema-version: 1\n"

// Error codes in results.
const (
	CodeConflict    = "conflict"
	CodeInvalid     = "invalid"
	CodePrepare     = "prepare_failed"
	CodeBlocked     = "blocked"
	CodeActivate    = "activate_failed"
	CodeOpReused    = "operation_reused"
	CodePlanChanged = "plan_changed"
	CodeBadRequest  = "bad_request"
	CodeNotFound    = "not_found"
)

// Error is a request error with a stable code.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// ChangeRequest describes a candidate configuration relative to a base
// revision: whole documents, patches, or both (patches apply after the
// documents).
type ChangeRequest struct {
	// BaseRevision is the revision the client edited. It must be the
	// active revision.
	BaseRevision uint64     `json:"base_revision"`
	Profile      *string    `json:"profile,omitempty"`
	Local        *string    `json:"local,omitempty"`
	Patch        []model.Op `json:"patch,omitempty"`
	LocalPatch   []model.Op `json:"local_patch,omitempty"`
}

// CommitRequest is a ChangeRequest to activate.
type CommitRequest struct {
	ChangeRequest
	// OperationID makes the commit idempotent: retrying with the same ID
	// and content returns the first result. Generated when empty.
	OperationID string `json:"operation_id,omitempty"`
	// PlanHash, if set, must match the hash PlanConfiguration returned,
	// so the client commits exactly what it reviewed.
	PlanHash string `json:"plan_hash,omitempty"`
	Source   string `json:"source,omitempty"`
	Message  string `json:"message,omitempty"`

	restoredFrom uint64
}

// FieldChange is one differing field between two revisions.
type FieldChange struct {
	Path string `json:"path"`
	From any    `json:"from,omitempty"`
	To   any    `json:"to,omitempty"`
}

// Conflict explains a stale base revision.
type Conflict struct {
	Base    uint64        `json:"base"`
	Active  uint64        `json:"active"`
	Changes []FieldChange `json:"changes"`
}

// Result is the outcome of a commit; it is also what GetOperation
// returns.
type Result struct {
	OperationID string            `json:"operation_id"`
	State       string            `json:"state"`
	Revision    uint64            `json:"revision,omitempty"`
	Generation  uint64            `json:"generation,omitempty"`
	NoChange    bool              `json:"no_change,omitempty"`
	Plan        *generation.Plan  `json:"plan,omitempty"`
	Diagnostics model.Diagnostics `json:"diagnostics,omitempty"`
	Conflict    *Conflict         `json:"conflict,omitempty"`
	Error       *Error            `json:"error,omitempty"`
	Degraded    bool              `json:"degraded,omitempty"`
}

// Service is the ConfigService.
type Service struct {
	opts   Options
	store  *store.Store
	engine *generation.Engine
	events *Broker
	log    *slog.Logger

	mu       sync.Mutex
	active   uint64
	profile  []byte
	local    []byte
	eff      *compile.Effective
	warnings model.Diagnostics
	// startErr is set when the active revision could not be started.
	startErr error
}

// ErrCrashed is returned by a commit aborted through FailPoint.
var ErrCrashed = errors.New("service: aborted at fail point")

// Open recovers the state root and starts the active revision.
func Open(opts Options) (*Service, error) {
	st, err := store.Open(opts.StateRoot)
	if err != nil {
		return nil, err
	}
	s := &Service{opts: opts, store: st, engine: opts.Engine, events: NewBroker(), log: opts.Logger}
	if s.log == nil {
		s.log = slog.Default()
	}
	if err := s.recover(); err != nil {
		return nil, fmt.Errorf("recover state root: %w", err)
	}
	a, err := st.ReadActive()
	if err != nil {
		return nil, err
	}
	if a == nil {
		profile, local := opts.InitialProfile, opts.InitialLocal
		if profile == nil {
			profile = []byte(DefaultProfile)
		}
		p, l := string(profile), string(local)
		res, err := s.Commit(context.Background(), CommitRequest{
			ChangeRequest: ChangeRequest{Profile: &p, Local: &l},
			OperationID:   "initial", Source: "initial",
		})
		if err != nil {
			return nil, err
		}
		if res.State != store.OpCommitted {
			return nil, fmt.Errorf("initial configuration: %s", describe(res))
		}
		return s, nil
	}
	if err := s.startActive(a); err != nil {
		s.startErr = err
		s.log.Error("active configuration did not start; fix it with a new commit", "revision", a.Revision, "err", err)
	}
	return s, nil
}

func describe(r Result) string {
	if r.Error != nil {
		msg := r.Error.Message
		if len(r.Diagnostics) > 0 {
			msg += "\n" + r.Diagnostics.Errors().Error()
		}
		return msg
	}
	return r.State
}

// recover settles operations left pending by a crash.
func (s *Service) recover() error {
	a, err := s.store.ReadActive()
	if err != nil {
		return err
	}
	var active uint64
	if a != nil {
		active = a.Revision
	}
	ops, err := s.store.ListOperations()
	if err != nil {
		return err
	}
	for _, op := range ops {
		if op.State != store.OpPending {
			continue
		}
		var res Result
		_ = json.Unmarshal(op.Result, &res)
		if op.Revision != 0 && op.Revision == active {
			op.State = store.OpCommitted
			res.State = store.OpCommitted
			res.Revision = active
		} else {
			op.State = store.OpFailed
			res.State = store.OpFailed
			res.Error = errf(CodeActivate, "the process stopped before the commit completed; revision %d stays active", active)
			res.Revision = 0
		}
		res.OperationID = op.ID
		op.Result, _ = json.Marshal(res)
		op.Updated = time.Now().UTC()
		if err := s.store.WriteOperation(op); err != nil {
			return err
		}
	}
	revs, err := s.store.RevisionNumbers()
	if err != nil {
		return err
	}
	for _, n := range revs {
		if n > active {
			if err := s.store.DeleteRevision(n); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) compileOpts() compile.Options {
	return compile.Options{Secrets: s.opts.Secrets, ProcessLookup: s.engine.ProcessLookup()}
}

func (s *Service) startActive(a *store.Active) error {
	_, profile, local, err := s.store.ReadRevision(a.Revision)
	if err != nil {
		return err
	}
	s.active, s.profile, s.local = a.Revision, profile, local
	eff, diags := compile.Compile(profile, local, s.compileOpts())
	s.warnings = diags
	if eff == nil {
		return diags.Errors()
	}
	p, err := s.engine.Prepare(eff)
	if err != nil {
		return err
	}
	if _, err := s.engine.Activate(p, a.Revision); err != nil {
		return err
	}
	s.eff = eff
	return nil
}

// Events is the service's event broker.
func (s *Service) Events() *Broker { return s.events }

// Engine is the runtime the service drives.
func (s *Service) Engine() *generation.Engine { return s.engine }

// ActiveRevision is the confirmed active revision.
func (s *Service) ActiveRevision() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

func requestHash(req CommitRequest) string {
	b, _ := json.Marshal(struct {
		ChangeRequest
		Restored uint64
		Plan     string
	}{req.ChangeRequest, req.restoredFrom, req.PlanHash})
	return store.Hash(b)
}

func newOperationID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "op-" + hex.EncodeToString(b)
}

// candidate builds the documents a change request describes, against the
// active documents. Called with s.mu held.
func (s *Service) candidate(req ChangeRequest) (profile, local []byte, err error) {
	build := func(name string, active []byte, whole *string, patch []model.Op) ([]byte, error) {
		base := active
		if whole != nil {
			base = []byte(*whole)
		}
		masked := name == model.DocProfile && containsMask(base)
		if len(patch) == 0 && !masked {
			return base, nil
		}
		doc, diags := model.LoadDoc(name, base)
		if diags.HasErrors() {
			// Let compilation report the syntax error with positions.
			if len(patch) == 0 {
				return base, nil
			}
			return nil, errf(CodeInvalid, "%s: %v", name, diags.Error())
		}
		if err := doc.Apply(patch...); err != nil {
			return nil, errf(CodeBadRequest, "%s patch: %v", name, err)
		}
		if name == model.DocProfile {
			activeDoc, _ := model.LoadDoc(name, active)
			if err := doc.UnmaskSecrets(activeDoc); err != nil {
				return nil, errf(CodeBadRequest, "%v", err)
			}
		}
		return doc.Bytes(), nil
	}
	if profile, err = build(model.DocProfile, s.profile, req.Profile, req.Patch); err != nil {
		return nil, nil, err
	}
	if local, err = build(model.DocLocal, s.local, req.Local, req.LocalPatch); err != nil {
		return nil, nil, err
	}
	return profile, local, nil
}

func containsMask(b []byte) bool { return bytes.Contains(b, []byte(model.Mask)) }

// conflict computes the field differences between the client's base and
// the active revision. Called with s.mu held.
func (s *Service) conflict(base uint64) *Conflict {
	c := &Conflict{Base: base, Active: s.active}
	_, bp, bl, err := s.store.ReadRevision(base)
	if err != nil {
		return c
	}
	c.Changes = append(diffDocs(model.DocProfile, "", bp, s.profile), diffDocs(model.DocLocal, "/local", bl, s.local)...)
	return c
}

func diffDocs(name, prefix string, a, b []byte) []FieldChange {
	flat := func(data []byte) map[string]any {
		doc, diags := model.LoadDoc(name, data)
		if diags.HasErrors() {
			return map[string]any{}
		}
		if name == model.DocProfile {
			doc.MaskSecrets()
		}
		return model.Flatten(doc.Mapping())
	}
	fa, fb := flat(a), flat(b)
	var out []FieldChange
	for p, va := range fa {
		vb, ok := fb[p]
		if !ok {
			out = append(out, FieldChange{Path: prefix + p, From: va})
		} else if !reflect.DeepEqual(va, vb) {
			out = append(out, FieldChange{Path: prefix + p, From: va, To: vb})
		}
	}
	for p, vb := range fb {
		if _, ok := fa[p]; !ok {
			out = append(out, FieldChange{Path: prefix + p, To: vb})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// PlanHash binds a plan to its base revision and candidate content.
func PlanHash(base uint64, profile, local []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s", base, store.Hash(profile), store.Hash(local))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// ValidateResult is the answer to Validate.
type ValidateResult struct {
	Valid       bool              `json:"valid"`
	Diagnostics model.Diagnostics `json:"diagnostics,omitempty"`
}

// Validate compiles a candidate without any side effect.
func (s *Service) Validate(req ChangeRequest) (ValidateResult, error) {
	s.mu.Lock()
	profile, local, err := s.candidate(req)
	s.mu.Unlock()
	if err != nil {
		return ValidateResult{}, err
	}
	eff, diags := compile.Compile(profile, local, s.compileOpts())
	return ValidateResult{Valid: eff != nil, Diagnostics: diags}, nil
}

// PlanResult is the answer to Plan.
type PlanResult struct {
	Base        uint64            `json:"base_revision"`
	Valid       bool              `json:"valid"`
	Plan        *generation.Plan  `json:"plan,omitempty"`
	PlanHash    string            `json:"plan_hash,omitempty"`
	Diagnostics model.Diagnostics `json:"diagnostics,omitempty"`
	Conflict    *Conflict         `json:"conflict,omitempty"`
}

// Plan compiles a candidate and reports what committing it would change.
func (s *Service) Plan(req ChangeRequest) (PlanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.BaseRevision != s.active {
		return PlanResult{Base: req.BaseRevision, Conflict: s.conflict(req.BaseRevision)}, nil
	}
	profile, local, err := s.candidate(req)
	if err != nil {
		return PlanResult{}, err
	}
	eff, diags := compile.Compile(profile, local, s.compileOpts())
	res := PlanResult{Base: s.active, Diagnostics: diags, Valid: eff != nil}
	if eff == nil {
		return res, nil
	}
	plan := s.engine.Plan(eff)
	res.Plan = &plan
	res.PlanHash = PlanHash(s.active, profile, local)
	return res, nil
}

func (s *Service) fail(point string) error {
	if s.opts.FailPoint == nil {
		return nil
	}
	if err := s.opts.FailPoint(point); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrCrashed, point, err)
	}
	return nil
}

// Commit validates, prepares and activates a change. The returned error is
// for failures of the service itself (disk errors, an aborted fail point);
// a rejected change is a Result with State "rejected".
func (s *Service) Commit(ctx context.Context, req CommitRequest) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.OperationID == "" {
		req.OperationID = newOperationID()
	}
	if err := store.ValidOperationID(req.OperationID); err != nil {
		return Result{}, errf(CodeBadRequest, "%v", err)
	}
	if req.Source == "" {
		req.Source = "api"
	}
	hash := requestHash(req)
	if op, ok, err := s.store.ReadOperation(req.OperationID); err != nil {
		return Result{}, err
	} else if ok {
		if op.RequestHash != hash {
			return Result{}, errf(CodeOpReused, "operation %s was already used for a different change", req.OperationID)
		}
		var res Result
		if err := json.Unmarshal(op.Result, &res); err != nil {
			return Result{}, err
		}
		return res, nil
	}
	now := time.Now().UTC()
	op := store.Operation{ID: req.OperationID, RequestHash: hash, Base: req.BaseRevision, Created: now, Updated: now}
	res := Result{OperationID: req.OperationID}
	reject := func(e *Error) (Result, error) {
		res.State, res.Error = store.OpRejected, e
		op.State = store.OpRejected
		op.Result, _ = json.Marshal(res)
		if err := s.store.WriteOperation(op); err != nil {
			return Result{}, err
		}
		s.events.Publish(EventRejected, res)
		return res, nil
	}

	initial := s.active == 0 && req.OperationID == "initial"
	if !initial && req.BaseRevision != s.active {
		res.Conflict = s.conflict(req.BaseRevision)
		return reject(errf(CodeConflict, "revision %d is active, not %d", s.active, req.BaseRevision))
	}
	profile, local, err := s.candidate(req.ChangeRequest)
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return reject(e)
		}
		return Result{}, err
	}
	if req.PlanHash != "" && req.PlanHash != PlanHash(s.active, profile, local) {
		return reject(errf(CodePlanChanged, "the candidate differs from the one that was planned"))
	}
	eff, diags := compile.Compile(profile, local, s.compileOpts())
	res.Diagnostics = diags
	if eff == nil {
		return reject(errf(CodeInvalid, "the configuration has %d errors", len(diags.Errors())))
	}
	if !initial && s.startErr == nil && string(profile) == string(s.profile) && string(local) == string(s.local) && sameInstances(s.eff, eff) {
		res.State, res.Revision, res.NoChange = store.OpCommitted, s.active, true
		op.State, op.Revision = store.OpCommitted, s.active
		op.Result, _ = json.Marshal(res)
		return res, s.store.WriteOperation(op)
	}
	prepared, err := s.engine.Prepare(eff)
	if err != nil {
		code := CodePrepare
		if errors.Is(err, generation.ErrBlocked) {
			code = CodeBlocked
		}
		var pe *generation.PrepareError
		if errors.As(err, &pe) {
			res.Diagnostics = append(res.Diagnostics, model.Diagnostic{Severity: model.SeverityError, Code: code, Path: pe.Path, Message: pe.Err.Error()})
		}
		return reject(errf(code, "%v", err))
	}
	plan := prepared.Plan()
	res.Plan = &plan

	number, err := s.nextRevision()
	if err != nil {
		s.engine.Abort(prepared)
		return Result{}, err
	}
	rev := store.Revision{Number: number, Base: s.active, Operation: req.OperationID, Source: req.Source,
		Message: req.Message, Created: now, RestoredFrom: req.restoredFrom}
	if _, err := s.store.WriteRevision(rev, profile, local); err != nil {
		s.engine.Abort(prepared)
		return Result{}, err
	}
	if err := s.fail("revision-written"); err != nil {
		s.engine.Abort(prepared)
		return Result{}, err
	}
	op.State, op.Revision = store.OpPending, number
	res.State, res.Revision = store.OpPending, number
	op.Result, _ = json.Marshal(res)
	if err := s.store.WriteOperation(op); err != nil {
		s.engine.Abort(prepared)
		s.store.DeleteRevision(number)
		return Result{}, err
	}
	if err := s.fail("intent-written"); err != nil {
		s.engine.Abort(prepared)
		return Result{}, err
	}

	gen, actErr := s.engine.Activate(prepared, number)
	if actErr != nil {
		return s.rollback(op, res, number, actErr)
	}
	if err := s.fail("activated"); err != nil {
		return Result{}, err
	}
	if err := s.store.WriteActive(store.Active{Revision: number, Profile: store.Hash(profile), Local: store.Hash(local),
		Operation: req.OperationID, Updated: time.Now().UTC()}); err != nil {
		// The runtime runs the new revision but it is not durable: go back
		// to the old one so what runs matches what is recorded.
		return s.rollback(op, res, number, err)
	}
	if err := s.fail("active-written"); err != nil {
		return Result{}, err
	}
	s.active, s.profile, s.local, s.eff, s.warnings, s.startErr = number, profile, local, eff, diags, nil
	res.State, res.Generation = store.OpCommitted, gen
	op.State = store.OpCommitted
	op.Updated = time.Now().UTC()
	op.Result, _ = json.Marshal(res)
	if err := s.store.WriteOperation(op); err != nil {
		// active.json is written, so recovery will mark it committed.
		s.log.Error("record committed operation", "operation", op.ID, "err", err)
	}
	if err := s.fail("op-committed"); err != nil {
		return Result{}, err
	}
	s.events.Publish(EventCommitted, map[string]any{"revision": number, "operation": op.ID, "source": req.Source, "generation": gen, "plan": plan})
	s.events.Publish(EventRuntime, map[string]any{"generation": gen, "revision": number})
	return res, nil
}

// rollback returns to the previous revision after the switch or its
// recording failed. Called with s.mu held.
func (s *Service) rollback(op store.Operation, res Result, number uint64, cause error) (Result, error) {
	res.State, res.Revision = store.OpFailed, 0
	res.Error = errf(CodeActivate, "%v", cause)
	var ae *generation.ActivateError
	if errors.As(cause, &ae) && ae.Degraded {
		res.Degraded = true
	}
	if s.eff != nil {
		if p, err := s.engine.Prepare(s.eff); err != nil {
			res.Degraded = true
			s.log.Error("roll back to the previous revision", "revision", s.active, "err", err)
		} else if _, err := s.engine.Activate(p, s.active); err != nil {
			res.Degraded = true
			s.log.Error("roll back to the previous revision", "revision", s.active, "err", err)
		}
	}
	op.State = store.OpFailed
	op.Updated = time.Now().UTC()
	op.Result, _ = json.Marshal(res)
	if err := s.store.WriteOperation(op); err != nil {
		return Result{}, err
	}
	if err := s.store.DeleteRevision(number); err != nil {
		s.log.Error("remove failed revision", "revision", number, "err", err)
	}
	s.events.Publish(EventRejected, res)
	return res, nil
}

func (s *Service) nextRevision() (uint64, error) {
	max := s.active
	revs, err := s.store.RevisionNumbers()
	if err != nil {
		return 0, err
	}
	for _, n := range revs {
		if n > max {
			max = n
		}
	}
	ops, err := s.store.ListOperations()
	if err != nil {
		return 0, err
	}
	for _, op := range ops {
		if op.Revision > max {
			max = op.Revision
		}
	}
	return max + 1, nil
}

// GetOperation returns the recorded result of an operation.
func (s *Service) GetOperation(id string) (Result, error) {
	op, ok, err := s.store.ReadOperation(id)
	if err != nil {
		return Result{}, errf(CodeBadRequest, "%v", err)
	}
	if !ok {
		return Result{}, errf(CodeNotFound, "no operation %s", id)
	}
	var res Result
	if err := json.Unmarshal(op.Result, &res); err != nil {
		return Result{}, err
	}
	return res, nil
}

// Configuration is the answer to GetConfiguration.
type Configuration struct {
	Revision    uint64             `json:"revision"`
	Profile     string             `json:"profile"`
	Local       string             `json:"local"`
	Masked      int                `json:"masked,omitempty"`
	Effective   *compile.Effective `json:"effective,omitempty"`
	Diagnostics model.Diagnostics  `json:"diagnostics,omitempty"`
	StartError  string             `json:"start_error,omitempty"`
}

// GetConfiguration returns the active documents (inline credentials
// masked unless reveal), the effective configuration with field origins,
// and its warnings.
func (s *Service) GetConfiguration(reveal bool) Configuration {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := Configuration{Revision: s.active, Profile: string(s.profile), Local: string(s.local), Effective: s.eff, Diagnostics: s.warnings}
	if s.startErr != nil {
		c.StartError = s.startErr.Error()
	}
	if !reveal {
		if doc, diags := model.LoadDoc(model.DocProfile, s.profile); !diags.HasErrors() {
			if n := doc.MaskSecrets(); n > 0 {
				c.Profile, c.Masked = string(doc.Bytes()), n
			}
		}
	}
	return c
}

// Documents returns the active documents unmasked, for the candidate
// files.
func (s *Service) Documents() (revision uint64, profile, local []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active, s.profile, s.local
}

// ListRevisions lists stored revisions, newest first.
func (s *Service) ListRevisions() ([]store.Revision, error) { return s.store.ListRevisions() }

// RestoreRequest restores an old revision as a new one.
type RestoreRequest struct {
	Revision     uint64 `json:"revision"`
	BaseRevision uint64 `json:"base_revision"`
	OperationID  string `json:"operation_id,omitempty"`
}

// RestoreRevision commits the content of an older revision as a new
// revision.
func (s *Service) RestoreRevision(ctx context.Context, req RestoreRequest) (Result, error) {
	_, profile, local, err := s.store.ReadRevision(req.Revision)
	if err != nil {
		return Result{}, errf(CodeNotFound, "revision %d: %v", req.Revision, err)
	}
	p, l := string(profile), string(local)
	return s.Commit(ctx, CommitRequest{
		ChangeRequest: ChangeRequest{BaseRevision: req.BaseRevision, Profile: &p, Local: &l},
		OperationID:   req.OperationID, Source: "restore",
		Message:      fmt.Sprintf("restore revision %d", req.Revision),
		restoredFrom: req.Revision,
	})
}

// Close stops the runtime.
func (s *Service) Close() {
	s.engine.Close()
}

// sameInstances reports whether two compilations of the same documents
// produce the same instances; they differ when a referenced secret
// changed.
func sameInstances(a, b *compile.Effective) bool {
	if a == nil || len(a.Outbounds) != len(b.Outbounds) {
		return false
	}
	for i := range a.Outbounds {
		if a.Outbounds[i].Fingerprint != b.Outbounds[i].Fingerprint {
			return false
		}
	}
	return true
}

// Secrets is the service's secret store.
func (s *Service) Secrets() secret.Store { return s.opts.Secrets }

// Reapply recompiles the active documents, for example after a secret
// they reference changed, and activates the result if any instance
// changed.
func (s *Service) Reapply(ctx context.Context, source string) (Result, error) {
	s.mu.Lock()
	base := s.active
	s.mu.Unlock()
	return s.Commit(ctx, CommitRequest{ChangeRequest: ChangeRequest{BaseRevision: base}, Source: source, Message: "re-resolve secrets"})
}

// StartError reports why the active revision is not running, if it is
// not.
func (s *Service) StartError() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.startErr == nil {
		return ""
	}
	return s.startErr.Error()
}
